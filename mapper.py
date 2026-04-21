"""
APT TTP Mapper
==============
Extracts and maps adversary TTPs from threat intelligence reports
to the MITRE ATT&CK Enterprise framework.

Usage:
    python mapper.py <path_to_report.pdf or .txt>

Example:
    python mapper.py sample_reports/apt33_report.pdf

Output:
    CSV and Excel files saved to the /output directory.

Author: Shankar Bettadapura
"""

# =============================================================================
# IMPORTS
# All libraries used across every phase are declared here at the top.
# Python convention is to group: standard library first, then third-party.
# =============================================================================

import os           # File path checks, directory creation
import re           # Regular expressions (used for T-ID pattern matching)
import sys          # Command-line argument parsing
import json         # Reading/writing JSON (the ATT&CK dataset)
from datetime import datetime    # Timestamping output filenames
from collections import defaultdict  # Not used directly but useful for future extensions

import requests     # HTTP calls to download the ATT&CK dataset
import pandas as pd # Structuring results into tables, exporting to CSV/Excel
import pdfplumber   # Extracting text from PDF files


# =============================================================================
# PHASE 2 — CONSTANTS + DOWNLOAD ATT&CK DATA
# =============================================================================

ATTACK_DATA_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
LOCAL_ATTACK_FILE = "enterprise-attack.json"


def download_attack_data():
    """
    Downloads the MITRE ATT&CK Enterprise dataset if it doesn't already exist locally.

    The dataset is a large JSON file (~10MB) containing every technique,
    sub-technique, tactic, and associated metadata published by MITRE.

    The os.path.exists check ensures it only downloads once — every subsequent
    run reads the local file instead of hitting the network.
    """
    if not os.path.exists(LOCAL_ATTACK_FILE):
        print("[*] Downloading ATT&CK Enterprise dataset...")
        response = requests.get(ATTACK_DATA_URL)
        with open(LOCAL_ATTACK_FILE, "w") as f:
            json.dump(response.json(), f)
        print("[+] Download complete.")
    else:
        print("[*] ATT&CK dataset already exists locally. Skipping download.")


# =============================================================================
# PHASE 3 — BUILD TECHNIQUE LOOKUP DICTIONARY
# =============================================================================

def build_technique_lookup():
    """
    Parses the ATT&CK dataset and builds a lookup dictionary.

    Each entry maps a searchable keyword (technique name or alias) to:
      - Technique ID    e.g. T1566
      - Full name       e.g. Phishing
      - Tactic(s)       e.g. Initial Access
      - Description     First 200 characters
      - URL             Link to the ATT&CK technique page

    This dictionary is what the mapper queries against your report text.
    """
    download_attack_data()

    with open(LOCAL_ATTACK_FILE, "r") as f:
        raw_data = json.load(f)

    technique_lookup = {}

    for obj in raw_data["objects"]:

        # The ATT&CK JSON contains many object types: groups, malware,
        # relationships, etc. We only want attack-pattern — that is the
        # STIX type for techniques.
        if obj.get("type") != "attack-pattern":
            continue

        # Skip deprecated or revoked techniques — they are outdated entries
        # that MITRE has replaced or removed from the active framework.
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Extract the ATT&CK Technique ID (e.g. T1566 or T1566.001).
        # It lives inside external_references alongside other sources like NVD
        # and CVE, so we loop until we find the mitre-attack entry specifically.
        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break

        if not technique_id:
            continue

        # Extract tactic names from kill_chain_phases.
        # STIX stores these as hyphenated lowercase strings (e.g. "initial-access").
        # We convert to Title Case for readability.
        tactics = [
            phase["phase_name"].replace("-", " ").title()
            for phase in obj.get("kill_chain_phases", [])
        ]

        # Build the structured entry for this technique
        entry = {
            "id": technique_id,
            "name": obj["name"],
            "tactics": ", ".join(tactics),
            "description": obj.get("description", "")[:200],
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
        }

        # Index by lowercase technique name so we can match against report text
        keyword = obj["name"].lower()
        technique_lookup[keyword] = entry

        # Also index any aliases MITRE has listed for the technique
        for alias in obj.get("x_mitre_aliases", []):
            technique_lookup[alias.lower()] = entry

    print(f"[+] Loaded {len(technique_lookup)} technique keywords from ATT&CK.")
    return technique_lookup


# =============================================================================
# PHASE 4 — INGEST THE THREAT REPORT (PDF OR TXT)
# =============================================================================

def extract_text_from_file(filepath):
    """
    Accepts either a .txt or .pdf file path and returns the full text as a string.

    PDFs are the standard distribution format for threat intel reports
    (Mandiant, CrowdStrike, CISA, etc.), so pdfplumber handles those.
    Plain .txt handles cases where you paste report content directly into a file.

    The 'if page_text' guard handles scanned PDFs where pages are images
    with no text layer — those pages are skipped silently rather than crashing.
    """
    if filepath.endswith(".pdf"):
        text = ""
        with pdfplumber.open(filepath) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
        return text

    elif filepath.endswith(".txt"):
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()

    else:
        raise ValueError(f"Unsupported file type: {filepath}. Use .pdf or .txt")


# =============================================================================
# PHASE 5 — TTP MATCHING ENGINE
# =============================================================================

def extract_ttps(report_text, technique_lookup):
    """
    Scans the report text for two types of TTP indicators.

    Pass 1 — Explicit T-IDs:
        Direct mentions of ATT&CK IDs in the text (e.g. T1566, T1059.001).
        These are HIGH confidence — a report author consciously cited the ID.

    Pass 2 — Keyword Matches:
        Technique names found in the prose
        (e.g. "spearphishing", "credential dumping", "lateral movement").
        These are MEDIUM confidence — the language aligns with a technique
        but warrants analyst review to confirm intent and context.

    Using matched_ttps as a dict keyed by technique_id prevents duplicates.
    If a technique is found in both passes, the higher-confidence explicit
    match is preserved and the keyword match is discarded.

    Returns a list of matched TTP dictionaries.
    """
    report_lower = report_text.lower()
    matched_ttps = {}  # keyed by technique_id to avoid duplicates

    # -------------------------------------------------------------------------
    # Pass 1: Scan for explicit T-IDs
    # Regex breakdown:
    #   \b        — word boundary (prevents matching inside longer strings)
    #   T\d{4}    — the letter T followed by exactly 4 digits
    #   (?:\.\d{3})? — optionally a dot and 3 digits (for sub-techniques)
    #   \b        — closing word boundary
    # -------------------------------------------------------------------------
    tid_pattern = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
    explicit_ids = set(tid_pattern.findall(report_text))

    # Build a reverse lookup: technique_id → entry (for the explicit ID pass)
    id_to_entry = {v["id"]: v for v in technique_lookup.values()}

    for tid in explicit_ids:
        if tid in id_to_entry:
            entry = id_to_entry[tid].copy()
            entry["match_type"] = "Explicit T-ID"
            entry["confidence"] = "High"
            matched_ttps[tid] = entry

    # -------------------------------------------------------------------------
    # Pass 2: Keyword scan through the prose
    # The 5-character floor filters out short strings like "exec" or "cmd"
    # that would produce too many false positives in technical report text.
    # -------------------------------------------------------------------------
    for keyword, entry in technique_lookup.items():
        if len(keyword) < 5:
            continue

        if keyword in report_lower:
            tid = entry["id"]
            # Do not overwrite a High confidence explicit hit
            if tid not in matched_ttps:
                entry_copy = entry.copy()
                entry_copy["match_type"] = "Keyword Match"
                entry_copy["confidence"] = "Medium"
                matched_ttps[tid] = entry_copy

    results = list(matched_ttps.values())
    print(f"[+] Identified {len(results)} unique TTPs in the report.")
    return results


# =============================================================================
# PHASE 6 — OUTPUT GENERATION (CSV + EXCEL)
# =============================================================================

def generate_report(matched_ttps, output_dir="output", source_filename="report"):
    """
    Takes the list of matched TTP dictionaries and writes them to:
      - A CSV file  (easy to open anywhere, good for GitHub demo)
      - An Excel file (formatted for sharing with non-technical stakeholders)

    Output filenames include a timestamp so multiple runs don't overwrite
    each other (e.g. apt_report_ttp_map_20250421_1432.csv).

    Results are sorted by confidence (High first), then by Technique ID.
    """
    if not matched_ttps:
        print("[-] No TTPs found. Nothing to export.")
        return

    # Convert list of dicts to a DataFrame.
    # Each dict key becomes a column; each dict becomes a row.
    df = pd.DataFrame(matched_ttps)

    # Reorder columns for logical readability
    column_order = ["id", "name", "tactics", "confidence", "match_type", "description", "url"]
    df = df[[col for col in column_order if col in df.columns]]

    # Rename columns to human-readable Title Case
    df.columns = [col.replace("_", " ").title() for col in df.columns]

    # Sort: High confidence first, then by Technique ID alphanumerically
    confidence_order = {"High": 0, "Medium": 1, "Low": 2}
    df["_sort"] = df["Confidence"].map(confidence_order)
    df = df.sort_values(["_sort", "Id"]).drop(columns=["_sort"])

    # Generate timestamped filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    base_name = os.path.splitext(os.path.basename(source_filename))[0]

    csv_path = os.path.join(output_dir, f"{base_name}_ttp_map_{timestamp}.csv")
    xlsx_path = os.path.join(output_dir, f"{base_name}_ttp_map_{timestamp}.xlsx")

    # Create output directory if it doesn't exist (exist_ok=True prevents
    # an error if the folder is already there)
    os.makedirs(output_dir, exist_ok=True)

    df.to_csv(csv_path, index=False)
    df.to_excel(xlsx_path, index=False)

    print(f"[+] CSV saved:   {csv_path}")
    print(f"[+] Excel saved: {xlsx_path}")
    print(f"\n{'='*60}")
    print(df.to_string(index=False))

    return df


# =============================================================================
# PHASE 7 — MAIN ENTRY POINT
# =============================================================================

def main():
    """
    Entry point. Reads the report path from the command line and
    runs all phases in sequence.

    sys.argv is Python's list of command-line arguments.
    sys.argv[0] is always the script name itself.
    sys.argv[1] is the first argument you pass after it (your report path).

    The 'if __name__ == "__main__"' block at the bottom ensures main()
    only runs when you execute this script directly — not when another
    script imports it as a module.
    """
    if len(sys.argv) < 2:
        print("Usage: python mapper.py <path_to_report.pdf or .txt>")
        print("Example: python mapper.py sample_reports/apt33_report.pdf")
        sys.exit(1)

    report_path = sys.argv[1]

    if not os.path.exists(report_path):
        print(f"[-] File not found: {report_path}")
        sys.exit(1)

    print(f"\n[*] APT TTP Mapper — Starting analysis")
    print(f"[*] Input: {report_path}\n")

    # Phase 2 + 3: Load ATT&CK dataset and build lookup
    technique_lookup = build_technique_lookup()

    # Phase 4: Extract text from the report
    print(f"\n[*] Extracting text from report...")
    report_text = extract_text_from_file(report_path)
    print(f"[+] Extracted {len(report_text):,} characters of text.")

    # Phase 5: Run TTP matching
    print(f"\n[*] Running TTP extraction...")
    matched_ttps = extract_ttps(report_text, technique_lookup)

    # Phase 6: Generate output files
    print(f"\n[*] Generating report...")
    generate_report(matched_ttps, source_filename=report_path)


if __name__ == "__main__":
    main()