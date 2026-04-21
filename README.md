# APT TTP Mapper

A Python tool that extracts and maps adversary tactics, techniques, and procedures (TTPs) from threat intelligence reports to the [MITRE ATT&CK Enterprise framework](https://attack.mitre.org/).

Built as a practical complement to threat intelligence analysis — automating the TTP extraction process that analysts typically perform manually when reviewing adversary campaign reports.

---

## What It Does

- Accepts a threat report as input (PDF or plain text)
- Runs a two-pass extraction engine:
  - **Pass 1** — scans for explicit ATT&CK Technique IDs (e.g. T1566, T1059.001) → High confidence
  - **Pass 2** — scans prose for technique name keywords (e.g. "spearphishing", "credential dumping") → Medium confidence
- Maps each identified TTP to its full ATT&CK entry: Technique ID, name, tactic category, description, and ATT&CK URL
- Outputs a structured CSV and Excel report sorted by confidence level

---

## Sample Output

| Id | Name | Tactics | Confidence | Match Type |
|----|------|---------|------------|------------|
| T1078 | Valid Accounts | Defense Evasion, Initial Access | High | Explicit T-ID |
| T1059 | Command and Scripting Interpreter | Execution | High | Explicit T-ID |
| T1566 | Phishing | Initial Access | Medium | Keyword Match |
| T1190 | Exploit Public-Facing Application | Initial Access | Medium | Keyword Match |

---

## Installation

**Requirements:** Python 3.9+

```bash
# Clone the repository
git clone https://github.com/shankar-bettadapura/apt-ttp-mapper.git
cd apt-ttp-mapper

# Create and activate a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

```bash
python mapper.py <path_to_report.pdf or .txt>
```

**Examples:**

```bash
# PDF input (recommended — most threat reports are distributed as PDFs)
python mapper.py sample_reports/cisa_advisory_aa26-097a.pdf

# Plain text input
python mapper.py sample_reports/report.txt
```

On first run, the tool automatically downloads the MITRE ATT&CK Enterprise dataset (~10MB) and caches it locally. Subsequent runs use the cached file.

**Output files** are saved to the `/output` directory with timestamped filenames:
```
output/
└── cisa_advisory_aa26-097a_ttp_map_20260421_1432.csv
└── cisa_advisory_aa26-097a_ttp_map_20260421_1432.xlsx
```

---

## Project Structure

```
apt-ttp-mapper/
├── mapper.py              # Main script
├── requirements.txt       # Python dependencies
├── README.md
├── sample_reports/        # Drop input reports here
└── output/                # Extracted TTP reports land here
```

---

## Dependencies

| Library | Purpose |
|---------|---------|
| requests | Downloads the ATT&CK dataset |
| pandas | Structures results and exports to CSV/Excel |
| pdfplumber | Extracts text from PDF reports |
| openpyxl | Excel file generation backend |

---

## Tested Against

- CISA Advisory AA26-097A — Iranian-Affiliated Cyber Actors Exploit PLCs Across US Critical Infrastructure
- CISA Advisory AA23-335A — IRGC-Affiliated Cyber Actors Exploit PLCs in Multiple Sectors

---

## Limitations

This tool uses keyword and pattern matching, not semantic NLP. Known limitations:

- **False positives on keyword matches** — common words that overlap with technique names (e.g. "access", "persistence") may surface low-signal hits in technical prose. All Medium confidence results should be reviewed by an analyst before use.
- **Scanned PDFs not supported** — pages that are image-only (no text layer) are silently skipped. OCR support is a planned enhancement.
- **Keyword floor at 5 characters** — technique names shorter than 5 characters are excluded from matching to reduce noise. A small number of legitimate short technique names are therefore not matched via keyword.
- **ATT&CK version pinned to latest main branch** — the cached dataset reflects the version available at download time. Re-delete `enterprise-attack.json` to force a refresh when ATT&CK releases a new version.

---

## Planned Enhancements

- Tactic frequency bar chart output using `matplotlib`
- HTML report output via `jinja2` templates
- Batch mode for processing a folder of reports and comparing TTP overlap across campaigns
- IOC extraction (IPs, hashes, domains) with VirusTotal/OTX enrichment
- OCR support for scanned PDFs via `pytesseract`

---

## Background

This tool was built as a practical extension of threat intelligence work covering Iranian APT operations against U.S. critical infrastructure. The TTP extraction process it automates is documented in the companion Substack post: [When the Lights Go Out — Iran's PLC Campaign](https://shankarbettadapura.substack.com).

---

## Author

**Shankar Bettadapura**
Cybersecurity & GRC | Threat Intelligence | AI Risk & Governance

[LinkedIn](https://www.linkedin.com/in/shankar-bettadapura) · [Substack](https://shankarbettadapura.substack.com) · [GitHub](https://github.com/shankar-bettadapura)
