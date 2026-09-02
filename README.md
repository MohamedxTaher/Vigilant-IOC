# Vigilant IOC

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-d73a49.svg)](SECURITY.md)
[![Reports](https://img.shields.io/badge/output-JSON%20%7C%20Markdown%20%7C%20CSV-0ea5e9.svg)](#reports)

<p align="center"><img src="assets/preview.png" alt="Vigilant IOC Preview" width="100%"></p>

## Technical Overview

Vigilant IOC performs fast static document analysis and heuristic IOC extraction for PDF, Office, and RTF files, including macro-enabled Office documents. It identifies suspicious content patterns—URLs, C2 IP addresses, macro triggers, embedded files, and obfuscation—without executing document macros or embedded code. Optional VirusTotal and AbuseIPDB lookups add reputation data to local findings; the final report combines extracted indicators, parser results, reputation scores, and a bounded 0-100 risk score with transparent threat verdicts.

## Core Features

- **Static IOC Extraction**: URLs, domains, IPv4 addresses, embedded files, JavaScript object counts, and macro indicators from document content.
- **Multi-Format Parser**: PDF, Office Open XML (.docx, .xlsx), legacy OLE (.doc, .xls), and RTF documents.
- **Macro Analysis**: Detect VBA auto-execution functions (`AutoOpen`, `Document_Open`), suspicious keywords, API calls (`CreateObject`, `Shell`, `URLDownloadToFile`), and string obfuscation.
- **Reputation Enrichment**: Optional VirusTotal URL lookups and AbuseIPDB IP reputation (configurable thresholds).
- **Risk Scoring**: Heuristic-based 0–100 score with six threat verdicts: *benign*, *low*, *medium*, *suspicious*, *high*, *critical*.
- **Multi-Format Output**: Markdown, JSON, CSV, JSONL, and HTML reports.
- **Command-Line Interface**: Single file or directory scanning with optional multi-threaded processing.

## Extracted Indicators

Reports group findings into actionable categories:

| Indicator Type | Examples |
| --- | --- |
| URLs & Domains | Links in document text, embedded relationships, and macro content |
| C2 IP Addresses | IPv4 addresses from document content and reputation results |
| Macro Triggers | `AutoOpen`, `Document_Open`, suspicious keywords, dangerous API calls |
| Hash Fingerprints | SHA-256 and MD5 digests of analyzed files |
| Embedded Content | Files and JavaScript objects embedded in PDFs |

## Installation

### Prerequisites

- Python 3.10 or newer
- pip
- Optional: VirusTotal and AbuseIPDB API keys for reputation enrichment

### Quick Start

```bash
git clone https://github.com/MohamedxTaher/Vigilant-IOC.git
cd Vigilant-IOC
python -m venv .venv
.venv\Scripts\activate       # Windows PowerShell
# or: source .venv/bin/activate  (macOS/Linux)
pip install -r requirements.txt
```

### Configure Reputation Services (Optional)

Copy `.env.example` to `.env` and set your API keys only if you need reputation lookups:

```env
VT_API_KEY=YOUR_VIRUSTOTAL_API_KEY
ABUSEIPDB_API_KEY=YOUR_ABUSEIPDB_API_KEY
VT_THRESHOLD=5                    # VirusTotal consensus vendors (default: 5)
ABUSE_CONFIDENCE_CUTOFF=70        # AbuseIPDB confidence % (default: 70)
```

## Usage

### Inspect Available Options

```bash
python main.py --help
```

### Scan a Single Document

```bash
# Scan with Markdown report output
python main.py --file invoices/bad.pdf --report

# Scan with JSON output (silent mode)
python main.py --file sensitive.docm --json --quiet
```

### Scan a Directory

```bash
# Scan all documents with 4 worker threads
python main.py --dir samples/ --threads 4 --json

# Scan with verbose logging
python main.py --dir documents/ --report --debug
```

### Common Options

| Flag | Purpose |
| --- | --- |
| `--file PATH` | Scan a single file (repeatable) |
| `--dir PATH` | Scan all supported files in a directory |
| `--report` | Write Markdown report to `reports/` |
| `--json` | Output JSON to stdout and `reports/` |
| `--quiet` | Suppress progress messages |
| `--debug` | Enable debug-level logging |
| `--threads N` | Directory scan worker count (default: 2) |
| `--help` | Show full option list |

### Output Formats

Reports are written to `reports/` in the requested format(s):

- **Markdown** (`--report`): Human-readable threat summary with tables and inline details.
- **JSON** (`--json`): Structured output following `vigilant_ioc_core/report_schema.json`.
- **CSV/JSONL** (`--csv`, `--jsonl`): Bulk analysis export.
- **HTML** (`--html`): Standalone interactive report.

## Security Warning

Do **not** open or execute untrusted documents outside an isolated analysis environment. Vigilant IOC performs static analysis only and does not provide sandboxing. Malicious documents may exploit vulnerabilities in the PDF or Office parsing libraries even in read-only mode.

## Development

### Run Tests

```bash
pip install -r dev-requirements.txt
python -m pytest -q
```

### Linting & Type Checking

```bash
python -m ruff check . --select E,F,W --line-length 100
mypy vigilant_ioc_core logger.py settings.py
```

### Project Structure

```
vigilant_ioc_core/
  ├── __init__.py              # Main dispatch logic
  ├── heuristics.py            # Risk scoring engine
  ├── pdf_parser.py            # PDF extraction (PyMuPDF + pdfminer.six)
  ├── doc_parser.py            # Office/RTF extraction (oletools)
  ├── macro_analyzer.py        # VBA macro detection
  ├── url_reputation.py        # VirusTotal integration
  ├── abuseipdb_check.py       # AbuseIPDB integration
  ├── report_generator.py      # Multi-format report output
  ├── report_schema.json       # JSON output validation schema
  └── exceptions.py            # Custom exception types
tests/
  ├── conftest.py              # Pytest fixtures and mocks
  ├── test_smoke.py            # Integration tests
  └── unit/                    # Isolated module tests
```

## License & Author

**Author**: Harsimran Sidhu (Original), Maintained by Mohamed Taher  
**License**: [MIT License](LICENSE)

## Contributing

Contributions are welcome. Please review [SECURITY.md](SECURITY.md) for responsible disclosure of security issues before opening public issues or pull requests.

---

**Report a vulnerability**: See [SECURITY.md](SECURITY.md)  
**Feature requests or bugs**: [GitHub Issues](https://github.com/MohamedxTaher/Vigilant-IOC/issues)  
**Repository**: [github.com/MohamedxTaher/Vigilant-IOC](https://github.com/MohamedxTaher/Vigilant-IOC)
