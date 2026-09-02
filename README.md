# Vigilant IOC

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-d73a49.svg)](SECURITY.md)
[![Reports](https://img.shields.io/badge/output-JSON%20%7C%20Markdown%20%7C%20CSV-0ea5e9.svg)](#reports)

<p align="center"><img src="assets/preview.png" alt="Vigilant IOC Preview" width="100%"></p>

## Overview

Vigilant IOC performs fast static document analysis and heuristic IOC extraction for PDF, Office, and RTF files, including macro-enabled Office documents. It identifies suspicious content without executing document macros or embedded code.

Optional VirusTotal and AbuseIPDB lookups add reputation data to the local findings. The final report combines extracted indicators, parser results, reputation data, and a transparent risk score.

## Core features

- Extract URLs, domains, IP addresses, embedded files, JavaScript counts, and macro indicators.
- Parse PDF, Office Open XML, legacy OLE, and RTF documents.
- Detect VBA auto-execution functions, suspicious keywords, API calls, and obfuscation.
- Enrich URLs with VirusTotal and IP addresses with AbuseIPDB when API keys are configured.
- Assign a bounded 0-100 score with benign, low, medium, suspicious, high, and critical verdicts.
- Write Markdown, JSON, CSV, JSONL, and HTML reports.
- Process a single file or a directory through the Click command-line interface.

## Installation

### Prerequisites

- Python 3.10 or newer
- pip
- Optional VirusTotal and AbuseIPDB API keys

```bash
git clone https://github.com/MohamedxTaher/Vigilant-IOC.git
cd Vigilant-IOC
python -m venv .venv
.venv\Scripts\activate       # Windows PowerShell
pip install -r requirements.txt
```

Copy `.env.example` to `.env` only when reputation lookups are needed, then set the relevant API keys:

```env
VT_API_KEY=YOUR_VIRUSTOTAL_API_KEY
ABUSEIPDB_API_KEY=YOUR_ABUSEIPDB_API_KEY
```

## Usage

Inspect available options:

```bash
python main.py --help
```

Scan a document you are authorized to inspect and write a Markdown report:

```bash
python main.py --file path/to/document.docm --report
```

Scan a directory and write JSON output:

```bash
python main.py --dir path/to/documents --json --quiet
```

Useful options include `--threads` for directory scans, `--debug` for diagnostic logging, `--report` for Markdown output, and `--json` for JSON output.

Do not open or execute untrusted documents outside an isolated analysis environment. Vigilant IOC reads files for static analysis; it does not provide sandboxing.

## Extracted indicators

Reports group findings into the following categories:

| Category | Examples |
| --- | --- |
| URLs and domains | Links found in document text, relationships, and macro content |
| C2 IP addresses | IPv4 addresses extracted from document content and reputation results |
| Macro triggers | `AutoOpen`, `Document_Open`, suspicious VBA keywords, and API calls |
| Hash fingerprints | SHA-256 and MD5 values for analyzed files |
| Embedded content | Embedded files and JavaScript objects found in PDFs |

## Reports

Reports are written to `reports/` in Markdown, JSON, CSV, JSONL, or HTML format. The JSON output follows `vigilant_ioc_core/report_schema.json`.

## Development

```bash
pip install -r requirements.txt
pip install -r dev-requirements.txt
python -m pytest -q
python -m ruff check . --select E,F,W --line-length 100
mypy vigilant_ioc_core logger.py settings.py
```

The test suite uses mocks for external reputation services. Files in `examples/` are not required for the test command and should be handled only in an isolated environment.

## Project structure

```text
.
├── vigilant_ioc_core/
│   ├── __init__.py
│   ├── abuseipdb_check.py
│   ├── doc_parser.py
│   ├── exceptions.py
│   ├── heuristics.py
│   ├── macro_analyzer.py
│   ├── pdf_parser.py
│   ├── report_generator.py
│   ├── report_schema.json
│   └── url_reputation.py
├── main.py
├── logger.py
├── settings.py
├── requirements.txt
├── dev-requirements.txt
├── pyproject.toml
├── pytest.ini
├── .env.example
├── SECURITY.md
├── LICENSE
├── tests/
└── examples/
```

## License and author

MIT License. See [LICENSE](LICENSE).

BY-> Mohamed Taher

- GitHub: https://github.com/MohamedxTaher
- LinkedIn: https://www.linkedin.com/in/mohamed-taherx/
