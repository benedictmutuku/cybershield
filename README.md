# CYBERSHIELD

An AI-powered phishing and scam detection system for identifying malicious URLs,
messages, and emails. This repository is scaffolded for a final-year project
using Python, scikit-learn, XGBoost, DistilBERT, FastAPI, and Streamlit.

## Project status

The initial project structure and URL feature extractor are in place. Model
training, API endpoints, the Streamlit interface, and message/email analysis
will be added in later development stages. The current feature extractor
provides heuristic URL characteristics; it does not determine whether a URL is
safe or malicious.

## Getting started

1. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   ```

   On Windows, activate it with:

   ```powershell
   .venv\Scripts\Activate.ps1
   ```

2. Install the project dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

3. Run the feature extractor from the repository root:

   ```bash
   python -c "from src.features import extract_url_features; print(extract_url_features('https://login.example.com/verify'))"
   ```

4. Run the tests:

   ```bash
   python -m pytest
   ```

## Building the URL dataset

Place the phishing URL CSV at `data/raw/phishing.csv` and the Tranco domain
CSV at `data/raw/tranco.csv`, then run:

```bash
python build_dataset.py
```

The script supports a URL/domain header or common headerless formats, including
Tranco's `rank,domain` rows. It removes duplicates, adds `https://` to Tranco
domains without a scheme, and writes an equal number of phishing (`label=1`)
and legitimate (`label=0`) entries to `data/processed/urls.csv`. If an address
appears in both sources with the same host, path, and query, it is retained as
phishing only. When the unique classes differ in size, a reproducible sample
from the larger class is used.

## Scan history database

The SQLite database is created automatically at `data/cybershield.db` when
using `api.database`. The `scans` table stores each scan's input, type, risk
score, label, reasons, and creation timestamp. For example:

```python
from api.database import get_recent_scans, get_stats, save_scan

save_scan(
    input_text="https://example.com",
    input_type="url",
    risk_score=0.15,
    label="safe",
    reasons="No suspicious indicators",
)
print(get_recent_scans(limit=10))
print(get_stats())
```

## FastAPI service

Start the API from the repository root with:

```bash
uvicorn api.main:app --reload
```

The service exposes `POST /scan` (JSON body with `input_text` and
`input_type`, either `url` or `message`), `GET /stats`, and `GET /recent`.
Static files in `frontend/` are served under `/static/`; open
`http://127.0.0.1:8000/static/index.html` after starting the server to view the
PhishShield AI dashboard. Its summary statistics are loaded from `GET /stats`;
recent threats and the scan-timeline chart are loaded from `GET /recent`
(Chart.js is loaded from jsDelivr). The scan form submits URLs or messages to
`POST /scan` and displays the risk score, verdict, and reasons; scores above 70
also trigger a high-risk warning. The API scanner uses transparent starter
heuristics; it is not a trained AI model and its results are not a guarantee
of safety.

## URL features

`src/features.py` exposes `extract_url_features(url)`, which returns a
dictionary containing:

- `length`: number of characters in the trimmed URL.
- `dots`, `hyphens`, `digits`, `at_symbol`: character counts across the URL.
- `is_ip_address`: `1` when the parsed hostname is an IPv4 or IPv6 address,
  otherwise `0`.
- `uses_https`: `1` when the URL uses HTTPS, otherwise `0`.
- `subdomains`: number of hostname labels before the final two labels. This is
  a simple estimate, not a public-suffix-aware domain calculation.
- `suspicious_keywords`: count of configured suspicious terms found as
  individual URL tokens.
- `entropy`: Shannon entropy of the URL characters, in bits per character.

The function accepts URLs with or without a scheme. Empty input and malformed
URLs that cannot be parsed raise `ValueError`.

## Project structure

```text
cybershield/
├── data/           # Raw, interim, and processed datasets
├── notebooks/      # Exploratory analysis and experiments
├── src/            # Reusable Python code and ML features
├── api/            # FastAPI application
├── app/            # Streamlit user interface
├── frontend/       # Static files served by the API
├── tests/          # Automated tests
├── requirements.txt
└── README.md
```

## Responsible use

This project is an educational security aid. Detection results should be
treated as assessments rather than guarantees; users should not rely on a
single automated result to make high-impact security decisions.
