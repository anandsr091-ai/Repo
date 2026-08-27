# websec-toolkit

A personal web-application security scanner: stitches together free,
battle-tested open-source engines into one orchestrated pipeline with
a single combined report. No commercial platform, no license fees.

## Architecture

| Layer | Purpose | Tool(s) |
|---|---|---|
| 1. Scanning engines | Do the actual analysis | Semgrep (static code), TruffleHog (leaked secrets), pip-audit / npm audit (vulnerable dependencies) |
| 2. Orchestration | Runs each tool, collects raw output | `orchestrator.py` |
| 3. Normalization | Maps every tool's JSON into one schema | `normalizer.py` |
| 4. Reporting | Plain-language combined report (text + HTML) | `report.py` |

**Not included yet, by design:** OWASP Dependency-Check and OWASP ZAP.
Dependency-Check needs a synced NVD feed and ZAP needs a live running
target — both are laptop/CI concerns, not something to wire up on day
one. See "Adding ZAP later" below when you're ready.

## Setup (VS Code / local machine)

```bash
git clone <your-new-repo-url>
cd websec-toolkit
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# TruffleHog is a Go binary, install separately:
# macOS:   brew install trufflehog
# Linux:   curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
# Windows: see https://github.com/trufflesecurity/trufflehog#installation
```

## Usage

Point it at whatever you're building:

```bash
WEBSEC_TARGET=/path/to/your/app python main.py
```

Or edit `TARGET_CODE_PATH` directly in `config.py`.

Open the report:

```
reports/combined_report.html
```

## Toggling engines

Edit the `ENGINES` dict in `config.py`. Each engine no-ops with a clear
message if its tool isn't installed or if the target doesn't apply
(e.g. `npm_audit` skips if there's no `package-lock.json`), so it's
safe to leave everything on.

## Adding ZAP later (dynamic/runtime scanning)

1. Get your app running locally (`npm run dev`, etc.) or in a staging
   environment you're authorized to test.
2. Install OWASP ZAP and confirm `zap-baseline.py` is on your PATH.
3. Set `TARGET_URL` in `config.py` (or `WEBSEC_TARGET_URL` env var) and
   flip `zap: True` in `ENGINES`.

## Adding Dependency-Check later (deeper CVE coverage)

Dependency-Check's CVE database is more current/detailed than
pip-audit/npm audit in some cases, at the cost of a slower first-run
NVD sync and a Java dependency. Worth adding once the core pipeline
is stable and you want that extra depth.

## Important: only scan code you're authorized to scan

Never run this against an employer's code or systems without explicit
written sign-off from security/engineering leadership. Use it on your
own projects or open-source code until you have that.
