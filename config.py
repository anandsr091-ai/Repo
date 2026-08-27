"""
Central configuration: target path, tool commands, output locations.
Edit TARGET_CODE_PATH (and TARGET_URL if/when you add ZAP later) to point
at the app you want to scan.
"""
import os

# --- What to scan ---
TARGET_CODE_PATH = os.environ.get("WEBSEC_TARGET", "./target-app")  # local source folder
TARGET_URL = os.environ.get("WEBSEC_TARGET_URL", "")  # only used if/when ZAP is enabled (laptop, not sandbox)

# Semgrep ruleset. "auto" and "p/..." pull from semgrep.dev's registry, which
# needs open internet access. On your laptop with normal internet, switch
# this to "auto" (best default) or "p/security-audit" (broader, curated).
# The bundled local rules are a small offline starter set so the pipeline
# still works in network-restricted environments (e.g. this sandbox).
SEMGREP_CONFIG = os.environ.get("WEBSEC_SEMGREP_CONFIG", "./semgrep-rules/basic-rules.yml")

# --- Which engines to run ---
# Toggle these off/on depending on what's installed on your machine.
ENGINES = {
    "semgrep": True,
    "trufflehog": True,
    "pip_audit": True,      # only meaningful if TARGET_CODE_PATH is a Python project (has requirements.txt)
    "npm_audit": True,      # only meaningful if TARGET_CODE_PATH is a Node project (has package-lock.json)
    "zap": False,           # leave off until you're running against a live app on your laptop
}

# --- Paths ---
SCAN_DIR = "scans"
REPORT_DIR = "reports"
os.makedirs(SCAN_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

SEMGREP_OUTPUT = os.path.join(SCAN_DIR, "semgrep.json")
TRUFFLEHOG_OUTPUT = os.path.join(SCAN_DIR, "trufflehog.json")
PIP_AUDIT_OUTPUT = os.path.join(SCAN_DIR, "pip_audit.json")
NPM_AUDIT_OUTPUT = os.path.join(SCAN_DIR, "npm_audit.json")
ZAP_OUTPUT = os.path.join(SCAN_DIR, "zap.json")
