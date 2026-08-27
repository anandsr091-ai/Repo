"""
Runs each enabled scanner as a subprocess and saves its raw output.
Each run_* function is defensive: if a tool isn't installed, it prints a
clear message instead of crashing the whole pipeline.
"""
import os
import shutil
import subprocess
import config


def _tool_missing(binary):
    return shutil.which(binary) is None


def run(cmd, label, output_file=None):
    print(f"[orchestrator] Running {label} ...")
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=1800,
            encoding="utf-8", errors="replace",
)
        # Many scanners exit 1 when findings exist -- that's normal, not a crash.
        if result.returncode not in (0, 1):
            print(f"[orchestrator] WARNING: {label} exited with code {result.returncode}")
            print(result.stderr[-500:])
        else:
            print(f"[orchestrator] {label} finished.")
        return result
    except subprocess.TimeoutExpired:
        print(f"[orchestrator] ERROR: {label} timed out.")
    except FileNotFoundError:
        print(f"[orchestrator] ERROR: {label} tool not found. Is it installed?")
    return None


def run_semgrep():
    if _tool_missing("semgrep"):
        print("[orchestrator] SKIP Semgrep: not installed (pip install semgrep).")
        return
    cmd = f'semgrep --config="{config.SEMGREP_CONFIG}" --json --output="{config.SEMGREP_OUTPUT}" "{config.TARGET_CODE_PATH}"'
    run(cmd, "Semgrep (static analysis)")


def run_trufflehog():
    if _tool_missing("trufflehog"):
        print("[orchestrator] SKIP TruffleHog: not installed.")
        print("  Install: https://github.com/trufflesecurity/trufflehog#installation")
        return
    cmd = f'trufflehog filesystem "{config.TARGET_CODE_PATH}" --json'
    result = run(cmd, "TruffleHog (secrets scan)")
    if result is not None:
        with open(config.TRUFFLEHOG_OUTPUT, "w", encoding="utf-8") as f:
            f.write(result.stdout)


def run_pip_audit():
    req_file = os.path.join(config.TARGET_CODE_PATH, "requirements.txt")
    if not os.path.exists(req_file):
        print("[orchestrator] SKIP pip-audit: no requirements.txt found in target.")
        return
    if _tool_missing("pip-audit"):
        print("[orchestrator] SKIP pip-audit: not installed (pip install pip-audit).")
        return
    cmd = f'pip-audit -r "{req_file}" -f json -o "{config.PIP_AUDIT_OUTPUT}"'
    run(cmd, "pip-audit (Python dependency scan)")


def run_npm_audit():
    pkg_lock = os.path.join(config.TARGET_CODE_PATH, "package-lock.json")
    if not os.path.exists(pkg_lock):
        print("[orchestrator] SKIP npm audit: no package-lock.json found in target.")
        return
    if _tool_missing("npm"):
        print("[orchestrator] SKIP npm audit: npm not installed.")
        return
    cmd = f'cd "{config.TARGET_CODE_PATH}" && npm audit --json > "{os.path.abspath(config.NPM_AUDIT_OUTPUT)}"'
    run(cmd, "npm audit (Node dependency scan)")


def run_zap():
    # Requires a running ZAP daemon and a live target URL. Meant for your
    # laptop against a running instance of your app, not this pipeline's
    # default sandboxed run.
    if not config.TARGET_URL:
        print("[orchestrator] SKIP ZAP: no TARGET_URL configured.")
        return
    if _tool_missing("zap-baseline.py"):
        print("[orchestrator] SKIP ZAP: zap-baseline.py not found. Install OWASP ZAP.")
        return
    cmd = f'zap-baseline.py -t "{config.TARGET_URL}" -J "{config.ZAP_OUTPUT}"'
    run(cmd, "OWASP ZAP (dynamic scan)")


def run_all():
    if config.ENGINES.get("semgrep"):
        run_semgrep()
    if config.ENGINES.get("trufflehog"):
        run_trufflehog()
    if config.ENGINES.get("pip_audit"):
        run_pip_audit()
    if config.ENGINES.get("npm_audit"):
        run_npm_audit()
    if config.ENGINES.get("zap"):
        run_zap()
    print("[orchestrator] All enabled scans complete. Raw output saved in:", config.SCAN_DIR)


if __name__ == "__main__":
    run_all()
