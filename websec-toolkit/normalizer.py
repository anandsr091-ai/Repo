"""
Reads each tool's raw output and maps it into one common finding schema:

{
    "tool": str,
    "severity": "critical" | "high" | "medium" | "low" | "info",
    "title": str,
    "file": str | None,
    "line": int | None,
    "description": str,
}
"""
import json
import os
import config

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return None


def normalize_semgrep():
    data = _load_json(config.SEMGREP_OUTPUT)
    findings = []
    if not data:
        return findings
    sev_map = {"error": "high", "warning": "medium", "info": "info"}
    for r in data.get("results", []):
        sev = r.get("extra", {}).get("severity", "info").lower()
        sev = sev_map.get(sev, sev)
        findings.append({
            "tool": "Semgrep",
            "severity": sev,
            "title": r.get("check_id", "Static analysis finding"),
            "file": r.get("path"),
            "line": r.get("start", {}).get("line"),
            "description": r.get("extra", {}).get("message", ""),
        })
    return findings


def normalize_trufflehog():
    findings = []
    if not os.path.exists(config.TRUFFLEHOG_OUTPUT):
        return findings
    with open(config.TRUFFLEHOG_OUTPUT, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            source_meta = r.get("SourceMetadata", {}).get("Data", {})
            file_path = source_meta.get("Filesystem", {}).get("file")
            findings.append({
                "tool": "TruffleHog",
                "severity": "critical",  # leaked secrets are always treated as critical
                "title": f"Leaked secret: {r.get('DetectorName', 'unknown')}",
                "file": file_path,
                "line": None,
                "description": "Possible credential/secret committed to source.",
            })
    return findings


def normalize_pip_audit():
    data = _load_json(config.PIP_AUDIT_OUTPUT)
    findings = []
    if not data:
        return findings
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    if isinstance(deps, list):
        for dep in deps:
            name = dep.get("name", "unknown package")
            version = dep.get("version", "")
            for vuln in dep.get("vulns", []) or []:
                findings.append({
                    "tool": "pip-audit",
                    "severity": "high",  # pip-audit doesn't grade severity by default; treat as high
                    "title": f"{name} {version}: {vuln.get('id', 'vulnerability')}",
                    "file": "requirements.txt",
                    "line": None,
                    "description": "; ".join(vuln.get("description", "").split("\n"))[:400],
                })
    return findings


def normalize_npm_audit():
    data = _load_json(config.NPM_AUDIT_OUTPUT)
    findings = []
    if not data:
        return findings
    vulns = data.get("vulnerabilities", {})
    for name, info in vulns.items():
        sev = info.get("severity", "info").lower()
        via = info.get("via", [])
        title_bits = [v.get("title", v) if isinstance(v, dict) else str(v) for v in via]
        findings.append({
            "tool": "npm audit",
            "severity": sev,
            "title": f"{name}: {', '.join(str(t) for t in title_bits[:2])}",
            "file": "package-lock.json",
            "line": None,
            "description": f"Affected range: {info.get('range', 'unknown')}",
        })
    return findings


def normalize_zap():
    data = _load_json(config.ZAP_OUTPUT)
    findings = []
    if not data:
        return findings
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "Info").split(" ")[0].lower()
            findings.append({
                "tool": "OWASP ZAP",
                "severity": risk,
                "title": alert.get("name", "Runtime finding"),
                "file": config.TARGET_URL,
                "line": None,
                "description": alert.get("desc", "")[:400],
            })
    return findings


def normalize_all():
    findings = (
        normalize_semgrep()
        + normalize_trufflehog()
        + normalize_pip_audit()
        + normalize_npm_audit()
        + normalize_zap()
    )
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 5))
    return findings
