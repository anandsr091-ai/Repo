"""
Turns the combined, normalized findings into a plain-language report
(text + a simple standalone HTML version, no extra dependencies).
"""
import os
from datetime import datetime
import config

SEVERITY_COLORS = {
    "critical": "#7f1d1d",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#1d4ed8",
    "info": "#374151",
}


def _summary_counts(findings):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def generate_text_report(findings):
    lines = []
    lines.append("WEB APPLICATION SECURITY TOOLKIT -- COMBINED REPORT")
    lines.append(f"Generated: {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"Total findings: {len(findings)}")
    counts = _summary_counts(findings)
    if counts:
        lines.append("By severity: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    lines.append("=" * 60)
    if not findings:
        lines.append("No findings detected across any scanner that ran.")
    else:
        for i, f in enumerate(findings, 1):
            lines.append(f"\n[{i}] {f['severity'].upper()} -- {f['title']}")
            lines.append(f"    Tool: {f['tool']}")
            loc = f["file"] or "n/a"
            if f.get("line"):
                loc += f" (line {f['line']})"
            lines.append(f"    Location: {loc}")
            if f.get("description"):
                lines.append(f"    Details: {f['description']}")
    report_text = "\n".join(lines)
    out_path = os.path.join(config.REPORT_DIR, "combined_report.txt")
    with open(out_path, "w") as out:
        out.write(report_text)
    print(f"[report] Text report written to {out_path}")
    return out_path


def generate_html_report(findings):
    counts = _summary_counts(findings)
    rows = ""
    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "#374151")
        loc = f["file"] or "n/a"
        if f.get("line"):
            loc += f" (line {f['line']})"
        rows += f"""
        <tr>
          <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;">{f['severity'].upper()}</span></td>
          <td>{f['title']}</td>
          <td>{f['tool']}</td>
          <td>{loc}</td>
          <td>{f.get('description','')}</td>
        </tr>"""
    summary_html = " &nbsp;|&nbsp; ".join(f"{k}: {v}" for k, v in counts.items()) or "No findings"
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WebSec Toolkit Report</title>
<style>
body {{ font-family: -apple-system, Arial, sans-serif; margin: 2rem; color: #111; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
th {{ background: #f9fafb; }}
</style></head>
<body>
<h1>Web Application Security Toolkit — Combined Report</h1>
<p>Generated: {datetime.now().isoformat(timespec='seconds')}<br>
Total findings: {len(findings)} &nbsp;|&nbsp; {summary_html}</p>
<table>
<tr><th>Severity</th><th>Finding</th><th>Tool</th><th>Location</th><th>Details</th></tr>
{rows}
</table>
</body></html>"""
    out_path = os.path.join(config.REPORT_DIR, "combined_report.html")
    with open(out_path, "w") as out:
        out.write(html)
    print(f"[report] HTML report written to {out_path}")
    return out_path
