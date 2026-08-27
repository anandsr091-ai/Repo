"""
Single entrypoint: run every enabled scanner, normalize the output,
write a combined plain-language report.

Usage:
    python main.py
    WEBSEC_TARGET=/path/to/your/app python main.py
"""
import orchestrator
import normalizer
import report
import config


def main():
    print(f"[main] Target: {config.TARGET_CODE_PATH}")
    print(f"[main] Enabled engines: {[k for k, v in config.ENGINES.items() if v]}")
    orchestrator.run_all()
    findings = normalizer.normalize_all()
    text_path = report.generate_text_report(findings)
    html_path = report.generate_html_report(findings)
    print(f"\n[main] Done. {len(findings)} findings.")
    print(f"[main] Open: {html_path}")


if __name__ == "__main__":
    main()
