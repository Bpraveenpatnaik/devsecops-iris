import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "reports"))
import sarif_summary  # noqa: E402


def make_sarif(tmp_path, rules):
    sarif = {"runs": [{
        "tool": {"driver": {"rules": rules}},
        "results": [{"ruleId": r["id"]} for r in rules],
    }]}
    path = tmp_path / "results.sarif"
    path.write_text(json.dumps(sarif))
    return path


def test_parses_committed_report():
    findings = sarif_summary.parse(Path(__file__).parent / "reports" / "results.sarif")
    assert len(findings) == 72
    assert sum(f["severity"] == "Critical" for f in findings) == 2


def test_parses_current_grype_format_without_fix_line(tmp_path):
    path = make_sarif(tmp_path, [
        {"id": "a", "shortDescription": {"text": "CVE-2025-0001 high vulnerability for openssl package"},
         "help": {"text": "Vulnerability CVE-2025-0001\nSeverity: high\nPackage: openssl"}},
        {"id": "b", "shortDescription": {"text": "CVE-2025-0002 low vulnerability for zlib package"},
         "help": {"text": "Version: 1.2\nFix Version: 1.3"}},
    ])
    findings = sarif_summary.parse(path)
    assert [f["severity"] for f in findings] == ["High", "Low"]
    assert findings[0]["fix"] == "unknown"
    assert findings[1]["fix"] == "1.3"


def test_writes_summary_and_chart(tmp_path):
    path = make_sarif(tmp_path, [
        {"id": "a", "shortDescription": {"text": "CVE-1 critical vulnerability for libc6 package"}},
    ])
    sarif_summary.main(path)
    assert "CVE-1" in (tmp_path / "SARIF_SUMMARY.md").read_text()
    assert (tmp_path / "sarif-severity.png").exists()
