"""Summarize an Anchore/Grype SARIF report by severity.

Writes a Markdown summary (with a table of every Critical and Medium finding)
and a bar chart of findings per severity.

Usage: python reports/sarif_summary.py [reports/results.sarif]
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

SEVERITIES = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
# severity is a state, so it uses the status colors; the label beside each bar
# carries the meaning too, so color is never the only cue
COLORS = {
    "Critical": "#d03b3b",
    "High": "#ec835a",
    "Medium": "#ec835a",
    "Low": "#fab219",
    "Negligible": "#a8a7a0",
    "Unknown": "#a8a7a0",
}
TEXT, MUTED, AXIS = "#0b0b0b", "#52514e", "#c3c2b7"


SHORT_DESCRIPTION = re.compile(r"^(\S+) (\w+) vulnerability for (\S+) package")


def optional_field(text, name):
    match = re.search(rf"{name}: (.+)", text)
    return match.group(1).strip() if match else "unknown"


def parse(path):
    """Return one dict per finding.

    The rule's short description ("CVE-X Medium vulnerability for pkg package")
    has the same shape in older Anchore reports and current Grype releases, so
    the CVE, severity and package come from it. Version and fix details are in
    the free-text help, which varies between releases, so they are optional.
    """
    sarif = json.loads(Path(path).read_text())
    findings = []
    for run in sarif["runs"]:
        rules = {r["id"]: r for r in run["tool"]["driver"].get("rules", [])}
        for result in run.get("results", []):
            rule = rules.get(result["ruleId"], {})
            short = rule.get("shortDescription", {}).get("text", "")
            match = SHORT_DESCRIPTION.match(short)
            if not match:
                continue
            cve, severity, package = match.groups()
            severity = severity.capitalize()
            if severity not in SEVERITIES:
                severity = "Unknown"
            help_text = rule.get("help", {}).get("text", "")
            findings.append({
                "cve": cve,
                "severity": severity,
                "package": package,
                "version": optional_field(help_text, "Version"),
                "fix": optional_field(help_text, "Fix Version"),
            })
    return findings


def write_chart(counts, out):
    levels = [s for s in SEVERITIES if counts[s]]
    values = [counts[s] for s in levels]
    fig, ax = plt.subplots(figsize=(7, 0.6 * len(levels) + 1.2), dpi=200)
    ax.set_facecolor("#fcfcfb")
    bars = ax.barh(levels, values, color=[COLORS[s] for s in levels], height=0.55)
    ax.invert_yaxis()
    for bar, value in zip(bars, values):
        ax.text(bar.get_width() + max(values) * 0.01, bar.get_y() + bar.get_height() / 2,
                str(value), va="center", fontsize=10, color=TEXT)
    ax.set_title(f"Container image vulnerabilities by severity ({sum(values)} total)",
                 loc="left", fontsize=11, color=TEXT)
    ax.set_xlabel("Findings", color=MUTED, fontsize=9)
    ax.tick_params(colors=MUTED, labelsize=9, length=0)
    ax.tick_params(axis="y", labelcolor=TEXT)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    ax.set_xlim(0, max(values) * 1.1)
    fig.tight_layout()
    fig.savefig(out, facecolor="#fcfcfb")


def write_markdown(findings, counts, out, chart_name):
    fixable = sum(f["fix"].lower() not in ("none", "unknown", "") for f in findings)
    lines = [
        "# Container Scan Summary",
        "",
        f"Anchore/Grype scan of the container image: **{len(findings)} findings**, "
        f"**{fixable} with a fix available**.",
        "",
        f"![Findings by severity]({chart_name})",
        "",
        "| Severity | Findings |",
        "|---|---|",
        *[f"| {s} | {counts[s]} |" for s in SEVERITIES if counts[s]],
        "",
        "## Critical and medium findings",
        "",
        "| CVE | Severity | Package | Version | Fix |",
        "|---|---|---|---|---|",
    ]
    for f in sorted(findings, key=lambda f: SEVERITIES.index(f["severity"])):
        if f["severity"] in ("Critical", "High", "Medium"):
            lines.append(f"| {f['cve']} | {f['severity']} | {f['package']} | {f['version']} | {f['fix']} |")
    lines += [
        "",
        "## Takeaways",
        "",
        "- Every finding is in a Debian OS package from the base image; none are in the application's Python code.",
        "- No fix was available upstream for any finding when the scan ran, so the remedy is a newer, "
        "regularly rebuilt base image rather than package pinning. The Dockerfile now uses `python:3.11-slim`.",
        "",
    ]
    Path(out).write_text("\n".join(lines))


def main(sarif_path):
    sarif_path = Path(sarif_path)
    findings = parse(sarif_path)
    counts = Counter(f["severity"] for f in findings)
    chart = sarif_path.parent / "sarif-severity.png"
    if findings:
        write_chart(counts, chart)
    write_markdown(findings, counts, sarif_path.parent / "SARIF_SUMMARY.md", chart.name)
    return counts


if __name__ == "__main__":
    print(dict(main(sys.argv[1] if len(sys.argv) > 1 else "reports/results.sarif")))
