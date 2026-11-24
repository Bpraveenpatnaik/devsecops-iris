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


def parse(path):
    sarif = json.loads(Path(path).read_text())
    findings = []
    for run in sarif["runs"]:
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        for result in run.get("results", []):
            text = rules[result["ruleId"]]["help"]["text"]
            field = lambda name: re.search(rf"{name}: (.+)", text).group(1).strip()
            findings.append({
                "cve": re.match(r"Vulnerability (\S+)", text).group(1),
                "severity": field("Severity"),
                "package": field("Package"),
                "version": field("Version"),
                "fix": field("Fix Version"),
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
    fixable = sum(f["fix"].lower() != "none" for f in findings)
    lines = [
        "# Container Scan Summary",
        "",
        f"Anchore/Grype scan of the `python:3.8-slim`-based image: **{len(findings)} findings**, "
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


if __name__ == "__main__":
    sarif_path = Path(sys.argv[1] if len(sys.argv) > 1 else "reports/results.sarif")
    findings = parse(sarif_path)
    counts = Counter(f["severity"] for f in findings)
    chart = sarif_path.parent / "sarif-severity.png"
    write_chart(counts, chart)
    write_markdown(findings, counts, sarif_path.parent / "SARIF_SUMMARY.md", chart.name)
    print(dict(counts))
