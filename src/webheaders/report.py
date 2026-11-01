"""Render a Report as JSON or HTML."""
from __future__ import annotations

import html
import json

from webheaders.checks import Report


def to_json(report: Report) -> str:
    return json.dumps(
        {
            "url": report.url,
            "score": report.score,
            "grade": report.grade,
            "findings": [f.__dict__ for f in report.findings],
        },
        indent=2,
    )


def to_html(report: Report) -> str:
    rows = "\n".join(
        f"<tr class='{f.status}'><td>{html.escape(f.name)}</td>"
        f"<td>{f.status.upper()}</td><td>{html.escape(f.detail)}</td></tr>"
        for f in report.findings
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Security headers: {html.escape(report.url)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
td, th {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; }}
.pass td:nth-child(2) {{ color: #0a7d2c; }}
.warn td:nth-child(2) {{ color: #b26a00; }}
.fail td:nth-child(2) {{ color: #b00020; }}
</style></head><body>
<h1>Security headers report</h1>
<p><strong>URL:</strong> {html.escape(report.url)}<br>
<strong>Score:</strong> {report.score} / 100 (grade {report.grade})</p>
<table><tr><th>Check</th><th>Status</th><th>Detail</th></tr>
{rows}
</table></body></html>"""
