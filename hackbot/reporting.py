"""
HackBot Report Generator
=========================
Generates comprehensive security assessment reports in HTML, Markdown, and JSON formats.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Template

from hackbot.config import REPORTS_DIR


# ── HTML Report Template ─────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HackBot Security Report — {{ target }}</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --text-dim: #8b949e; --accent: #58a6ff;
    --critical: #f85149; --high: #f0883e; --medium: #d29922;
    --low: #58a6ff; --info: #8b949e; --success: #3fb950;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
  .container { max-width: 1100px; margin: 0 auto; }
  h1 { color: var(--success); font-size: 2rem; margin-bottom: 0.5rem; }
  h2 { color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem;
       margin: 2rem 0 1rem; }
  h3 { color: var(--text); margin: 1.5rem 0 0.5rem; }
  .header { background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
            padding: 2rem; margin-bottom: 2rem; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 1rem; margin-top: 1rem; }
  .meta-item { background: var(--bg); padding: 1rem; border-radius: 4px; }
  .meta-label { font-size: 0.85rem; color: var(--text-dim); text-transform: uppercase;
                letter-spacing: 0.05em; }
  .meta-value { font-size: 1.1rem; font-weight: 600; margin-top: 0.25rem; }
  .severity-badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 3px;
                    font-weight: 600; font-size: 0.85rem; }
  .severity-Critical { background: var(--critical); color: white; }
  .severity-High { background: var(--high); color: white; }
  .severity-Medium { background: var(--medium); color: white; }
  .severity-Low { background: var(--low); color: white; }
  .severity-Info { background: var(--info); color: white; }
  .stats { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 4px;
          padding: 1rem 1.5rem; text-align: center; min-width: 100px; }
  .stat-num { font-size: 2rem; font-weight: 700; }
  .stat-label { font-size: 0.85rem; color: var(--text-dim); }
  .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
             padding: 1.5rem; margin-bottom: 1rem; }
  .finding-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; }
  .finding-title { font-weight: 600; font-size: 1.1rem; }
  pre { background: var(--bg); border: 1px solid var(--border); border-radius: 4px;
        padding: 1rem; overflow-x: auto; font-size: 0.9rem; margin: 0.5rem 0; }
  code { font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; }
  .recommendation { background: rgba(56, 139, 253, 0.1); border-left: 3px solid var(--accent);
                    padding: 0.75rem 1rem; margin: 0.5rem 0; border-radius: 0 4px 4px 0; }
  .tool-history { margin: 1rem 0; }
  .tool-entry { background: var(--surface); border: 1px solid var(--border); border-radius: 4px;
                padding: 1rem; margin-bottom: 0.5rem; }
  .tool-cmd { font-family: monospace; color: var(--success); }
  .tool-status { font-weight: 600; }
  .success { color: var(--success); }
  .failed { color: var(--critical); }
  footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
           color: var(--text-dim); font-size: 0.85rem; text-align: center; }
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>⚡ HackBot Security Report</h1>
  <div class="meta">
    <div class="meta-item">
      <div class="meta-label">Target</div>
      <div class="meta-value">{{ target }}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Date</div>
      <div class="meta-value">{{ date }}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Scope</div>
      <div class="meta-value">{{ scope or 'Full Assessment' }}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Duration</div>
      <div class="meta-value">{{ duration }}</div>
    </div>
  </div>
</div>

<h2>Executive Summary</h2>
<div class="stats">
  {% for sev, count in severity_counts.items() %}
  <div class="stat">
    <div class="stat-num severity-{{ sev }}" style="color: inherit;">{{ count }}</div>
    <div class="stat-label">{{ sev }}</div>
  </div>
  {% endfor %}
  <div class="stat">
    <div class="stat-num">{{ total_findings }}</div>
    <div class="stat-label">Total</div>
  </div>
</div>

{% if summary %}
<p>{{ summary }}</p>
{% endif %}

<h2>Findings</h2>
{% for finding in findings %}
<div class="finding">
  <div class="finding-header">
    <span class="severity-badge severity-{{ finding.severity }}">{{ finding.severity }}</span>
    <span class="finding-title">{{ finding.title }}</span>
  </div>
  <p>{{ finding.description }}</p>
  {% if finding.evidence %}
  <h4>Evidence</h4>
  <pre><code>{{ finding.evidence }}</code></pre>
  {% endif %}
  {% if finding.recommendation %}
  <div class="recommendation">
    <strong>Recommendation:</strong> {{ finding.recommendation }}
  </div>
  {% endif %}
</div>
{% endfor %}

{% if tool_history %}
<h2>Tool Execution Log</h2>
{% for entry in tool_history %}
<div class="tool-entry">
  <span class="tool-cmd">$ {{ entry.command }}</span>
  <span class="tool-status {{ 'success' if entry.success else 'failed' }}">
    {{ '✓' if entry.success else '✗' }}
  </span>
  <span style="color: var(--text-dim);">({{ entry.duration }}s, exit={{ entry.return_code }})</span>
  {% if entry.stdout and include_raw %}
  <details>
    <summary style="cursor: pointer; color: var(--accent); margin-top: 0.5rem;">Output</summary>
    <pre><code>{{ entry.stdout[:2000] }}</code></pre>
  </details>
  {% endif %}
</div>
{% endfor %}
{% endif %}

<footer>
  Generated by HackBot AI Cybersecurity Assistant • {{ date }}
</footer>

</div>
</body>
</html>"""


class ReportGenerator:
    """Generates security assessment reports."""

    def __init__(self, include_raw: bool = True, report_format: str = "html"):
        self.include_raw = include_raw
        self.report_format = report_format

    def generate(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        tool_history: List[Dict[str, Any]] = None,
        scope: str = "",
        summary: str = "",
        start_time: float = 0,
    ) -> str:
        """Generate a report and return the file path."""
        if self.report_format == "html":
            return self._generate_html(target, findings, tool_history, scope, summary, start_time)
        elif self.report_format == "markdown":
            return self._generate_markdown(target, findings, tool_history, scope, summary, start_time)
        elif self.report_format == "json":
            return self._generate_json(target, findings, tool_history, scope, summary, start_time)
        else:
            return self._generate_html(target, findings, tool_history, scope, summary, start_time)

    def _generate_html(
        self, target, findings, tool_history, scope, summary, start_time
    ) -> str:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"report_{target.replace('/', '_').replace(':', '_')}_{ts}.html"

        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "Info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        duration = ""
        if start_time:
            mins = (time.time() - start_time) / 60
            duration = f"{mins:.0f} minutes"

        template = Template(HTML_TEMPLATE)
        html = template.render(
            target=target,
            date=time.strftime("%Y-%m-%d %H:%M:%S"),
            scope=scope,
            duration=duration,
            severity_counts=severity_counts,
            total_findings=len(findings),
            summary=summary,
            findings=findings,
            tool_history=tool_history or [],
            include_raw=self.include_raw,
        )

        with open(path, "w") as f:
            f.write(html)

        return str(path)

    def _generate_markdown(
        self, target, findings, tool_history, scope, summary, start_time
    ) -> str:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"report_{target.replace('/', '_').replace(':', '_')}_{ts}.md"

        lines = [
            f"# HackBot Security Report",
            f"",
            f"**Target:** {target}",
            f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Scope:** {scope or 'Full Assessment'}",
            f"",
        ]

        if summary:
            lines.extend(["## Executive Summary", "", summary, ""])

        lines.extend(["## Findings", ""])

        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "Info")
            lines.append(f"### {i}. [{sev}] {f.get('title', 'Untitled')}")
            lines.append(f"")
            lines.append(f"{f.get('description', '')}")
            if f.get("evidence"):
                lines.extend(["", "**Evidence:**", f"```", f["evidence"], "```"])
            if f.get("recommendation"):
                lines.extend(["", f"**Recommendation:** {f['recommendation']}"])
            lines.append("")

        if tool_history:
            lines.extend(["## Tool Execution Log", ""])
            for entry in tool_history:
                status = "✓" if entry.get("success") else "✗"
                lines.append(
                    f"- {status} `{entry.get('command', '')}` "
                    f"(exit={entry.get('return_code', '')}, {entry.get('duration', 0)}s)"
                )

        lines.extend(["", "---", f"*Generated by HackBot AI Cybersecurity Assistant*"])

        content = "\n".join(lines)
        with open(path, "w") as f:
            f.write(content)

        return str(path)

    def _generate_json(
        self, target, findings, tool_history, scope, summary, start_time
    ) -> str:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"report_{target.replace('/', '_').replace(':', '_')}_{ts}.json"

        data = {
            "target": target,
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scope": scope,
            "summary": summary,
            "findings": findings,
            "tool_history": tool_history or [],
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        return str(path)
