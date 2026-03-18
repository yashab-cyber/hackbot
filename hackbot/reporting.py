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

<h2>1. Executive Summary</h2>
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

<h2>2. Risk Assessment Charts</h2>
{% if severity_counts %}
<table style="width: 100%; border-collapse: collapse; margin: 1rem 0;">
  <thead>
    <tr style="background: var(--accent); color: white;">
      <th style="padding: 0.5rem 1rem; text-align: left;">Severity</th>
      <th style="padding: 0.5rem 1rem; text-align: center;">Count</th>
      <th style="padding: 0.5rem 1rem; text-align: center;">Percentage</th>
    </tr>
  </thead>
  <tbody>
    {% for sev, count in severity_counts.items() %}
    <tr style="background: var(--surface); border-bottom: 1px solid var(--border);">
      <td style="padding: 0.5rem 1rem; font-weight: 600;">
        <span class="severity-badge severity-{{ sev }}">{{ sev }}</span>
      </td>
      <td style="padding: 0.5rem 1rem; text-align: center;">{{ count }}</td>
      <td style="padding: 0.5rem 1rem; text-align: center;">{{ (count / total_findings * 100) | round(0) | int if total_findings else 0 }}%</td>
    </tr>
    {% endfor %}
    <tr style="background: var(--bg); border-top: 2px solid var(--border); font-weight: 700;">
      <td style="padding: 0.5rem 1rem;">Total</td>
      <td style="padding: 0.5rem 1rem; text-align: center;">{{ total_findings }}</td>
      <td style="padding: 0.5rem 1rem; text-align: center;">100%</td>
    </tr>
  </tbody>
</table>
{% else %}
<p style="color: var(--text-dim);">No findings recorded.</p>
{% endif %}

<h2>3. Detailed Findings</h2>
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
<h2>4. List of Commands Executed</h2>
{% for entry in tool_history %}
<div class="tool-entry">
  <div><strong>#{{ loop.index }} Tool:</strong> <span class="tool-cmd">{{ entry.tool }}</span></div>
  <div><strong>Sudo:</strong> {{ 'Yes' if entry.sudo_used else 'No' }}</div>
  <span class="tool-cmd">$ {{ entry.command }}</span>
  <span class="tool-status {{ 'success' if entry.success else 'failed' }}">
    {{ '✓' if entry.success else '✗' }}
  </span>
  <span style="color: var(--text-dim);">({{ entry.duration }}s, exit={{ entry.return_code }})</span>
</div>
{% endfor %}

<h2>5. Technical Annex (Agent Output)</h2>
{% if include_raw %}
{% for entry in tool_history %}
<div class="tool-entry">
  <div><strong>#{{ loop.index }} {{ entry.tool }}</strong></div>
  <div class="tool-cmd">$ {{ entry.command }}</div>
  <pre><code>{{ entry.annex_output[:8000] }}</code></pre>
</div>
{% endfor %}
{% else %}
<p>Raw output export is disabled by configuration (`include_raw_output: false`).</p>
{% endif %}
{% endif %}

{% if scripts %}
<h2>Generated Scripts</h2>
{% for script in scripts %}
<div class="tool-entry">
  <div><strong>Name:</strong> <span class="tool-cmd">{{ script.name }}</span></div>
  <div><strong>Language:</strong> <span class="tool-cmd">{{ script.language }}</span></div>
  {% if script.path %}<div><strong>Saved To:</strong> {{ script.path }}</div>{% endif %}
  {% if script.description %}<p>{{ script.description }}</p>{% endif %}
  <pre><code>{{ script.content[:4000] }}</code></pre>
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
        scripts: List[Dict[str, Any]] = None,
        scope: str = "",
        summary: str = "",
        start_time: float = 0,
    ) -> str:
        """Generate a report and return the file path."""
        if self.report_format == "html":
            return self._generate_html(target, findings, tool_history, scripts, scope, summary, start_time)
        elif self.report_format == "markdown":
            return self._generate_markdown(target, findings, tool_history, scripts, scope, summary, start_time)
        elif self.report_format == "json":
            return self._generate_json(target, findings, tool_history, scripts, scope, summary, start_time)
        else:
            return self._generate_html(target, findings, tool_history, scripts, scope, summary, start_time)

    def _generate_html(
        self, target, findings, tool_history, scripts, scope, summary, start_time
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
        normalized_tool_history = self._normalize_tool_history(tool_history)
        normalized_scripts = self._normalize_scripts(scripts)
        html = template.render(
            target=target,
            date=time.strftime("%Y-%m-%d %H:%M:%S"),
            scope=scope,
            duration=duration,
            severity_counts=severity_counts,
            total_findings=len(findings),
            summary=summary,
            findings=findings,
            tool_history=normalized_tool_history,
            scripts=normalized_scripts,
            include_raw=self.include_raw,
        )

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

        return str(path)

    def _generate_markdown(
        self, target, findings, tool_history, scripts, scope, summary, start_time
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

        lines.append("## 1. Executive Summary")
        lines.append("")
        if summary:
            lines.extend([summary, ""])

        # Risk Assessment Charts section
        severity_counts = {}
        for finding in findings:
            sev = finding.get("severity", "Info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        total = len(findings)

        lines.extend(["## 2. Risk Assessment Charts", ""])
        lines.append("| Severity | Count | Percentage |")
        lines.append("|----------|-------|------------|")
        for sev, count in severity_counts.items():
            pct = f"{count / total * 100:.0f}%" if total else "0%"
            lines.append(f"| {sev} | {count} | {pct} |")
        lines.append(f"| **Total** | **{total}** | **100%** |")
        lines.append("")

        lines.extend(["## 3. Detailed Findings", ""])

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

        normalized_tool_history = self._normalize_tool_history(tool_history)

        if normalized_tool_history:
            lines.extend(["## 4. List of Commands Executed", ""])
            for entry in normalized_tool_history:
                status = "✓" if entry.get("success") else "✗"
                lines.append(
                    f"- {status} [{entry.get('tool', 'unknown')}] `{entry.get('command', '(no command)')}` "
                    f"(sudo={'yes' if entry.get('sudo_used') else 'no'}, "
                    f"exit={entry.get('return_code', '')}, {entry.get('duration', 0)}s)"
                )

            lines.extend(["", "## 5. Technical Annex (Agent Output)", ""])
            if self.include_raw:
                for i, entry in enumerate(normalized_tool_history, 1):
                    lines.extend([
                        f"### {i}. {entry.get('tool', 'unknown')}",
                        f"Command: `{entry.get('command', '(no command)')}`",
                        "```",
                        str(entry.get("annex_output", ""))[:8000],
                        "```",
                        "",
                    ])
            else:
                lines.append("Raw output export is disabled by configuration (`include_raw_output: false`).")

        normalized_scripts = self._normalize_scripts(scripts)
        if normalized_scripts:
            lines.extend(["", "## Generated Scripts", ""])
            for i, script in enumerate(normalized_scripts, 1):
                lines.append(
                    f"### {i}. {script.get('name', 'generated_script')} "
                    f"[{script.get('language', 'text')}]"
                )
                if script.get("description"):
                    lines.append(script.get("description", ""))
                if script.get("path"):
                    lines.append(f"Saved to: `{script.get('path')}`")
                lines.extend([
                    f"```{script.get('language', 'text')}",
                    script.get("content", ""),
                    "```",
                    "",
                ])

        lines.extend(["", "---", f"*Generated by HackBot AI Cybersecurity Assistant*"])

        content = "\n".join(lines)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        return str(path)

    def _generate_json(
        self, target, findings, tool_history, scripts, scope, summary, start_time
    ) -> str:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"report_{target.replace('/', '_').replace(':', '_')}_{ts}.json"

        normalized_tool_history = self._normalize_tool_history(tool_history)

        severity_counts: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "Info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        total = len(findings)

        risk_assessment = [
            {
                "severity": sev,
                "count": count,
                "percentage": f"{count / total * 100:.0f}%" if total else "0%",
            }
            for sev, count in severity_counts.items()
        ]

        data = {
            "target": target,
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scope": scope,
            "summary": summary,
            "risk_assessment": risk_assessment,
            "findings": findings,
            "tool_history": normalized_tool_history,
            "commands_executed": [
                {
                    "index": i + 1,
                    "tool": e.get("tool", "unknown"),
                    "command": e.get("command", "(no command)"),
                    "sudo_used": bool(e.get("sudo_used", False)),
                    "success": bool(e.get("success", False)),
                    "return_code": e.get("return_code", ""),
                    "duration": e.get("duration", 0),
                }
                for i, e in enumerate(normalized_tool_history)
            ],
            "technical_annex": [
                {
                    "index": i + 1,
                    "tool": e.get("tool", "unknown"),
                    "command": e.get("command", "(no command)"),
                    "output": str(e.get("annex_output", "")) if self.include_raw else "",
                }
                for i, e in enumerate(normalized_tool_history)
            ],
            "scripts": self._normalize_scripts(scripts),
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return str(path)

    @staticmethod
    def _normalize_tool_history(tool_history: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Ensure each tool log entry has explicit tool and command values for reporting."""
        normalized: List[Dict[str, Any]] = []
        for entry in tool_history or []:
            cmd = str(entry.get("command", "") or "").strip()
            tool = str(entry.get("tool", "") or "").strip()
            if not tool and cmd:
                tool = cmd.split()[0]

            out = dict(entry)
            out["tool"] = tool or "unknown"
            out["command"] = cmd or "(no command)"
            out["sudo_used"] = out["command"].startswith("sudo ")

            stdout = str(out.get("stdout", "") or "")
            stderr = str(out.get("stderr", "") or "")
            if stdout and stderr:
                out["annex_output"] = f"{stdout}\n\n[STDERR]\n{stderr}"
            elif stdout:
                out["annex_output"] = stdout
            elif stderr:
                out["annex_output"] = f"[STDERR]\n{stderr}"
            else:
                out["annex_output"] = "(no output)"
            normalized.append(out)
        return normalized

    @staticmethod
    def _normalize_scripts(scripts: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Normalize generated script entries for report rendering."""
        normalized: List[Dict[str, Any]] = []
        for script in scripts or []:
            out = dict(script)
            out["name"] = str(out.get("name", "generated_script") or "generated_script").strip()
            out["language"] = str(out.get("language", "text") or "text").strip()
            out["content"] = str(out.get("content", "") or "")
            out["description"] = str(out.get("description") or out.get("purpose") or "")
            out["path"] = str(out.get("path", "") or "")
            normalized.append(out)
        return normalized
