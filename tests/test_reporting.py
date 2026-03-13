"""Tests for generic (HTML/Markdown/JSON) report generation."""

import json
from pathlib import Path
from unittest.mock import patch

from hackbot.reporting import ReportGenerator


SAMPLE_FINDINGS = [
    {
        "title": "Missing Security Header",
        "severity": "Low",
        "description": "X-Frame-Options not set.",
    }
]


def test_normalize_tool_history_fills_missing_tool_and_command():
    raw = [
        {"command": "nmap -sV example.com", "success": True, "duration": 2.1, "return_code": 0},
        {"tool": "nikto", "command": "", "success": False, "duration": 4.2, "return_code": 1},
        {"success": True},
    ]

    normalized = ReportGenerator._normalize_tool_history(raw)

    assert normalized[0]["tool"] == "nmap"
    assert normalized[0]["command"] == "nmap -sV example.com"
    assert normalized[1]["tool"] == "nikto"
    assert normalized[1]["command"] == "(no command)"
    assert normalized[2]["tool"] == "unknown"
    assert normalized[2]["command"] == "(no command)"


def test_markdown_report_contains_tool_and_command(tmp_path):
    with patch("hackbot.reporting.REPORTS_DIR", tmp_path):
        rg = ReportGenerator(report_format="markdown")
        path = rg.generate(
            target="example.com",
            findings=SAMPLE_FINDINGS,
            tool_history=[{"command": "nmap -sV example.com", "success": True, "duration": 1.2, "return_code": 0}],
        )

        text = Path(path).read_text(encoding="utf-8")
        assert "## Tool Execution Log" in text
        assert "[nmap]" in text
        assert "nmap -sV example.com" in text


def test_json_report_contains_normalized_tool_history(tmp_path):
    with patch("hackbot.reporting.REPORTS_DIR", tmp_path):
        rg = ReportGenerator(report_format="json")
        path = rg.generate(
            target="example.com",
            findings=SAMPLE_FINDINGS,
            tool_history=[{"command": "curl -I https://example.com", "success": True}],
        )

        data = json.loads(Path(path).read_text(encoding="utf-8"))
        assert data["tool_history"][0]["tool"] == "curl"
        assert data["tool_history"][0]["command"] == "curl -I https://example.com"
