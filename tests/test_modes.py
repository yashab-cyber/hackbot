"""Tests for HackBot modes."""

import pytest

from hackbot.modes.plan import PlanMode, PLAN_TEMPLATES
from hackbot.modes.agent import Severity, Finding


def test_plan_templates_exist():
    """Test that plan templates are available."""
    templates = PlanMode.list_templates()
    assert "web_pentest" in templates
    assert "network_pentest" in templates
    assert "api_pentest" in templates
    assert "cloud_audit" in templates
    assert "red_team" in templates
    assert "bug_bounty" in templates


def test_plan_templates_have_phases():
    """Test that each template has phases."""
    for key, template in PLAN_TEMPLATES.items():
        assert "name" in template
        assert "phases" in template
        assert len(template["phases"]) > 0


def test_severity_enum():
    """Test Severity enum values."""
    assert Severity.CRITICAL.value == "Critical"
    assert Severity.HIGH.value == "High"
    assert Severity.MEDIUM.value == "Medium"
    assert Severity.LOW.value == "Low"
    assert Severity.INFO.value == "Info"


def test_finding_creation():
    """Test Finding dataclass."""
    finding = Finding(
        title="SQL Injection",
        severity=Severity.HIGH,
        description="Found SQL injection in login form",
        evidence="' OR '1'='1",
        recommendation="Use parameterized queries",
    )
    assert finding.title == "SQL Injection"
    assert finding.severity == Severity.HIGH

    d = finding.to_dict()
    assert d["severity"] == "High"
    assert d["title"] == "SQL Injection"
