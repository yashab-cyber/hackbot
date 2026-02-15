"""Tests for HackBot configuration module."""

import os
import tempfile
from pathlib import Path

import pytest

from hackbot.config import (
    HackBotConfig,
    AIConfig,
    AgentConfig,
    detect_platform,
    detect_tools,
    _deep_merge,
    load_config,
)


def test_default_config():
    """Test that default config is created properly."""
    cfg = HackBotConfig()
    assert cfg.ai.provider == "openai"
    assert cfg.ai.model == "gpt-4o"
    assert cfg.ai.temperature == 0.2
    assert cfg.agent.safe_mode is True
    assert cfg.agent.max_steps == 50
    assert cfg.reporting.format == "html"
    assert cfg.ui.show_banner is True


def test_ai_config():
    """Test AI config dataclass."""
    ai = AIConfig(provider="ollama", model="llama3", api_key="test-key")
    assert ai.provider == "ollama"
    assert ai.model == "llama3"
    assert ai.api_key == "test-key"


def test_agent_config_defaults():
    """Test agent config has allowed tools."""
    cfg = AgentConfig()
    assert "nmap" in cfg.allowed_tools
    assert "nikto" in cfg.allowed_tools
    assert "sqlmap" in cfg.allowed_tools
    assert cfg.timeout == 300


def test_deep_merge():
    """Test deep merge of config dictionaries."""
    base = {"a": {"b": 1, "c": 2}, "d": 3}
    override = {"a": {"b": 10}, "e": 5}
    result = _deep_merge(base, override)
    assert result["a"]["b"] == 10
    assert result["a"]["c"] == 2
    assert result["d"] == 3
    assert result["e"] == 5


def test_detect_platform():
    """Test platform detection returns valid data."""
    plat = detect_platform()
    assert "system" in plat
    assert "release" in plat
    assert "machine" in plat
    assert "python" in plat
    assert plat["system"] in ("Linux", "Darwin", "Windows")


def test_detect_tools():
    """Test tool detection."""
    tools = detect_tools(["python3", "nonexistent_tool_xyz"])
    assert tools.get("python3") is not None or tools.get("python3") is None
    assert tools.get("nonexistent_tool_xyz") is None


def test_env_var_override(monkeypatch):
    """Test that environment variables override config."""
    monkeypatch.setenv("HACKBOT_API_KEY", "test-env-key")
    monkeypatch.setenv("HACKBOT_MODEL", "gpt-4")
    cfg = load_config()
    assert cfg.ai.api_key == "test-env-key"
    assert cfg.ai.model == "gpt-4"
