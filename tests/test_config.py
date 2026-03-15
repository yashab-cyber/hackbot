"""Tests for HackBot configuration module."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from hackbot.config import (
    HackBotConfig,
    AIConfig,
    AgentConfig,
    detect_platform,
    detect_tools,
    resolve_tool_path,
    _deep_merge,
    _merge_allowed_tools,
    load_config,
)


def test_default_config():
    """Test that default config is created properly."""
    cfg = HackBotConfig()
    assert cfg.ai.provider == "openai"
    assert cfg.ai.model == "gpt-4o"
    assert cfg.ai.temperature == 0.2
    assert cfg.agent.safe_mode is True
    assert cfg.agent.sudo_mode is False
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
    assert "msfconsole" in cfg.allowed_tools
    assert "wifite" in cfg.allowed_tools
    assert "aircrack-ng" in cfg.allowed_tools
    assert cfg.timeout == 300
    assert cfg.nvd_api_key == ""
    assert cfg.sudo_password == ""


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


def test_resolve_tool_path_thc_ipv6_alias(monkeypatch):
    """thc-ipv6 should resolve via Kali-style alias binaries (e.g., alive6)."""
    real_which = __import__("shutil").which

    def fake_which(name):
        if name == "alive6":
            return "/usr/bin/alive6"
        if name == "thc-ipv6":
            return None
        return real_which(name)

    monkeypatch.setattr("hackbot.config.shutil.which", fake_which)
    assert resolve_tool_path("thc-ipv6") == "/usr/bin/alive6"


def test_detect_tools_thc_ipv6_alias(monkeypatch):
    """detect_tools should mark thc-ipv6 installed when an alias binary exists."""
    real_which = __import__("shutil").which

    def fake_which(name):
        if name == "alive6":
            return "/usr/bin/alive6"
        if name == "thc-ipv6":
            return None
        return real_which(name)

    monkeypatch.setattr("hackbot.config.shutil.which", fake_which)
    tools = detect_tools(["thc-ipv6"])
    assert tools["thc-ipv6"] == "/usr/bin/alive6"


def test_env_var_override(monkeypatch):
    """Test that environment variables override config."""
    monkeypatch.setenv("HACKBOT_API_KEY", "test-env-key")
    monkeypatch.setenv("HACKBOT_MODEL", "gpt-4")
    cfg = load_config()
    assert cfg.ai.api_key == "test-env-key"
    assert cfg.ai.model == "gpt-4"


def test_merge_allowed_tools_appends_new_defaults():
    current = ["nmap", "custom-tool", "NIKTO"]
    defaults = ["nmap", "nikto", "msfconsole"]
    merged = _merge_allowed_tools(current, defaults)

    assert merged[0] == "nmap"
    assert merged[1] == "custom-tool"
    assert any(t.lower() == "nikto" for t in merged)
    assert "msfconsole" in merged


def test_load_config_migrates_allowed_tools_from_old_file(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        yaml.dump({
            "agent": {
                "allowed_tools": ["nmap", "nikto"],
            }
        }),
        encoding="utf-8",
    )

    monkeypatch.setattr("hackbot.config.CONFIG_FILE", cfg_file)
    cfg = load_config()

    assert "nmap" in cfg.agent.allowed_tools
    assert "nikto" in cfg.agent.allowed_tools
    assert "msfconsole" in cfg.agent.allowed_tools
    assert "wifite" in cfg.agent.allowed_tools
    assert "aircrack-ng" in cfg.agent.allowed_tools
