"""
HackBot Configuration Management
=================================
Handles config loading, API key management, and platform-specific paths.
"""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from platformdirs import user_config_dir, user_data_dir

APP_NAME = "hackbot"

# ── paths ────────────────────────────────────────────────────────────────────

CONFIG_DIR = Path(user_config_dir(APP_NAME))
DATA_DIR = Path(user_data_dir(APP_NAME))
REPORTS_DIR = DATA_DIR / "reports"
LOGS_DIR = DATA_DIR / "logs"
SESSIONS_DIR = DATA_DIR / "sessions"
CONFIG_FILE = CONFIG_DIR / "config.yaml"


def ensure_dirs() -> None:
    """Create all required directories."""
    for d in (CONFIG_DIR, DATA_DIR, REPORTS_DIR, LOGS_DIR, SESSIONS_DIR):
        d.mkdir(parents=True, exist_ok=True)


# ── default config ───────────────────────────────────────────────────────────

DEFAULT_CONFIG: Dict[str, Any] = {
    "ai": {
        "provider": "openai",
        "model": "gpt-4o",
        "api_key": "",
        "base_url": "",
        "temperature": 0.2,
        "max_tokens": 4096,
    },
    "agent": {
        "auto_confirm": False,
        "max_steps": 50,
        "timeout": 300,
        "safe_mode": True,
        "allowed_tools": [
            "nmap",
            "nikto",
            "gobuster",
            "sqlmap",
            "wfuzz",
            "ffuf",
            "nuclei",
            "subfinder",
            "httpx",
            "amass",
            "whatweb",
            "dirb",
            "hydra",
            "john",
            "hashcat",
            "curl",
            "wget",
            "dig",
            "whois",
            "traceroute",
            "ping",
            "netcat",
            "openssl",
            "testssl",
            "sslscan",
            "masscan",
        ],
    },
    "reporting": {
        "format": "html",
        "auto_save": True,
        "include_raw_output": True,
    },
    "ui": {
        "theme": "dark",
        "show_banner": True,
        "verbose": False,
    },
}


@dataclass
class AIConfig:
    provider: str = "openai"
    model: str = "gpt-4o"
    api_key: str = ""
    base_url: str = ""
    temperature: float = 0.2
    max_tokens: int = 4096


@dataclass
class AgentConfig:
    auto_confirm: bool = False
    max_steps: int = 50
    timeout: int = 300
    safe_mode: bool = True
    allowed_tools: List[str] = field(default_factory=lambda: DEFAULT_CONFIG["agent"]["allowed_tools"])


@dataclass
class ReportingConfig:
    format: str = "html"
    auto_save: bool = True
    include_raw_output: bool = True


@dataclass
class UIConfig:
    theme: str = "dark"
    show_banner: bool = True
    verbose: bool = False


@dataclass
class HackBotConfig:
    ai: AIConfig = field(default_factory=AIConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    ui: UIConfig = field(default_factory=UIConfig)


def load_config() -> HackBotConfig:
    """Load configuration from disk, env vars, and defaults."""
    ensure_dirs()
    raw: Dict[str, Any] = {}

    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            raw = yaml.safe_load(f) or {}

    # Merge with defaults
    merged = _deep_merge(DEFAULT_CONFIG, raw)

    # Env-var overrides
    if os.environ.get("HACKBOT_API_KEY"):
        merged["ai"]["api_key"] = os.environ["HACKBOT_API_KEY"]
    if os.environ.get("HACKBOT_MODEL"):
        merged["ai"]["model"] = os.environ["HACKBOT_MODEL"]
    if os.environ.get("HACKBOT_PROVIDER"):
        merged["ai"]["provider"] = os.environ["HACKBOT_PROVIDER"]
    if os.environ.get("HACKBOT_BASE_URL"):
        merged["ai"]["base_url"] = os.environ["HACKBOT_BASE_URL"]
    if os.environ.get("OPENAI_API_KEY") and not merged["ai"]["api_key"]:
        merged["ai"]["api_key"] = os.environ["OPENAI_API_KEY"]
    if os.environ.get("ANTHROPIC_API_KEY") and not merged["ai"]["api_key"]:
        merged["ai"]["api_key"] = os.environ["ANTHROPIC_API_KEY"]
        if merged["ai"]["provider"] == "openai":
            merged["ai"]["provider"] = "anthropic"
            merged["ai"]["model"] = "claude-sonnet-4-20250514"
    if os.environ.get("GEMINI_API_KEY") and not merged["ai"]["api_key"]:
        merged["ai"]["api_key"] = os.environ["GEMINI_API_KEY"]
        if merged["ai"]["provider"] == "openai":
            merged["ai"]["provider"] = "gemini"
            merged["ai"]["model"] = "gemini-2.5-pro"
    if os.environ.get("GOOGLE_API_KEY") and not merged["ai"]["api_key"]:
        merged["ai"]["api_key"] = os.environ["GOOGLE_API_KEY"]
        if merged["ai"]["provider"] == "openai":
            merged["ai"]["provider"] = "gemini"
            merged["ai"]["model"] = "gemini-2.5-pro"
    if os.environ.get("GROQ_API_KEY") and not merged["ai"]["api_key"]:
        merged["ai"]["api_key"] = os.environ["GROQ_API_KEY"]
        if merged["ai"]["provider"] == "openai":
            merged["ai"]["provider"] = "groq"
            merged["ai"]["model"] = "llama-3.3-70b-versatile"
    if os.environ.get("MISTRAL_API_KEY") and not merged["ai"]["api_key"]:
        merged["ai"]["api_key"] = os.environ["MISTRAL_API_KEY"]
        if merged["ai"]["provider"] == "openai":
            merged["ai"]["provider"] = "mistral"
            merged["ai"]["model"] = "mistral-large-latest"
    if os.environ.get("DEEPSEEK_API_KEY") and not merged["ai"]["api_key"]:
        merged["ai"]["api_key"] = os.environ["DEEPSEEK_API_KEY"]
        if merged["ai"]["provider"] == "openai":
            merged["ai"]["provider"] = "deepseek"
            merged["ai"]["model"] = "deepseek-chat"
    if os.environ.get("TOGETHER_API_KEY") and not merged["ai"]["api_key"]:
        merged["ai"]["api_key"] = os.environ["TOGETHER_API_KEY"]
        if merged["ai"]["provider"] == "openai":
            merged["ai"]["provider"] = "together"
            merged["ai"]["model"] = "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo"
    if os.environ.get("OPENROUTER_API_KEY") and not merged["ai"]["api_key"]:
        merged["ai"]["api_key"] = os.environ["OPENROUTER_API_KEY"]
        if merged["ai"]["provider"] == "openai":
            merged["ai"]["provider"] = "openrouter"
            merged["ai"]["model"] = "anthropic/claude-sonnet-4-20250514"

    cfg = HackBotConfig(
        ai=AIConfig(**merged.get("ai", {})),
        agent=AgentConfig(**merged.get("agent", {})),
        reporting=ReportingConfig(**merged.get("reporting", {})),
        ui=UIConfig(**merged.get("ui", {})),
    )
    return cfg


def save_config(cfg: HackBotConfig) -> None:
    """Persist current configuration to disk."""
    ensure_dirs()
    data = {
        "ai": {
            "provider": cfg.ai.provider,
            "model": cfg.ai.model,
            "api_key": cfg.ai.api_key,
            "base_url": cfg.ai.base_url,
            "temperature": cfg.ai.temperature,
            "max_tokens": cfg.ai.max_tokens,
        },
        "agent": {
            "auto_confirm": cfg.agent.auto_confirm,
            "max_steps": cfg.agent.max_steps,
            "timeout": cfg.agent.timeout,
            "safe_mode": cfg.agent.safe_mode,
            "allowed_tools": cfg.agent.allowed_tools,
        },
        "reporting": {
            "format": cfg.reporting.format,
            "auto_save": cfg.reporting.auto_save,
            "include_raw_output": cfg.reporting.include_raw_output,
        },
        "ui": {
            "theme": cfg.ui.theme,
            "show_banner": cfg.ui.show_banner,
            "verbose": cfg.ui.verbose,
        },
    }
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    result = base.copy()
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


# ── tool detection ───────────────────────────────────────────────────────────

def detect_platform() -> Dict[str, str]:
    """Return platform information."""
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }


def detect_tools(allowed: List[str]) -> Dict[str, Optional[str]]:
    """Detect which security tools are installed."""
    found: Dict[str, Optional[str]] = {}
    for tool in allowed:
        path = shutil.which(tool)
        found[tool] = path
    return found
