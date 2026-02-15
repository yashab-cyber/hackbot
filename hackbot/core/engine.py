"""
HackBot AI Engine
=================
Manages LLM interactions with support for multiple providers (OpenAI, Ollama, etc.).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from openai import OpenAI

from hackbot.config import AIConfig

# ── Provider Registry ────────────────────────────────────────────────────────

PROVIDERS = {
    "openai": {
        "name": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "env_key": "OPENAI_API_KEY",
        "models": [
            {"id": "gpt-5.2", "name": "GPT-5.2 (latest flagship)", "ctx": 128000},
            {"id": "gpt-5.1", "name": "GPT-5.1 (reasoning + code)", "ctx": 128000},
            {"id": "gpt-5.2-codex", "name": "GPT-5.2 Codex (coding)", "ctx": 128000},
            {"id": "gpt-5.2-codex-mini", "name": "GPT-5.2 Codex Mini (fast coding)", "ctx": 128000},
            {"id": "gpt-4o", "name": "GPT-4o (recommended)", "ctx": 128000},
            {"id": "gpt-4o-mini", "name": "GPT-4o Mini (fast/cheap)", "ctx": 128000},
            {"id": "gpt-4-turbo", "name": "GPT-4 Turbo", "ctx": 128000},
            {"id": "o3-mini", "name": "o3-mini (reasoning)", "ctx": 200000},
            {"id": "o1", "name": "o1 (reasoning)", "ctx": 200000},
        ],
    },
    "anthropic": {
        "name": "Anthropic (Claude)",
        "base_url": "https://api.anthropic.com/v1",
        "env_key": "ANTHROPIC_API_KEY",
        "models": [
            {"id": "claude-opus-4.6", "name": "Claude Opus 4.6 (latest)", "ctx": 200000},
            {"id": "claude-opus-4.5", "name": "Claude Opus 4.5 (research + code)", "ctx": 200000},
            {"id": "claude-sonnet-4-20250514", "name": "Claude Sonnet 4 (recommended)", "ctx": 200000},
            {"id": "claude-opus-4-20250514", "name": "Claude Opus 4", "ctx": 200000},
            {"id": "claude-3-7-sonnet-20250219", "name": "Claude 3.7 Sonnet", "ctx": 200000},
            {"id": "claude-3-5-haiku-20241022", "name": "Claude 3.5 Haiku (fast)", "ctx": 200000},
        ],
    },
    "gemini": {
        "name": "Google Gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "env_key": "GEMINI_API_KEY",
        "models": [
            {"id": "gemini-3-pro", "name": "Gemini 3 Pro (latest)", "ctx": 1000000},
            {"id": "gemini-3-flash-preview", "name": "Gemini 3 Flash Preview (fast)", "ctx": 1000000},
            {"id": "gemini-2.5-pro", "name": "Gemini 2.5 Pro (recommended)", "ctx": 1000000},
            {"id": "gemini-2.5-flash", "name": "Gemini 2.5 Flash", "ctx": 1000000},
            {"id": "gemini-2.0-flash", "name": "Gemini 2.0 Flash", "ctx": 1000000},
        ],
    },
    "groq": {
        "name": "Groq (Ultra-fast)",
        "base_url": "https://api.groq.com/openai/v1",
        "env_key": "GROQ_API_KEY",
        "models": [
            {"id": "llama-3.3-70b-versatile", "name": "LLaMA 3.3 70B (recommended)", "ctx": 128000},
            {"id": "llama-3.1-405b-reasoning", "name": "LLaMA 3.1 405B (reasoning)", "ctx": 131072},
            {"id": "llama-3.1-8b-instant", "name": "LLaMA 3.1 8B (fast)", "ctx": 128000},
            {"id": "mixtral-8x7b-32768", "name": "Mixtral 8x7B", "ctx": 32768},
            {"id": "gemma2-9b-it", "name": "Gemma 2 9B", "ctx": 8192},
        ],
    },
    "mistral": {
        "name": "Mistral AI",
        "base_url": "https://api.mistral.ai/v1",
        "env_key": "MISTRAL_API_KEY",
        "models": [
            {"id": "mistral-large-2", "name": "Mistral Large 2 (latest)", "ctx": 128000},
            {"id": "mistral-large-latest", "name": "Mistral Large (recommended)", "ctx": 128000},
            {"id": "mistral-small-latest", "name": "Mistral Small (fast)", "ctx": 32000},
            {"id": "codestral-latest", "name": "Codestral (code)", "ctx": 32000},
            {"id": "open-mistral-nemo", "name": "Mistral Nemo (open)", "ctx": 128000},
        ],
    },
    "deepseek": {
        "name": "DeepSeek",
        "base_url": "https://api.deepseek.com/v1",
        "env_key": "DEEPSEEK_API_KEY",
        "models": [
            {"id": "deepseek-chat", "name": "DeepSeek V3 (recommended)", "ctx": 64000},
            {"id": "deepseek-reasoner", "name": "DeepSeek R1 (reasoning)", "ctx": 64000},
        ],
    },
    "together": {
        "name": "Together AI",
        "base_url": "https://api.together.xyz/v1",
        "env_key": "TOGETHER_API_KEY",
        "models": [
            {"id": "meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo", "name": "LLaMA 3.1 405B Turbo", "ctx": 131072},
            {"id": "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo", "name": "LLaMA 3.1 70B Turbo", "ctx": 131072},
            {"id": "Qwen/Qwen2.5-72B-Instruct-Turbo", "name": "Qwen 2.5 72B", "ctx": 32768},
            {"id": "mistralai/Mistral-Large-2-Instruct", "name": "Mistral Large 2", "ctx": 128000},
            {"id": "deepseek-ai/DeepSeek-R1", "name": "DeepSeek R1", "ctx": 64000},
        ],
    },
    "openrouter": {
        "name": "OpenRouter (Multi-provider)",
        "base_url": "https://openrouter.ai/api/v1",
        "env_key": "OPENROUTER_API_KEY",
        "models": [
            {"id": "openai/gpt-5.2", "name": "GPT-5.2", "ctx": 128000},
            {"id": "openai/gpt-5.1", "name": "GPT-5.1", "ctx": 128000},
            {"id": "anthropic/claude-opus-4.6", "name": "Claude Opus 4.6", "ctx": 200000},
            {"id": "anthropic/claude-opus-4.5", "name": "Claude Opus 4.5", "ctx": 200000},
            {"id": "google/gemini-3-pro", "name": "Gemini 3 Pro", "ctx": 1000000},
            {"id": "openai/gpt-4o", "name": "GPT-4o", "ctx": 128000},
            {"id": "meta-llama/llama-3.1-405b-instruct", "name": "LLaMA 3.1 405B", "ctx": 131072},
            {"id": "deepseek/deepseek-r1", "name": "DeepSeek R1", "ctx": 64000},
            {"id": "mistralai/mistral-large-2", "name": "Mistral Large 2", "ctx": 128000},
        ],
    },
    "ollama": {
        "name": "Ollama (Local)",
        "base_url": "http://localhost:11434/v1",
        "env_key": "",
        "models": [
            {"id": "llama3.1:405b", "name": "LLaMA 3.1 405B", "ctx": 131072},
            {"id": "llama3.1:70b", "name": "LLaMA 3.1 70B", "ctx": 128000},
            {"id": "llama3.2", "name": "LLaMA 3.2 (default)", "ctx": 128000},
            {"id": "mistral", "name": "Mistral 7B", "ctx": 32000},
            {"id": "mixtral", "name": "Mixtral 8x7B", "ctx": 32000},
            {"id": "vicuna:13b", "name": "Vicuna 13B", "ctx": 16384},
            {"id": "deepseek-r1:14b", "name": "DeepSeek R1 14B", "ctx": 64000},
            {"id": "qwen2.5:14b", "name": "Qwen 2.5 14B", "ctx": 32768},
            {"id": "glm4:9b", "name": "GLM-4 9B", "ctx": 128000},
        ],
    },
    "local": {
        "name": "Local / Custom Endpoint",
        "base_url": "http://localhost:8080/v1",
        "env_key": "",
        "models": [
            {"id": "default", "name": "Default model on server", "ctx": 4096},
        ],
    },
}

# ── System Prompts ───────────────────────────────────────────────────────────

SYSTEM_PROMPT_CHAT = """You are HackBot, an expert cybersecurity AI assistant.
You have deep knowledge of:
- Penetration testing methodologies (OWASP, PTES, OSSTMM)
- Network security, web application security, mobile security
- Vulnerability assessment and exploitation techniques
- Security tools: nmap, Burp Suite, Metasploit, sqlmap, nikto, etc.
- Reverse engineering and malware analysis
- Cryptography and secure coding practices
- Incident response and digital forensics
- Cloud security (AWS, Azure, GCP)
- Active Directory attacks and defense
- Social engineering and phishing
- CTF challenges and bug bounty hunting

You provide detailed, accurate, and actionable security guidance.
Always emphasize ethical hacking and responsible disclosure.
Format responses with clear sections, code blocks, and examples when appropriate."""

SYSTEM_PROMPT_AGENT = """You are HackBot Agent, an autonomous cybersecurity testing AI.
You can execute real security tools and commands to perform penetration testing.

IMPORTANT RULES:
1. You MUST only test targets you have explicit authorization to test
2. Always start with reconnaissance before active testing
3. Follow a structured methodology: Recon → Scanning → Enumeration → Exploitation → Post-Exploitation → Reporting
4. Explain what each command does before executing it
5. Analyze output thoroughly and determine next steps intelligently
6. Document all findings with severity ratings (Critical/High/Medium/Low/Info)
7. If safe_mode is enabled, avoid destructive or highly aggressive scans

BUILT-IN INTELLIGENCE:
- CVE Lookup: After running nmap or service detection, you can ask the user to run /cve with service names to auto-map discovered services to known CVEs from the NVD database.
- OSINT Module: Before active scanning, recommend running /osint against the target domain for passive reconnaissance (subdomains, DNS records, WHOIS, tech stack fingerprinting).
- After nmap/masscan scans, recommend /topology to visualize the network map.
- Compliance Mapping: After collecting findings, recommend /compliance to automatically map them to PCI DSS, NIST 800-53, OWASP Top 10, and ISO 27001 controls. You can also filter by framework, e.g. /compliance pci nist.
- Diff Reports: If this is a follow-up assessment, recommend /diff to compare with a previous session and see which vulnerabilities are new, fixed, or persistent.
- Multi-Target Campaigns: If you see "CAMPAIGN CONTEXT" in the assessment context, you are part of a coordinated multi-target campaign. Use intelligence from previously assessed targets to guide your testing — look for similar vulnerabilities, shared infrastructure, lateral movement opportunities, and common misconfigurations across the campaign scope.
- Custom Plugins: Users may have registered custom plugin tools. If custom plugins are listed in the assessment context, you can call them using:
  ```json
  {"action": "execute", "tool": "hackbot-plugin", "command": "hackbot-plugin <plugin_name> --arg1 value1 --arg2 value2", "explanation": "<why>"}
  ```

When you need to run a command, respond with a JSON action block:
```json
{"action": "execute", "tool": "<tool_name>", "command": "<full_command>", "explanation": "<why>"}
```

When you want to report a finding:
```json
{"action": "finding", "title": "<title>", "severity": "<Critical|High|Medium|Low|Info>", "description": "<details>", "evidence": "<output>", "recommendation": "<fix>"}
```

When you are done with the assessment:
```json
{"action": "complete", "summary": "<assessment_summary>"}
```

When you want to generate a professional PDF report (at the end of the assessment, or when the user asks for a report):
```json
{"action": "generate_report", "format": "pdf", "include_compliance": true}
```

You may include multiple action blocks in a single response along with your analysis text."""

SYSTEM_PROMPT_PLAN = """You are HackBot Planner, a cybersecurity assessment planning AI.
You create detailed, structured penetration testing plans and attack strategies.

Your plans should include:
1. Scope definition and rules of engagement
2. Methodology selection (OWASP, PTES, etc.)
3. Phase-by-phase breakdown with specific tools and techniques
4. Risk assessment and contingency plans
5. Timeline estimates
6. Required tools and resources
7. Reporting templates and deliverables

Format plans as structured documents with clear sections and checklists.
Include specific commands and tool configurations where appropriate."""


# ── Message Types ────────────────────────────────────────────────────────────

@dataclass
class Message:
    role: str  # "system" | "user" | "assistant"
    content: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_api(self) -> Dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass
class Conversation:
    messages: List[Message] = field(default_factory=list)
    mode: str = "chat"
    target: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add(self, role: str, content: str, **meta: Any) -> Message:
        msg = Message(role=role, content=content, metadata=meta)
        self.messages.append(msg)
        return msg

    def to_api_messages(self) -> List[Dict[str, str]]:
        return [m.to_api() for m in self.messages]

    def clear(self) -> None:
        system_msgs = [m for m in self.messages if m.role == "system"]
        self.messages = system_msgs


# ── AI Engine ────────────────────────────────────────────────────────────────

class AIEngine:
    """Core AI engine that handles LLM communication."""

    def __init__(self, config: AIConfig):
        self.config = config
        self._client: Optional[OpenAI] = None
        self._setup_client()

    def _setup_client(self) -> None:
        """Initialize the OpenAI-compatible client for any provider."""
        provider = self.config.provider
        preset = PROVIDERS.get(provider, {})
        api_key = self.config.api_key
        base_url = self.config.base_url

        # Use preset base_url if user hasn't overridden
        if not base_url and preset:
            base_url = preset.get("base_url", "")

        kwargs: Dict[str, Any] = {"api_key": api_key or "unused"}

        if base_url:
            kwargs["base_url"] = base_url

        # Provider-specific tweaks
        if provider == "ollama":
            kwargs["api_key"] = api_key or "ollama"
        elif provider == "local":
            kwargs["api_key"] = api_key or "local"

        self._client = OpenAI(**kwargs)

    @property
    def client(self) -> OpenAI:
        if self._client is None:
            self._setup_client()
        return self._client

    def chat(
        self,
        conversation: Conversation,
        stream: bool = True,
        on_token: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Send conversation to LLM and return response."""
        messages = conversation.to_api_messages()

        if stream and on_token:
            return self._stream_chat(messages, on_token)
        else:
            return self._blocking_chat(messages)

    def _blocking_chat(self, messages: List[Dict[str, str]]) -> str:
        response = self.client.chat.completions.create(
            model=self.config.model,
            messages=messages,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
        )
        return response.choices[0].message.content or ""

    def _stream_chat(
        self,
        messages: List[Dict[str, str]],
        on_token: Callable[[str], None],
    ) -> str:
        stream = self.client.chat.completions.create(
            model=self.config.model,
            messages=messages,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            stream=True,
        )
        full_response = []
        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                token = chunk.choices[0].delta.content
                full_response.append(token)
                on_token(token)
        return "".join(full_response)

    def quick_ask(self, prompt: str, system: str = "") -> str:
        """One-shot question without conversation history."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self._blocking_chat(messages)

    def is_configured(self) -> bool:
        """Check if API key is set."""
        return bool(self.config.api_key)


def create_conversation(mode: str, target: str = "") -> Conversation:
    """Create a new conversation with the appropriate system prompt."""
    conv = Conversation(mode=mode, target=target)

    if mode == "chat":
        conv.add("system", SYSTEM_PROMPT_CHAT)
    elif mode == "agent":
        system = SYSTEM_PROMPT_AGENT
        if target:
            system += f"\n\nTarget for this assessment: {target}"
        conv.add("system", system)
    elif mode == "plan":
        conv.add("system", SYSTEM_PROMPT_PLAN)
    else:
        conv.add("system", SYSTEM_PROMPT_CHAT)

    return conv
