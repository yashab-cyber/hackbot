"""
HackBot Telegram Bot Integration
==================================
Full remote control of HackBot via Telegram with QR code authentication.

Features:
  - QR code pairing to link a Telegram user to a HackBot instance
  - All three modes: Chat, Agent, Plan
  - Slash-command parity with the CLI
  - Session persistence across restarts
  - Streaming-style chunked responses for long outputs
  - Inline keyboard navigation for modes, tools, and settings

Usage (CLI)::

    hackbot telegram                     # Start bot (prints QR + link)
    hackbot telegram --token <TOKEN>     # Provide token directly

Usage (REPL)::

    /telegram start                      # Start Telegram bot
    /telegram stop                       # Stop Telegram bot
    /telegram status                     # Show connection status
    /telegram qr                         # Re-display QR code

Environment::

    TELEGRAM_BOT_TOKEN=<your-token>

Setup:
  1. Talk to @BotFather on Telegram → /newbot → get the token
  2. Set the token via env var, config, or --token flag
  3. Run `hackbot telegram` — scan the QR code with your phone
  4. Start chatting with your bot on Telegram!
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import logging
import os
import secrets
import textwrap
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Lazy imports — these are optional dependencies
_TG_AVAILABLE = False
_QR_AVAILABLE = False

try:
    from telegram import (
        Bot,
        InlineKeyboardButton,
        InlineKeyboardMarkup,
        Update,
    )
    from telegram.constants import ChatAction, ParseMode
    from telegram.ext import (
        Application,
        CallbackQueryHandler,
        CommandHandler,
        ContextTypes,
        MessageHandler,
        filters,
    )
    _TG_AVAILABLE = True
except ImportError:
    pass

try:
    import qrcode
    _QR_AVAILABLE = True
except ImportError:
    pass

from hackbot import __version__
from hackbot.config import (
    CONFIG_DIR,
    HackBotConfig,
    detect_platform,
    detect_tools,
    load_config,
    save_config,
)
from hackbot.core.engine import AIEngine, PROVIDERS, SUPPORTED_LANGUAGES
from hackbot.core.cve import CVELookup
from hackbot.core.compliance import ComplianceMapper
from hackbot.core.osint import OSINTEngine
from hackbot.core.remediation import RemediationEngine
from hackbot.core.plugins import get_plugin_manager, ensure_plugins_dir
from hackbot.modes.agent import AgentMode
from hackbot.modes.chat import ChatMode
from hackbot.modes.plan import PlanMode
from hackbot.reporting import ReportGenerator


# ── Constants ────────────────────────────────────────────────────────────────

MAX_TG_MESSAGE_LENGTH = 4096  # Telegram's max message length
PAIR_CODE_EXPIRY = 300  # 5 minutes for QR code pairing
AUTH_FILE = CONFIG_DIR / "telegram_auth.json"


def check_telegram_deps() -> bool:
    """Check if Telegram bot dependencies are available."""
    return _TG_AVAILABLE


def check_qr_deps() -> bool:
    """Check if QR code generation is available."""
    return _QR_AVAILABLE


# ── Authentication / Pairing ─────────────────────────────────────────────────

@dataclass
class PairingState:
    """Manages QR code pairing between device and Telegram user."""
    code: str = ""
    created_at: float = 0.0
    authorized_users: Set[int] = field(default_factory=set)

    def generate_code(self) -> str:
        """Generate a new pairing code."""
        self.code = secrets.token_urlsafe(16)
        self.created_at = time.time()
        return self.code

    def is_expired(self) -> bool:
        return time.time() - self.created_at > PAIR_CODE_EXPIRY

    def verify(self, code: str) -> bool:
        """Verify a pairing code."""
        if self.is_expired():
            return False
        return secrets.compare_digest(self.code, code)

    def authorize(self, user_id: int) -> None:
        self.authorized_users.add(user_id)

    def is_authorized(self, user_id: int) -> bool:
        return user_id in self.authorized_users

    def save(self) -> None:
        """Persist authorized users to disk."""
        AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {"authorized_users": list(self.authorized_users)}
        AUTH_FILE.write_text(json.dumps(data))

    def load(self) -> None:
        """Load authorized users from disk."""
        if AUTH_FILE.exists():
            try:
                data = json.loads(AUTH_FILE.read_text())
                self.authorized_users = set(data.get("authorized_users", []))
            except (json.JSONDecodeError, KeyError):
                pass


def generate_qr_code(bot_username: str, pair_code: str) -> Optional[bytes]:
    """Generate a QR code PNG for Telegram bot pairing.

    The QR code encodes a deep link: https://t.me/<bot>?start=<code>
    """
    if not _QR_AVAILABLE:
        return None

    url = f"https://t.me/{bot_username}?start={pair_code}"
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf.getvalue()


def generate_qr_terminal(bot_username: str, pair_code: str) -> str:
    """Generate an ASCII QR code for terminal display."""
    if not _QR_AVAILABLE:
        return ""

    url = f"https://t.me/{bot_username}?start={pair_code}"
    qr = qrcode.QRCode(version=1, box_size=1, border=2)
    qr.add_data(url)
    qr.make(fit=True)

    # Build ASCII representation
    matrix = qr.get_matrix()
    lines = []
    for row in matrix:
        line = ""
        for cell in row:
            line += "██" if cell else "  "
        lines.append(line)
    return "\n".join(lines)


# ── Per-User Session ─────────────────────────────────────────────────────────

@dataclass
class TelegramUserSession:
    """Per-user HackBot session state."""
    user_id: int
    mode: str = "chat"  # chat | agent | plan
    chat_mode: Optional[ChatMode] = None
    agent_mode: Optional[AgentMode] = None
    plan_mode: Optional[PlanMode] = None
    last_activity: float = field(default_factory=time.time)

    def touch(self) -> None:
        self.last_activity = time.time()


# ── Telegram Message Helpers ─────────────────────────────────────────────────

def _split_message(text: str, max_len: int = MAX_TG_MESSAGE_LENGTH) -> List[str]:
    """Split a long message into Telegram-safe chunks."""
    if len(text) <= max_len:
        return [text]

    chunks = []
    while text:
        if len(text) <= max_len:
            chunks.append(text)
            break

        # Try to split at a newline
        split_at = text.rfind("\n", 0, max_len)
        if split_at < max_len // 2:
            # No good newline break — split at max_len
            split_at = max_len

        chunks.append(text[:split_at])
        text = text[split_at:].lstrip("\n")

    return chunks


def _escape_md(text: str) -> str:
    """Escape special Markdown characters for Telegram MarkdownV2."""
    # For simplicity, we use HTML parse mode instead of MarkdownV2
    # This function is kept for reference but we primarily use HTML
    special = r"_*[]()~`>#+-=|{}.!"
    for ch in special:
        text = text.replace(ch, f"\\{ch}")
    return text


def _format_html(text: str) -> str:
    """Convert HackBot output to Telegram HTML format.

    Handles code blocks, bold, etc. while escaping HTML entities.
    """
    import html as html_mod

    # First escape HTML
    escaped = html_mod.escape(text)

    # Restore code blocks: ```lang\ncode\n``` → <pre><code>code</code></pre>
    import re
    escaped = re.sub(
        r"```\w*\n(.*?)```",
        r"<pre><code>\1</code></pre>",
        escaped,
        flags=re.DOTALL,
    )

    # Inline code: `code` → <code>code</code>
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)

    # Bold: **text** → <b>text</b>
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped)

    # Italic: *text* → <i>text</i> (but not inside <b>)
    escaped = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<i>\1</i>", escaped)

    return escaped


# ── Main Bot Class ───────────────────────────────────────────────────────────

class HackBotTelegram:
    """
    Full HackBot Telegram bot integration.

    Provides:
    - QR code pairing for authentication
    - Chat, Agent, and Plan modes via Telegram
    - All major slash commands
    - Session persistence per user
    - Chunked output for long responses
    """

    def __init__(self, config: HackBotConfig, token: str = ""):
        if not _TG_AVAILABLE:
            raise ImportError(
                "Telegram bot dependencies not installed. Install with:\n"
                "  pip install 'python-telegram-bot>=21.0' qrcode[pil]"
            )

        self.config = config
        self.token = token or os.environ.get("TELEGRAM_BOT_TOKEN", "") or config.ai.api_key  # fallback
        if not self.token or self.token == config.ai.api_key:
            self.token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.engine = AIEngine(config.ai)
        self.sessions: Dict[int, TelegramUserSession] = {}
        self.pairing = PairingState()
        self.pairing.load()
        self._app: Optional[Application] = None
        self._running = False
        self._bot_username = ""
        self._thread: Optional[threading.Thread] = None

    # ── Session Management ───────────────────────────────────────────────

    def _get_session(self, user_id: int) -> TelegramUserSession:
        """Get or create a user session."""
        if user_id not in self.sessions:
            session = TelegramUserSession(user_id=user_id)
            session.chat_mode = ChatMode(self.engine, self.config)
            session.plan_mode = PlanMode(self.engine, self.config)
            self.sessions[user_id] = session
        session = self.sessions[user_id]
        session.touch()
        return session

    def _reset_session(self, user_id: int) -> None:
        """Reset a user's session."""
        session = self._get_session(user_id)
        session.chat_mode = ChatMode(self.engine, self.config)
        session.plan_mode = PlanMode(self.engine, self.config)
        session.agent_mode = None
        session.mode = "chat"

    # ── Auth Decorator ───────────────────────────────────────────────────

    def _require_auth(self, handler):
        """Decorator: require Telegram user to be authorized."""
        async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
            user_id = update.effective_user.id
            if not self.pairing.is_authorized(user_id):
                await update.message.reply_text(
                    "🔒 <b>Not authorized.</b>\n\n"
                    "Scan the QR code displayed on your HackBot terminal, "
                    "or send the pairing code with:\n"
                    "<code>/start &lt;pairing_code&gt;</code>",
                    parse_mode=ParseMode.HTML,
                )
                return
            return await handler(update, context)
        return wrapper

    # ── Command Handlers ─────────────────────────────────────────────────

    async def _cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /start — pairing and welcome."""
        user_id = update.effective_user.id
        args = context.args

        # Check if this is a pairing attempt
        if args and len(args) == 1:
            code = args[0]
            if self.pairing.verify(code):
                self.pairing.authorize(user_id)
                self.pairing.save()
                await update.message.reply_text(
                    f"✅ <b>Paired successfully!</b>\n\n"
                    f"Welcome to HackBot v{__version__}, "
                    f"{update.effective_user.first_name}!\n\n"
                    f"You now have full control of your HackBot instance.\n"
                    f"Type /help to see available commands.",
                    parse_mode=ParseMode.HTML,
                )
                logger.info("Telegram user %s authorized via QR pairing", user_id)
                return
            else:
                await update.message.reply_text(
                    "❌ Invalid or expired pairing code.\n"
                    "Please scan the QR code again from your HackBot terminal.",
                )
                return

        # Already authorized → show welcome
        if self.pairing.is_authorized(user_id):
            keyboard = [
                [
                    InlineKeyboardButton("💬 Chat", callback_data="mode_chat"),
                    InlineKeyboardButton("🤖 Agent", callback_data="mode_agent"),
                    InlineKeyboardButton("📋 Plan", callback_data="mode_plan"),
                ],
                [
                    InlineKeyboardButton("⚙️ Settings", callback_data="settings"),
                    InlineKeyboardButton("ℹ️ Help", callback_data="help"),
                ],
            ]
            session = self._get_session(user_id)
            await update.message.reply_text(
                f"🤖 <b>HackBot v{__version__}</b>\n\n"
                f"Current mode: <b>{session.mode.upper()}</b>\n"
                f"Provider: <b>{self.config.ai.provider}/{self.config.ai.model}</b>\n"
                f"Language: <b>{self.config.ui.language}</b>\n\n"
                f"Send any message to chat, or use the buttons below.",
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup(keyboard),
            )
        else:
            await update.message.reply_text(
                "🔒 <b>HackBot — Authentication Required</b>\n\n"
                "To connect, scan the QR code shown on your HackBot terminal, "
                "or send:\n<code>/start &lt;pairing_code&gt;</code>",
                parse_mode=ParseMode.HTML,
            )

    async def _cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Show help."""
        help_text = (
            "🤖 <b>HackBot — Telegram Commands</b>\n\n"
            "<b>Modes:</b>\n"
            "/chat — Switch to Chat mode\n"
            "/agent &lt;target&gt; — Start Agent mode\n"
            "/plan &lt;target&gt; — Generate pentest plan\n\n"
            "<b>Agent:</b>\n"
            "/step — Execute next agent step\n"
            "/findings — Show current findings\n"
            "/stop — Stop current assessment\n\n"
            "<b>Intelligence:</b>\n"
            "/cve &lt;query&gt; — CVE / exploit lookup\n"
            "/osint &lt;domain&gt; — OSINT scan\n"
            "/compliance — Map findings to frameworks\n\n"
            "<b>Settings:</b>\n"
            "/model &lt;name&gt; — Switch AI model\n"
            "/provider &lt;name&gt; — Switch AI provider\n"
            "/language &lt;lang&gt; — Set response language\n"
            "/config — Show current config\n\n"
            "<b>Session:</b>\n"
            "/reset — Reset conversation\n"
            "/export — Export report\n"
            "/version — Show version\n"
            "/status — Show connection status\n\n"
            "<i>Or just type any message to chat!</i>"
        )
        await update.message.reply_text(help_text, parse_mode=ParseMode.HTML)

    async def _cmd_chat(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Switch to chat mode."""
        session = self._get_session(update.effective_user.id)
        session.mode = "chat"
        await update.message.reply_text("💬 Switched to <b>Chat Mode</b>", parse_mode=ParseMode.HTML)

    async def _cmd_agent(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Start agent mode with a target."""
        session = self._get_session(update.effective_user.id)
        target = " ".join(context.args) if context.args else ""

        if not target:
            await update.message.reply_text(
                "Usage: /agent &lt;target&gt;\n"
                "Example: <code>/agent 192.168.1.1</code>\n"
                "Example: <code>/agent example.com</code>",
                parse_mode=ParseMode.HTML,
            )
            return

        if not self.engine.is_configured():
            await update.message.reply_text("❌ API key not configured. Use /config to check.")
            return

        session.mode = "agent"
        session.agent_mode = AgentMode(
            engine=self.engine,
            config=self.config,
        )

        await update.message.reply_text(
            f"🤖 <b>Agent Mode — Starting assessment</b>\n"
            f"Target: <code>{target}</code>\n\n"
            f"⏳ Planning assessment...",
            parse_mode=ParseMode.HTML,
        )

        # Run the agent start in a thread to avoid blocking
        loop = asyncio.get_event_loop()
        try:
            response = await loop.run_in_executor(
                None, lambda: session.agent_mode.start(target)
            )
            for chunk in _split_message(response):
                await update.message.reply_text(
                    _format_html(chunk), parse_mode=ParseMode.HTML
                )
        except Exception as e:
            await update.message.reply_text(f"❌ Agent error: {e}")

    async def _cmd_step(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Execute next agent step."""
        session = self._get_session(update.effective_user.id)

        if session.mode != "agent" or not session.agent_mode or not session.agent_mode.is_running:
            await update.message.reply_text(
                "No active assessment. Start one with:\n<code>/agent &lt;target&gt;</code>",
                parse_mode=ParseMode.HTML,
            )
            return

        user_input = " ".join(context.args) if context.args else ""

        await update.message.chat.send_action(ChatAction.TYPING)
        loop = asyncio.get_event_loop()
        try:
            response, is_complete = await loop.run_in_executor(
                None, lambda: session.agent_mode.step(user_input)
            )
            for chunk in _split_message(response):
                await update.message.reply_text(
                    _format_html(chunk), parse_mode=ParseMode.HTML
                )
            if is_complete:
                await update.message.reply_text(
                    "✅ <b>Assessment complete!</b>\nUse /findings to view results, /export for report.",
                    parse_mode=ParseMode.HTML,
                )
        except Exception as e:
            await update.message.reply_text(f"❌ Step error: {e}")

    async def _cmd_findings(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Show agent findings."""
        session = self._get_session(update.effective_user.id)
        if not session.agent_mode or not session.agent_mode.findings:
            await update.message.reply_text("No findings yet.")
            return

        lines = [f"🔍 <b>Findings ({len(session.agent_mode.findings)})</b>\n"]
        severity_icons = {
            "Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Info": "⚪"
        }
        for i, f in enumerate(session.agent_mode.findings, 1):
            icon = severity_icons.get(f.severity.value, "•")
            lines.append(f"{icon} <b>#{i} {f.title}</b> [{f.severity.value}]")
            if f.description:
                desc = f.description[:150] + "..." if len(f.description) > 150 else f.description
                lines.append(f"   {desc}")
            lines.append("")

        text = "\n".join(lines)
        for chunk in _split_message(text):
            await update.message.reply_text(chunk, parse_mode=ParseMode.HTML)

    async def _cmd_stop(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Stop agent assessment."""
        session = self._get_session(update.effective_user.id)
        if session.agent_mode and session.agent_mode.is_running:
            session.agent_mode.is_running = False
            count = len(session.agent_mode.findings)
            await update.message.reply_text(
                f"🛑 Assessment stopped. {count} findings collected.\n"
                f"Use /findings to view, /export for report.",
            )
        else:
            await update.message.reply_text("No active assessment to stop.")

    async def _cmd_plan(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Generate a pentest plan."""
        session = self._get_session(update.effective_user.id)
        target = " ".join(context.args) if context.args else ""

        if not target:
            await update.message.reply_text(
                "Usage: /plan &lt;target&gt;\n"
                "Example: <code>/plan example.com web_pentest</code>\n\n"
                "Templates: web_pentest, network_pentest, api_pentest, "
                "cloud_audit, ad_pentest, wireless, mobile, bug_bounty",
                parse_mode=ParseMode.HTML,
            )
            return

        if not self.engine.is_configured():
            await update.message.reply_text("❌ API key not configured.")
            return

        session.mode = "plan"

        # Parse target and optional plan type
        parts = target.split()
        plan_target = parts[0]
        plan_type = parts[1] if len(parts) > 1 else "web_pentest"

        await update.message.chat.send_action(ChatAction.TYPING)
        loop = asyncio.get_event_loop()
        try:
            response = await loop.run_in_executor(
                None, lambda: session.plan_mode.create_plan(plan_target, plan_type)
            )
            for chunk in _split_message(response):
                await update.message.reply_text(
                    _format_html(chunk), parse_mode=ParseMode.HTML
                )
        except Exception as e:
            await update.message.reply_text(f"❌ Plan error: {e}")

    async def _cmd_cve(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """CVE lookup."""
        query = " ".join(context.args) if context.args else ""
        if not query:
            await update.message.reply_text(
                "Usage:\n"
                "<code>/cve CVE-2021-44228</code> — Lookup by ID\n"
                "<code>/cve Apache 2.4.49</code> — Search by keyword",
                parse_mode=ParseMode.HTML,
            )
            return

        await update.message.chat.send_action(ChatAction.TYPING)
        cve_engine = CVELookup()

        loop = asyncio.get_event_loop()
        try:
            if query.strip().upper().startswith("CVE-"):
                entry = await loop.run_in_executor(None, lambda: cve_engine.lookup_cve(query.strip()))
                if entry:
                    report = CVELookup.format_cve_report([entry], title=f"CVE: {entry.cve_id}")
                    for chunk in _split_message(report):
                        await update.message.reply_text(
                            _format_html(chunk), parse_mode=ParseMode.HTML
                        )
                else:
                    await update.message.reply_text(f"CVE not found: {query.strip()}")
            else:
                cves = await loop.run_in_executor(
                    None, lambda: cve_engine.search_cve(query, max_results=10)
                )
                report = CVELookup.format_cve_report(cves, title=f"CVE Search: {query}")
                for chunk in _split_message(report):
                    await update.message.reply_text(
                        _format_html(chunk), parse_mode=ParseMode.HTML
                    )
        except Exception as e:
            await update.message.reply_text(f"❌ CVE lookup error: {e}")

    async def _cmd_osint(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """OSINT scan."""
        domain = " ".join(context.args) if context.args else ""
        if not domain:
            await update.message.reply_text(
                "Usage: <code>/osint example.com</code>",
                parse_mode=ParseMode.HTML,
            )
            return

        await update.message.chat.send_action(ChatAction.TYPING)
        osint = OSINTEngine()

        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, lambda: osint.full_scan(domain))
            report = osint.format_report(result)
            for chunk in _split_message(report):
                await update.message.reply_text(
                    _format_html(chunk), parse_mode=ParseMode.HTML
                )
        except Exception as e:
            await update.message.reply_text(f"❌ OSINT error: {e}")

    async def _cmd_compliance(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Map findings to compliance frameworks."""
        session = self._get_session(update.effective_user.id)
        if not session.agent_mode or not session.agent_mode.findings:
            await update.message.reply_text("No findings to map. Run an agent assessment first.")
            return

        findings = [f.to_dict() for f in session.agent_mode.findings]
        mapper = ComplianceMapper()

        loop = asyncio.get_event_loop()
        try:
            mappings = await loop.run_in_executor(
                None, lambda: mapper.map_findings(findings)
            )
            report = mapper.format_report(mappings)
            for chunk in _split_message(report):
                await update.message.reply_text(
                    _format_html(chunk), parse_mode=ParseMode.HTML
                )
        except Exception as e:
            await update.message.reply_text(f"❌ Compliance error: {e}")

    async def _cmd_model(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Switch AI model."""
        model = " ".join(context.args) if context.args else ""
        if not model:
            # List models for current provider
            preset = PROVIDERS.get(self.config.ai.provider, {})
            models = preset.get("models", [])
            if models:
                lines = [f"<b>Models for {self.config.ai.provider}:</b>\n"]
                for m in models:
                    current = " ◀" if m["id"] == self.config.ai.model else ""
                    lines.append(f"<code>{m['id']}</code> — {m['name']}{current}")
                await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)
            else:
                await update.message.reply_text("No model list available for current provider.")
            return

        self.config.ai.model = model
        self.engine = AIEngine(self.config.ai)
        self._refresh_all_sessions()
        save_config(self.config)
        await update.message.reply_text(
            f"✅ Model set to: <code>{model}</code>", parse_mode=ParseMode.HTML
        )

    async def _cmd_provider(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Switch AI provider."""
        provider = " ".join(context.args).lower() if context.args else ""
        if not provider:
            lines = ["<b>Available providers:</b>\n"]
            for key, p in PROVIDERS.items():
                current = " ◀" if key == self.config.ai.provider else ""
                lines.append(f"<code>{key}</code> — {p['name']}{current}")
            await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)
            return

        if provider not in PROVIDERS:
            await update.message.reply_text(f"❌ Unknown provider: {provider}")
            return

        self.config.ai.provider = provider
        preset = PROVIDERS[provider]
        if preset["models"]:
            self.config.ai.model = preset["models"][0]["id"]
        self.engine = AIEngine(self.config.ai)
        self._refresh_all_sessions()
        save_config(self.config)
        await update.message.reply_text(
            f"✅ Provider: <code>{preset['name']}</code>\n"
            f"Model: <code>{self.config.ai.model}</code>",
            parse_mode=ParseMode.HTML,
        )

    async def _cmd_language(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Set response language."""
        lang = " ".join(context.args) if context.args else ""
        if not lang:
            current = self.config.ui.language
            lines = [f"Current: <b>{current}</b>\n\n<b>Available:</b>\n"]
            for name, native in sorted(SUPPORTED_LANGUAGES.items()):
                marker = " ◀" if name == current else ""
                lines.append(f"<code>{name}</code> ({native}){marker}")
            text = "\n".join(lines)
            for chunk in _split_message(text):
                await update.message.reply_text(chunk, parse_mode=ParseMode.HTML)
            return

        # Match language
        matched = None
        for name in SUPPORTED_LANGUAGES:
            if name.lower() == lang.lower():
                matched = name
                break
        if not matched:
            for name in SUPPORTED_LANGUAGES:
                if name.lower().startswith(lang.lower()):
                    matched = name
                    break

        if not matched:
            await update.message.reply_text(f"❌ Unknown language: {lang}\nUse /language to see all options.")
            return

        self.config.ui.language = matched
        save_config(self.config)
        self._refresh_all_sessions()
        native = SUPPORTED_LANGUAGES[matched]
        await update.message.reply_text(
            f"✅ Language set to: <b>{matched}</b> ({native})",
            parse_mode=ParseMode.HTML,
        )

    async def _cmd_config(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Show current configuration."""
        preset = PROVIDERS.get(self.config.ai.provider, {})
        provider_name = preset.get("name", self.config.ai.provider)
        text = (
            f"⚙️ <b>HackBot Configuration</b>\n\n"
            f"<b>Provider:</b> {provider_name}\n"
            f"<b>Model:</b> <code>{self.config.ai.model}</code>\n"
            f"<b>API Key:</b> {'✅ Set' if self.config.ai.api_key else '❌ Not set'}\n"
            f"<b>Language:</b> {self.config.ui.language}\n"
            f"<b>Safe Mode:</b> {'✅' if self.config.agent.safe_mode else '❌'}\n"
            f"<b>Max Steps:</b> {self.config.agent.max_steps}\n"
            f"<b>Temperature:</b> {self.config.ai.temperature}\n"
        )
        await update.message.reply_text(text, parse_mode=ParseMode.HTML)

    async def _cmd_reset(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Reset session."""
        self._reset_session(update.effective_user.id)
        await update.message.reply_text("🔄 Session reset. Fresh start!")

    async def _cmd_export(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Export assessment report."""
        session = self._get_session(update.effective_user.id)
        if not session.agent_mode or not session.agent_mode.findings:
            await update.message.reply_text("No findings to export.")
            return

        findings = [f.to_dict() for f in session.agent_mode.findings]
        tools_used = [s.tool_result.to_dict() for s in session.agent_mode.steps
                      if s.tool_result] if session.agent_mode.steps else []

        reporter = ReportGenerator(report_format="markdown")
        report = reporter.generate(
            target=session.agent_mode.target,
            findings=findings,
            tools_used=tools_used,
        )

        # Send as document
        buf = io.BytesIO(report.encode("utf-8"))
        buf.name = f"hackbot_report_{int(time.time())}.md"
        await update.message.reply_document(
            document=buf,
            caption=f"📊 HackBot Report — {session.agent_mode.target}",
        )

    async def _cmd_version(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Show version."""
        plat = detect_platform()
        await update.message.reply_text(
            f"🤖 <b>HackBot</b> v{__version__}\n"
            f"Developer: Yashab Alam\n"
            f"Platform: {plat['system']} {plat['machine']}\n"
            f"Python: {plat['python']}",
            parse_mode=ParseMode.HTML,
        )

    async def _cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Show bot connection status."""
        session = self._get_session(update.effective_user.id)
        tools = detect_tools(self.config.agent.allowed_tools)
        installed = sum(1 for v in tools.values() if v)
        total = len(tools)

        await update.message.reply_text(
            f"📡 <b>HackBot Status</b>\n\n"
            f"🟢 Bot: Connected\n"
            f"Mode: <b>{session.mode.upper()}</b>\n"
            f"Provider: {self.config.ai.provider}/{self.config.ai.model}\n"
            f"API Key: {'✅' if self.engine.is_configured() else '❌'}\n"
            f"Language: {self.config.ui.language}\n"
            f"Tools: {installed}/{total} installed\n"
            f"Agent: {'🟢 Running' if session.agent_mode and session.agent_mode.is_running else '⚪ Idle'}\n"
            f"Findings: {len(session.agent_mode.findings) if session.agent_mode else 0}",
            parse_mode=ParseMode.HTML,
        )

    # ── Callback Query Handler (inline buttons) ─────────────────────────

    async def _callback_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle inline keyboard button presses."""
        query = update.callback_query
        await query.answer()

        user_id = update.effective_user.id
        if not self.pairing.is_authorized(user_id):
            await query.edit_message_text("🔒 Not authorized.")
            return

        data = query.data
        session = self._get_session(user_id)

        if data == "mode_chat":
            session.mode = "chat"
            await query.edit_message_text("💬 Switched to <b>Chat Mode</b>", parse_mode=ParseMode.HTML)
        elif data == "mode_agent":
            session.mode = "agent"
            await query.edit_message_text(
                "🤖 <b>Agent Mode</b>\nSend /agent &lt;target&gt; to start an assessment.",
                parse_mode=ParseMode.HTML,
            )
        elif data == "mode_plan":
            session.mode = "plan"
            await query.edit_message_text(
                "📋 <b>Plan Mode</b>\nSend /plan &lt;target&gt; to generate a plan.",
                parse_mode=ParseMode.HTML,
            )
        elif data == "settings":
            await query.edit_message_text(
                f"⚙️ <b>Settings</b>\n\n"
                f"Provider: {self.config.ai.provider}\n"
                f"Model: {self.config.ai.model}\n"
                f"Language: {self.config.ui.language}\n\n"
                f"Use /model, /provider, /language to change.",
                parse_mode=ParseMode.HTML,
            )
        elif data == "help":
            await query.edit_message_text(
                "Type /help to see all available commands.",
            )

    # ── Free-Text Message Handler ────────────────────────────────────────

    async def _message_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle regular text messages — route to current mode."""
        user_id = update.effective_user.id
        if not self.pairing.is_authorized(user_id):
            await update.message.reply_text("🔒 Not authorized. Scan the QR code first.")
            return

        session = self._get_session(user_id)
        text = update.message.text.strip()

        if not text:
            return

        if not self.engine.is_configured():
            await update.message.reply_text(
                "❌ API key not configured.\n"
                "Set it with environment variable HACKBOT_API_KEY or in your config file."
            )
            return

        await update.message.chat.send_action(ChatAction.TYPING)
        loop = asyncio.get_event_loop()

        try:
            if session.mode == "chat":
                response = await loop.run_in_executor(
                    None, lambda: session.chat_mode.ask(text, stream=False)
                )
            elif session.mode == "agent":
                if session.agent_mode and session.agent_mode.is_running:
                    response, is_complete = await loop.run_in_executor(
                        None, lambda: session.agent_mode.step(text)
                    )
                    if is_complete:
                        response += "\n\n✅ Assessment complete!"
                else:
                    # No active agent — treat as chat
                    response = await loop.run_in_executor(
                        None, lambda: session.chat_mode.ask(text, stream=False)
                    )
            elif session.mode == "plan":
                response = await loop.run_in_executor(
                    None, lambda: session.plan_mode.ask(text, stream=False)
                )
            else:
                response = await loop.run_in_executor(
                    None, lambda: session.chat_mode.ask(text, stream=False)
                )

            for chunk in _split_message(response):
                await update.message.reply_text(
                    _format_html(chunk), parse_mode=ParseMode.HTML
                )
        except Exception as e:
            logger.error("Message handler error: %s", e)
            await update.message.reply_text(f"❌ Error: {e}")

    # ── Engine/Session Refresh ───────────────────────────────────────────

    def _refresh_all_sessions(self) -> None:
        """Rebuild engine and all user sessions after config change."""
        self.engine = AIEngine(self.config.ai)
        for user_id, session in self.sessions.items():
            session.chat_mode = ChatMode(self.engine, self.config)
            session.plan_mode = PlanMode(self.engine, self.config)
            if session.agent_mode:
                session.agent_mode.engine = self.engine

    # ── Bot Lifecycle ────────────────────────────────────────────────────

    def build_app(self) -> Application:
        """Build the Telegram Application with all handlers."""
        builder = Application.builder().token(self.token)
        application = builder.build()

        # Auth-wrapped handlers
        auth = self._require_auth

        application.add_handler(CommandHandler("start", self._cmd_start))
        application.add_handler(CommandHandler("help", auth(self._cmd_help)))
        application.add_handler(CommandHandler("chat", auth(self._cmd_chat)))
        application.add_handler(CommandHandler("agent", auth(self._cmd_agent)))
        application.add_handler(CommandHandler("step", auth(self._cmd_step)))
        application.add_handler(CommandHandler("findings", auth(self._cmd_findings)))
        application.add_handler(CommandHandler("stop", auth(self._cmd_stop)))
        application.add_handler(CommandHandler("plan", auth(self._cmd_plan)))
        application.add_handler(CommandHandler("cve", auth(self._cmd_cve)))
        application.add_handler(CommandHandler("osint", auth(self._cmd_osint)))
        application.add_handler(CommandHandler("compliance", auth(self._cmd_compliance)))
        application.add_handler(CommandHandler("model", auth(self._cmd_model)))
        application.add_handler(CommandHandler("provider", auth(self._cmd_provider)))
        application.add_handler(CommandHandler("language", auth(self._cmd_language)))
        application.add_handler(CommandHandler("lang", auth(self._cmd_language)))
        application.add_handler(CommandHandler("config", auth(self._cmd_config)))
        application.add_handler(CommandHandler("reset", auth(self._cmd_reset)))
        application.add_handler(CommandHandler("export", auth(self._cmd_export)))
        application.add_handler(CommandHandler("version", auth(self._cmd_version)))
        application.add_handler(CommandHandler("status", auth(self._cmd_status)))

        application.add_handler(CallbackQueryHandler(self._callback_handler))
        application.add_handler(MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            auth(self._message_handler),
        ))

        self._app = application
        return application

    async def _get_bot_username(self) -> str:
        """Fetch the bot's username."""
        bot = Bot(self.token)
        me = await bot.get_me()
        self._bot_username = me.username
        return me.username

    def get_pairing_info(self) -> Dict[str, Any]:
        """Generate pairing info (QR code, link, code)."""
        code = self.pairing.generate_code()
        qr_bytes = None
        qr_ascii = ""

        if self._bot_username:
            qr_bytes = generate_qr_code(self._bot_username, code)
            qr_ascii = generate_qr_terminal(self._bot_username, code)

        return {
            "code": code,
            "bot_username": self._bot_username,
            "link": f"https://t.me/{self._bot_username}?start={code}" if self._bot_username else "",
            "qr_png": qr_bytes,
            "qr_ascii": qr_ascii,
            "expires_in": PAIR_CODE_EXPIRY,
            "authorized_users": len(self.pairing.authorized_users),
        }

    def run_polling(self) -> None:
        """Run the bot with polling (blocking)."""
        if not self.token:
            raise ValueError(
                "Telegram bot token not set.\n"
                "Set TELEGRAM_BOT_TOKEN env var or pass --token."
            )

        app = self.build_app()

        # Get bot username synchronously before starting
        import asyncio
        loop = asyncio.new_event_loop()
        self._bot_username = loop.run_until_complete(self._get_bot_username())
        loop.close()

        self._running = True
        logger.info("Starting Telegram bot: @%s", self._bot_username)
        app.run_polling(drop_pending_updates=True)

    def start_background(self) -> Dict[str, Any]:
        """Start the bot in a background thread. Returns pairing info."""
        if self._running:
            return {"ok": False, "error": "Bot is already running"}

        if not self.token:
            return {"ok": False, "error": "Telegram bot token not set"}

        # Get bot username
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            self._bot_username = loop.run_until_complete(self._get_bot_username())
        except Exception as e:
            return {"ok": False, "error": f"Invalid bot token: {e}"}
        finally:
            loop.close()

        # Build app
        self.build_app()

        # Start in background thread
        def _run():
            self._running = True
            try:
                self._app.run_polling(drop_pending_updates=True)
            finally:
                self._running = False

        self._thread = threading.Thread(target=_run, daemon=True, name="hackbot-telegram")
        self._thread.start()

        # Generate pairing info
        info = self.get_pairing_info()
        info["ok"] = True
        info["message"] = f"Bot started: @{self._bot_username}"
        return info

    def stop(self) -> Dict[str, str]:
        """Stop the bot."""
        if not self._running:
            return {"ok": False, "message": "Bot is not running"}

        self._running = False
        if self._app:
            try:
                # Signal the application to stop
                self._app.stop_running()
            except Exception:
                pass

        return {"ok": True, "message": "Telegram bot stopped"}

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def bot_username(self) -> str:
        return self._bot_username


# ── Singleton ────────────────────────────────────────────────────────────────

_telegram_bot: Optional[HackBotTelegram] = None


def get_telegram_bot(config: Optional[HackBotConfig] = None, token: str = "") -> HackBotTelegram:
    """Get or create the singleton Telegram bot instance."""
    global _telegram_bot
    if _telegram_bot is None:
        if config is None:
            config = load_config()
        _telegram_bot = HackBotTelegram(config, token)
    return _telegram_bot


def reset_telegram_bot() -> None:
    """Reset the singleton."""
    global _telegram_bot
    if _telegram_bot and _telegram_bot.is_running:
        _telegram_bot.stop()
    _telegram_bot = None
