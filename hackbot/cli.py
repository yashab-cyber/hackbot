"""
HackBot CLI
============
Main command-line interface with interactive REPL, multiple modes,
and comprehensive command handling.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Optional

import click
from dotenv import load_dotenv
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory
from rich.live import Live
from rich.markdown import Markdown

from hackbot import __version__
from hackbot.config import (
    CONFIG_DIR,
    HackBotConfig,
    detect_platform,
    detect_tools,
    load_config,
    save_config,
)
from hackbot.core.engine import AIEngine, PROVIDERS
from hackbot.core.cve import CVELookup
from hackbot.core.compliance import ComplianceMapper
from hackbot.core.osint import OSINTEngine
from hackbot.core.diff_report import DiffEngine, list_agent_sessions, load_session_findings
from hackbot.core.pdf_report import PDFReportGenerator, HAS_REPORTLAB
from hackbot.core.plugins import PluginManager, get_plugin_manager, ensure_plugins_dir, PLUGINS_DIR
from hackbot.core.campaigns import (
    Campaign, CampaignManager, CampaignStatus, TargetStatus,
    get_campaign_manager, reset_campaign_manager,
)
from hackbot.core.remediation import RemediationEngine
from hackbot.core.proxy import ProxyEngine, get_proxy_engine, reset_proxy_engine
from hackbot.core.topology import TopologyParser
from hackbot.modes.agent import AgentMode
from hackbot.modes.chat import ChatMode
from hackbot.modes.plan import PlanMode
from hackbot.reporting import ReportGenerator
from hackbot.ui import (
    confirm_action,
    console,
    print_assistant,
    print_error,
    print_finding,
    print_info,
    print_step,
    print_success,
    print_tool_execution,
    print_tool_result,
    print_warning,
    show_banner,
    show_config_status,
    show_help,
    show_mode,
    show_tools_status,
)

load_dotenv()


class HackBotApp:
    """Main HackBot application controller."""

    def __init__(self, config: HackBotConfig):
        self.config = config
        self.engine = AIEngine(config.ai)
        self.mode = "chat"
        self.chat = ChatMode(self.engine, config)
        self.agent: Optional[AgentMode] = None
        self.plan = PlanMode(self.engine, config)
        self.reporter = ReportGenerator(
            include_raw=config.reporting.include_raw_output,
            report_format=config.reporting.format,
        )
        self._start_time = time.time()

    # ── Token streaming callback ─────────────────────────────────────────

    def _on_token(self, token: str) -> None:
        """Handle streaming tokens from AI."""
        console.print(token, end="", highlight=False)

    # ── Agent callbacks ──────────────────────────────────────────────────

    def _on_agent_step(self, step) -> None:
        """Handle agent step events."""
        if step.action == "execute" and step.tool_result:
            r = step.tool_result
            print_tool_result(r.tool, r.success, r.duration, r.output, r.return_code)
        elif step.action == "finding" and step.finding:
            f = step.finding
            print_finding(f.title, f.severity.value, f.description)
        elif step.action == "report":
            print_success(step.description)

    def _on_confirm(self, command: str, reason: str) -> bool:
        """Handle confirmation for risky commands."""
        return confirm_action(command, reason)

    def _on_tool_output(self, output: str) -> None:
        """Handle real-time tool output."""
        pass  # Output is shown via _on_agent_step

    # ── Command Handlers ─────────────────────────────────────────────────

    def handle_input(self, user_input: str) -> bool:
        """
        Process user input. Returns False to quit.
        """
        text = user_input.strip()
        if not text:
            return True

        # Command dispatch
        if text.startswith("/"):
            return self._handle_command(text)
        else:
            return self._handle_message(text)

    def _handle_command(self, text: str) -> bool:
        """Handle slash commands."""
        parts = text.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        commands = {
            "/quit": lambda: False,
            "/exit": lambda: False,
            "/q": lambda: False,
            "/help": lambda: (show_help(), True)[1],
            "/version": lambda: (self._show_version(), True)[1],
            "/donate": lambda: (self._show_donate(), True)[1],
            "/chat": lambda: self._switch_mode("chat"),
            "/agent": lambda: self._start_agent(args),
            "/plan": lambda: self._switch_mode("plan"),
            "/config": lambda: self._show_config(),
            "/tools": lambda: self._show_tools(),
            "/model": lambda: self._set_model(args),
            "/key": lambda: self._set_key(args),
            "/provider": lambda: self._set_provider(args),
            "/models": lambda: self._list_models(args),
            "/providers": lambda: self._list_providers(),
            "/save": lambda: self._save_session(args),
            "/load": lambda: self._load_session(args),
            "/sessions": lambda: self._list_all_sessions(args),
            "/clear": lambda: self._clear(),
            "/reset": lambda: self._reset(),
            "/continue": lambda: self._continue_response(),
            "/run": lambda: self._run_command(args),
            "/step": lambda: self._agent_step(args),
            "/findings": lambda: self._show_findings(),
            "/stop": lambda: self._stop_agent(),
            "/export": lambda: self._export_report(args),
            "/pdf": lambda: self._export_pdf(args),
            "/templates": lambda: self._show_templates(),
            "/checklist": lambda: self._generate_checklist(args),
            "/commands": lambda: self._generate_commands(args),
            "/cve": lambda: self._cve_lookup(args),
            "/osint": lambda: self._osint_scan(args),
            "/topology": lambda: self._show_topology(args),
            "/compliance": lambda: self._compliance_map(args),
            "/diff": lambda: self._diff_report(args),
            "/plugins": lambda: self._show_plugins(args),
            "/campaign": lambda: self._handle_campaign(args),
            "/remediate": lambda: self._generate_remediations(args),
            "/proxy": lambda: self._handle_proxy(args),
        }

        handler = commands.get(cmd)
        if handler:
            result = handler()
            return result if result is not None else True
        else:
            print_error(f"Unknown command: {cmd}. Type /help for available commands.")
            return True

    def _handle_message(self, text: str) -> bool:
        """Handle regular messages based on current mode."""
        if not self.engine.is_configured():
            print_error(
                "API key not configured. Set it with:\n"
                "  /key <your-api-key>\n"
                "  or set HACKBOT_API_KEY environment variable\n"
                "  or set OPENAI_API_KEY environment variable"
            )
            return True

        try:
            if self.mode == "chat":
                self._chat_message(text)
            elif self.mode == "agent":
                self._agent_message(text)
            elif self.mode == "plan":
                self._plan_message(text)
        except KeyboardInterrupt:
            console.print("\n[dim]Interrupted[/]")
        except Exception as e:
            print_error(f"Error: {str(e)}")
            if self.config.ui.verbose:
                console.print_exception()

        return True

    # ── Mode Handlers ────────────────────────────────────────────────────

    def _chat_message(self, text: str) -> None:
        console.print(f"\n[chat]HackBot:[/]")
        response = self.chat.ask(text, stream=True, on_token=self._on_token)
        console.print()  # newline after streaming
        if self.chat.was_truncated:
            print_info("Response may be incomplete. Type /continue to resume.")

    def _agent_message(self, text: str) -> None:
        if not self.agent or not self.agent.is_running:
            print_info("No active assessment. Starting agent with your input as target...")
            self._start_agent(text)
            return

        console.print(f"\n[agent]HackBot Agent:[/]")
        response, is_complete = self.agent.step(text)
        if not self.agent.on_token:
            # Wasn't streamed, print now
            console.print()
            print_assistant(response, "agent")

        if is_complete:
            print_success("Assessment complete!")
            if self.config.reporting.auto_save:
                self._export_report("")
        elif self.agent.was_truncated:
            print_info("Response may be incomplete. Type /continue to resume.")

    def _plan_message(self, text: str) -> None:
        console.print(f"\n[plan]HackBot Planner:[/]")
        response = self.plan.ask(text, on_token=self._on_token)
        console.print()

    # ── Mode Switching ───────────────────────────────────────────────────

    def _switch_mode(self, mode: str) -> bool:
        self.mode = mode
        show_mode(mode)
        return True

    def _start_agent(self, target: str) -> bool:
        if not target:
            print_error("Usage: /agent <target>  (e.g., /agent 192.168.1.1)")
            return True

        self.mode = "agent"
        show_mode("agent")

        self.agent = AgentMode(
            engine=self.engine,
            config=self.config,
            on_step=self._on_agent_step,
            on_confirm=self._on_confirm,
            on_output=self._on_tool_output,
            on_token=self._on_token,
        )

        print_info(f"Starting assessment against: {target}")
        console.print(f"\n[agent]HackBot Agent:[/]")
        response = self.agent.start(target)
        console.print()
        return True

    # ── Commands ─────────────────────────────────────────────────────────

    def _show_config(self) -> bool:
        preset = PROVIDERS.get(self.config.ai.provider, {})
        provider_name = preset.get("name", self.config.ai.provider)
        show_config_status({
            "provider": f"{provider_name} ({self.config.ai.provider})",
            "model": self.config.ai.model,
            "api_key": self.config.ai.api_key,
            "base_url": self.config.ai.base_url or preset.get("base_url", ""),
            "temperature": self.config.ai.temperature,
            "max_tokens": self.config.ai.max_tokens,
            "safe_mode": self.config.agent.safe_mode,
        })
        return True

    def _show_tools(self) -> bool:
        tools = detect_tools(self.config.agent.allowed_tools)
        show_tools_status(tools)
        return True

    def _set_model(self, model: str) -> bool:
        if not model:
            print_error("Usage: /model <model-name>\n  See available models: /models")
            return True
        self.config.ai.model = model
        self.engine = AIEngine(self.config.ai)
        # Update all modes with new engine
        self.chat.engine = self.engine
        self.plan.engine = self.engine
        save_config(self.config)
        print_success(f"Model set to: {model}")
        return True

    def _show_version(self) -> None:
        print_info(f"HackBot v{__version__}")
        console.print("[dim]  Developed by[/] [bold]Yashab Alam[/]")
        console.print("[dim]  GitHub:[/]   https://github.com/yashab-cyber")
        console.print("[dim]  LinkedIn:[/] https://www.linkedin.com/in/yashab-alam")

    def _show_donate(self) -> None:
        console.print("\n[bold bright_red]❤️  Support HackBot[/]\n")
        console.print("HackBot is free & open-source. If it has helped you,")
        console.print("please consider supporting its development!\n")
        console.print("[bold]Developer:[/]  Yashab Alam")
        console.print("[bold]GitHub:[/]     https://github.com/yashab-cyber")
        console.print("[bold]LinkedIn:[/]   https://www.linkedin.com/in/yashab-alam")
        console.print("[bold]Email:[/]      yashabalam707@gmail.com")
        console.print("[bold]Email:[/]      yashabalam9@gmail.com")
        console.print("\n[dim]For donation inquiries, sponsorship, or collaboration —[/]")
        console.print("[dim]reach out through any of the links above.[/]")
        console.print("[dim]See DONATE.md for more details.[/]\n")

    def _set_key(self, key: str) -> bool:
        if not key:
            print_error("Usage: /key <api-key>")
            return True
        self.config.ai.api_key = key
        self.engine = AIEngine(self.config.ai)
        self.chat.engine = self.engine
        self.plan.engine = self.engine

        # Validate the key before saving
        print_info("Validating API key...")
        result = self.engine.validate_api_key()
        if result["valid"]:
            save_config(self.config)
            print_success(result["message"])
        else:
            print_error(result["message"])
            print_warning("API key saved but may not work. Use /key to set a valid key.")
            save_config(self.config)
        return True

    def _set_provider(self, provider: str) -> bool:
        if not provider:
            # Show interactive list
            return self._list_providers()
        provider = provider.strip().lower()
        if provider not in PROVIDERS:
            print_error(
                f"Unknown provider: {provider}\n"
                f"  Available: {', '.join(PROVIDERS.keys())}"
            )
            return True
        preset = PROVIDERS[provider]
        self.config.ai.provider = provider
        # Set default model for the provider
        if preset["models"]:
            self.config.ai.model = preset["models"][0]["id"]
        # Clear base_url so engine uses preset
        self.config.ai.base_url = ""
        self.engine = AIEngine(self.config.ai)
        self.chat.engine = self.engine
        self.plan.engine = self.engine
        save_config(self.config)
        print_success(
            f"Provider: {preset['name']}\n"
            f"  Model: {self.config.ai.model}\n"
            f"  Endpoint: {preset['base_url']}"
        )
        if preset.get("env_key"):
            print_info(f"Set API key with: /key <key>  or  export {preset['env_key']}=<key>")

        # Validate existing key against new provider
        if self.config.ai.api_key:
            print_info("Validating API key with new provider...")
            result = self.engine.validate_api_key()
            if result["valid"]:
                print_success(result["message"])
            else:
                print_error(result["message"])
        return True

    def _list_providers(self) -> bool:
        from rich.table import Table
        table = Table(title="Available AI Providers", border_style="dim")
        table.add_column("ID", style="green")
        table.add_column("Name", style="cyan")
        table.add_column("Models", justify="right")
        table.add_column("Env Var", style="dim")
        table.add_column("Active", justify="center")
        for key, p in PROVIDERS.items():
            active = "●" if key == self.config.ai.provider else ""
            table.add_row(
                key, p["name"], str(len(p["models"])),
                p.get("env_key", "—") or "—",
                f"[green]{active}[/]" if active else "",
            )
        console.print(table)
        print_info("Switch with: /provider <id>  (e.g. /provider anthropic)")
        return True

    def _list_models(self, provider_key: str = "") -> bool:
        from rich.table import Table
        provider_key = provider_key.strip().lower() or self.config.ai.provider
        preset = PROVIDERS.get(provider_key)
        if not preset:
            print_error(f"Unknown provider: {provider_key}")
            return True
        table = Table(title=f"Models — {preset['name']}", border_style="dim")
        table.add_column("Model ID", style="cyan")
        table.add_column("Name")
        table.add_column("Context", justify="right", style="dim")
        table.add_column("Active", justify="center")
        for m in preset["models"]:
            active = "●" if m["id"] == self.config.ai.model else ""
            ctx = f"{m['ctx']:,}" if m.get("ctx") else "—"
            table.add_row(
                m["id"], m["name"], ctx,
                f"[green]{active}[/]" if active else "",
            )
        console.print(table)
        print_info("Switch with: /model <model-id>")
        return True

    def _save_session(self, name: str) -> bool:
        if self.mode == "chat":
            path = self.chat.save_session(name)
        elif self.mode == "plan":
            path = self.plan.save_plan(name)
        elif self.mode == "agent" and self.agent:
            path = self.agent.save_assessment()
        else:
            print_error("Nothing to save")
            return True
        print_success(f"Saved to: {path}")
        return True

    def _load_session(self, name: str) -> bool:
        if self.mode == "chat":
            sessions = self.chat.list_sessions()
            if not sessions:
                print_info("No saved sessions found")
                return True
            if name:
                matches = [s for s in sessions if name in s["name"] or name in s.get("id", "")]
                if matches:
                    self.chat.load_session(matches[0].get("id") or matches[0]["path"])
                    print_success(f"Loaded: {matches[0]['name']} ({matches[0]['message_count']} messages)")
                else:
                    print_error(f"Session not found: {name}")
            else:
                print_info("Available sessions:")
                for s in sessions[:10]:
                    ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(s["timestamp"]))
                    console.print(f"  [dim]{ts}[/]  {s['name']}  ({s['message_count']} msgs)")
                print_info("Load with: /load <name>")
        return True

    def _continue_response(self) -> bool:
        """Continue a response that was cut off."""
        if not self.engine.is_configured():
            print_error("API key not configured.")
            return True

        try:
            if self.mode == "chat":
                console.print(f"\n[chat]HackBot (continuing):[/]")
                response = self.chat.continue_response(
                    stream=True, on_token=self._on_token
                )
                console.print()
                if self.chat.was_truncated:
                    print_info("Still incomplete. Type /continue again to resume.")
            elif self.mode == "agent":
                if not self.agent:
                    print_error("No active assessment.")
                    return True
                console.print(f"\n[agent]HackBot Agent (continuing):[/]")
                response, is_complete = self.agent.continue_response(
                    on_token=self._on_token
                )
                console.print()
                if is_complete:
                    print_success("Assessment complete!")
                elif self.agent.was_truncated:
                    print_info("Still incomplete. Type /continue again to resume.")
            elif self.mode == "plan":
                # Plan mode uses the same ask method with continue prompt
                from hackbot.memory import CONTINUE_PROMPT
                console.print(f"\n[plan]HackBot Planner (continuing):[/]")
                response = self.plan.ask(CONTINUE_PROMPT, on_token=self._on_token)
                console.print()
            else:
                print_info("Nothing to continue.")
        except Exception as e:
            print_error(f"Error: {e}")

        return True

    def _list_all_sessions(self, mode_filter: str = "") -> bool:
        """List all saved sessions across all modes."""
        from hackbot.memory import MemoryManager
        memory = MemoryManager()

        mode = mode_filter.strip().lower() if mode_filter else None
        if mode and mode not in ("chat", "agent", "plan"):
            mode = None

        sessions = memory.list_sessions(mode=mode)

        if not sessions:
            print_info("No saved sessions found.")
            return True

        from rich.table import Table
        table = Table(title="Saved Sessions", border_style="dim")
        table.add_column("#", style="dim", width=3)
        table.add_column("Mode", style="cyan", width=6)
        table.add_column("Name")
        table.add_column("Messages", justify="right", width=8)
        table.add_column("Updated", style="dim")
        table.add_column("ID", style="dim")

        for i, s in enumerate(sessions[:25], 1):
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(s.updated))
            mode_icon = {"chat": "💬", "agent": "🤖", "plan": "📋"}.get(s.mode, "")
            table.add_row(
                str(i),
                f"{mode_icon} {s.mode}",
                s.name[:40],
                str(s.message_count),
                ts,
                s.id[:20] + "..." if len(s.id) > 20 else s.id,
            )
        console.print(table)
        print_info("Load a session: /load <name-or-id>")
        return True

    def _clear(self) -> bool:
        if self.mode == "chat":
            self.chat.reset()
        elif self.mode == "plan":
            self.plan.reset()
        print_success("Conversation cleared")
        return True

    def _reset(self) -> bool:
        self.chat = ChatMode(self.engine, self.config)
        self.agent = None
        self.plan = PlanMode(self.engine, self.config)
        self.mode = "chat"
        print_success("HackBot reset to fresh state")
        return True

    def _run_command(self, command: str) -> bool:
        if not command:
            print_error("Usage: /run <command>")
            return True
        if self.mode != "agent" or not self.agent:
            # Create a temporary agent for standalone commands
            self.agent = AgentMode(
                engine=self.engine,
                config=self.config,
                on_step=self._on_agent_step,
                on_confirm=self._on_confirm,
                on_output=self._on_tool_output,
            )

        tool_name = command.split()[0]
        print_tool_execution(tool_name, command)
        result = self.agent.run_command(command)
        print_tool_result(result.tool, result.success, result.duration, result.output, result.return_code)
        return True

    def _agent_step(self, user_input: str) -> bool:
        if not self.agent or not self.agent.is_running:
            print_error("No active assessment. Use /agent <target> first.")
            return True

        console.print(f"\n[agent]HackBot Agent:[/]")
        response, is_complete = self.agent.step(user_input)
        console.print()

        if is_complete:
            print_success("Assessment complete!")
            if self.config.reporting.auto_save:
                self._export_report("")
        return True

    def _show_findings(self) -> bool:
        if not self.agent:
            print_info("No active assessment")
            return True
        summary = self.agent.get_findings_summary()
        console.print(Markdown(summary))
        return True

    def _generate_remediations(self, args: str = "") -> bool:
        """Generate remediation guidance for findings."""
        if not self.agent:
            print_info("No active assessment — start one with /agent <target>")
            return True
        findings = [f.to_dict() for f in self.agent.findings]
        if not findings:
            print_info("No findings to remediate")
            return True

        use_ai = "--ai" in args
        engine = RemediationEngine(ai_engine=self.engine if use_ai else None)

        # Single finding by index
        idx_arg = args.replace("--ai", "").strip()
        if idx_arg.isdigit():
            idx = int(idx_arg) - 1
            if 0 <= idx < len(findings):
                r = engine.remediate_finding(findings[idx], use_ai=use_ai)
                console.print(Markdown(r.get_markdown()))
            else:
                print_error(f"Finding #{idx_arg} not found (1-{len(findings)})")
            return True

        # All findings
        with console.status("[cyan]Generating remediations..."):
            remediations = engine.remediate_findings(findings, use_ai=use_ai)
        report = RemediationEngine.get_summary_markdown(remediations)
        console.print(Markdown(report))
        print_success(f"Generated {len(remediations)} remediations "
                      f"({sum(len(r.steps) for r in remediations)} fix steps)")
        return True

    def _handle_proxy(self, args: str = "") -> bool:
        """Handle /proxy commands."""
        parts = args.strip().split(maxsplit=1)
        subcmd = parts[0].lower() if parts else "status"
        sub_args = parts[1] if len(parts) > 1 else ""
        proxy = get_proxy_engine()

        if subcmd == "start":
            port = int(sub_args) if sub_args.isdigit() else 8080
            result = proxy.start(port=port)
            if result["ok"]:
                print_success(result["message"])
                print_info(f"  curl example: {result['curl_example']}")
                print_info(f"  env: {result['env_hint']}")
            else:
                print_error(result["error"])

        elif subcmd == "stop":
            result = proxy.stop()
            if result["ok"]:
                print_success(f"Proxy stopped. {result['total_requests']} requests captured.")
            else:
                print_error(result["error"])

        elif subcmd == "status":
            stats = proxy.get_stats()
            if proxy.is_running:
                print_info(f"Proxy running on 127.0.0.1:{proxy.port}")
            else:
                print_info("Proxy is not running")
            print_info(f"  Requests: {stats['total_requests']} | "
                       f"Bytes: {stats['total_bytes']:,} | "
                       f"Avg: {stats['avg_duration_ms']}ms")
            if stats["scope"]:
                print_info(f"  Scope: {', '.join(stats['scope'])}")
            if stats["flags"]:
                print_info(f"  Flags: {stats['flags']}")

        elif subcmd == "traffic":
            limit = int(sub_args) if sub_args.isdigit() else None
            traffic = proxy.get_traffic(limit=limit)
            if not traffic:
                print_info("No captured traffic")
            else:
                for r in traffic:
                    flag_str = f" 🚩{','.join(r.flags)}" if r.flags else ""
                    color = "red" if r.status_code >= 400 else "yellow" if r.status_code >= 300 else "green"
                    console.print(f"  [dim]#{r.id}[/] [{color}]{r.method}[/] {r.url} → {r.status_code} "
                                  f"({r.duration_ms:.0f}ms, {r.response_size}B){flag_str}")

        elif subcmd == "filter":
            if not sub_args:
                print_error("Usage: /proxy filter <search_term>")
            else:
                traffic = proxy.get_traffic(filter_term=sub_args)
                if not traffic:
                    print_info(f"No traffic matching '{sub_args}'")
                else:
                    for r in traffic:
                        console.print(f"  [dim]#{r.id}[/] {r.method} {r.url} → {r.status_code}")
                    print_info(f"{len(traffic)} matching requests")

        elif subcmd == "scope":
            if not sub_args:
                if proxy.scope:
                    print_info(f"Current scope: {', '.join(proxy.scope)}")
                else:
                    print_info("No scope set (capturing all domains)")
            elif sub_args == "clear":
                proxy.clear_scope()
                print_success("Scope cleared — capturing all domains")
            else:
                domains = [d.strip() for d in sub_args.split(",")]
                proxy.set_scope(domains)
                print_success(f"Scope set: {', '.join(proxy.scope)}")

        elif subcmd == "clear":
            count = proxy.clear()
            print_success(f"Cleared {count} captured requests")

        elif subcmd == "export":
            filename = sub_args or "traffic_capture.json"
            data = proxy.export_traffic_json()
            from pathlib import Path
            Path(filename).write_text(data)
            print_success(f"Exported {proxy.get_stats()['total_requests']} requests to {filename}")

        elif subcmd == "replay":
            if not sub_args.isdigit():
                print_error("Usage: /proxy replay <request_id>")
            else:
                req_id = int(sub_args)
                result = proxy.replay_request(req_id)
                if result:
                    md = ProxyEngine.get_request_detail_markdown(result)
                    console.print(Markdown(md))
                else:
                    print_error(f"Request #{req_id} not found")

        elif subcmd == "flags":
            flagged = proxy.get_flagged_traffic()
            if not flagged:
                print_info("No flagged traffic")
            else:
                for r in flagged:
                    flags_str = ", ".join(r.flags)
                    console.print(f"  [dim]#{r.id}[/] [bold]{r.method}[/] {r.url} → {r.status_code} 🚩 {flags_str}")
                print_info(f"{len(flagged)} flagged requests")

        elif subcmd == "detail":
            if not sub_args.isdigit():
                print_error("Usage: /proxy detail <request_id>")
            else:
                req_id = int(sub_args)
                req = proxy.get_request_by_id(req_id)
                if req:
                    md = ProxyEngine.get_request_detail_markdown(req)
                    console.print(Markdown(md))
                else:
                    print_error(f"Request #{req_id} not found")

        else:
            print_info("Usage: /proxy <start|stop|status|traffic|filter|scope|clear|export|replay|flags|detail>")
            print_info("  start [port]   — Start proxy (default: 8080)")
            print_info("  stop           — Stop proxy")
            print_info("  status         — Show proxy stats")
            print_info("  traffic [n]    — Show captured traffic (last n requests)")
            print_info("  filter <term>  — Filter traffic by URL/header/body")
            print_info("  scope <domain> — Restrict capture to domain(s)")
            print_info("  clear          — Clear captured traffic")
            print_info("  export [file]  — Export traffic as JSON")
            print_info("  replay <id>    — Replay a captured request")
            print_info("  flags          — Show flagged requests")
            print_info("  detail <id>    — Show full request/response details")

        return True

    def _stop_agent(self) -> bool:
        if self.agent and self.agent.is_running:
            summary = self.agent.stop()
            print_assistant(summary, "agent")
            print_success("Assessment stopped")
        else:
            print_info("No active assessment")
        return True

    def _export_report(self, args: str) -> bool:
        if not self.agent:
            print_info("No assessment data to export")
            return True

        fmt = args.strip() or self.config.reporting.format
        if fmt == "pdf":
            return self._export_pdf(args)

        reporter = ReportGenerator(
            include_raw=self.config.reporting.include_raw_output,
            report_format=fmt,
        )

        findings = [f.to_dict() for f in self.agent.findings]
        tool_history = [r.to_dict() for r in self.agent.runner.history]

        path = reporter.generate(
            target=self.agent.target,
            findings=findings,
            tool_history=tool_history,
            scope=self.agent.scope,
            start_time=self._start_time,
        )
        print_success(f"Report saved: {path}")
        return True

    def _export_pdf(self, args: str) -> bool:
        """Generate a professional PDF pentest report."""
        if not self.agent:
            print_info("No assessment data to export")
            return True

        if not HAS_REPORTLAB:
            print_error("PDF generation requires reportlab. Install with: pip install 'hackbot[pdf]'")
            return True

        findings = [f.to_dict() for f in self.agent.findings]
        tool_history = [r.to_dict() for r in self.agent.runner.history]

        # Build compliance data if findings exist
        compliance_data = None
        if findings:
            try:
                mapper = ComplianceMapper()
                report = mapper.map_findings(findings, target=self.agent.target)
                if report.mappings:
                    compliance_data = report.to_dict()
            except Exception:
                pass

        print_info("Generating professional PDF report...")
        gen = PDFReportGenerator(include_raw=self.config.reporting.include_raw_output)
        path = gen.generate(
            target=self.agent.target,
            findings=findings,
            tool_history=tool_history,
            scope=self.agent.scope,
            summary="",
            start_time=self._start_time,
            compliance_data=compliance_data,
        )
        print_success(f"PDF report saved: {path}")
        return True

    def _show_templates(self) -> bool:
        templates = PlanMode.list_templates()
        console.print("\n[title]Available Plan Templates:[/]\n")
        for key, name in templates.items():
            console.print(f"  [bold]{key:20s}[/] {name}")
        console.print(f"\n[dim]Usage: /plan then ask to create a plan using a template[/]")
        return True

    def _generate_checklist(self, plan_type: str) -> bool:
        plan_type = plan_type.strip() or "web_pentest"
        console.print(f"\n[plan]HackBot Planner:[/]")
        self.plan.generate_checklist(plan_type, on_token=self._on_token)
        console.print()
        return True

    def _generate_commands(self, args: str) -> bool:
        if not args:
            print_error("Usage: /commands <target>")
            return True
        available = detect_tools(self.config.agent.allowed_tools)
        installed = [t for t, p in available.items() if p]
        console.print(f"\n[plan]HackBot Planner:[/]")
        self.plan.generate_commands(args, installed[:10], on_token=self._on_token)
        console.print()
        return True

    # ── CVE / OSINT / Topology Commands ──────────────────────────────────

    def _cve_lookup(self, args: str) -> bool:
        """Look up CVEs by ID or keyword."""
        if not args:
            print_error(
                "Usage:\n"
                "  /cve CVE-2021-44228          Look up a specific CVE\n"
                "  /cve Apache 2.4.49           Search by keyword\n"
                "  /cve --nmap <paste output>   Map nmap results to CVEs"
            )
            return True

        cve_engine = CVELookup()

        if args.strip().upper().startswith("CVE-"):
            # Direct CVE lookup
            print_info(f"Looking up {args.strip().upper()}...")
            entry = cve_engine.lookup_cve(args.strip())
            if entry:
                report = CVELookup.format_cve_report([entry], title=f"CVE Lookup: {entry.cve_id}")
                console.print(Markdown(report))
            else:
                print_error(f"CVE not found: {args.strip()}")

        elif args.strip().startswith("--nmap"):
            nmap_output = args.replace("--nmap", "", 1).strip()
            if not nmap_output:
                print_error("Paste nmap output after --nmap flag")
                return True
            print_info("Mapping nmap services to CVEs (this may take a moment)...")
            results = cve_engine.parse_nmap_and_lookup(nmap_output, max_per_service=5)
            report = CVELookup.format_nmap_cve_report(results)
            console.print(Markdown(report))

        else:
            # Keyword search
            print_info(f"Searching NVD for: {args}...")
            cves = cve_engine.search_cve(args, max_results=15)
            report = CVELookup.format_cve_report(cves, title=f"CVE Search: {args}")
            console.print(Markdown(report))

        return True

    def _osint_scan(self, args: str) -> bool:
        """Run OSINT scan on a domain."""
        if not args:
            print_error(
                "Usage:\n"
                "  /osint example.com           Full OSINT scan\n"
                "  /osint --subs example.com    Subdomain enumeration only\n"
                "  /osint --dns example.com     DNS records only\n"
                "  /osint --whois example.com   WHOIS lookup only\n"
                "  /osint --tech example.com    Tech stack fingerprinting only\n"
                "  /osint --emails example.com  Email harvesting only"
            )
            return True

        osint = OSINTEngine()
        args_stripped = args.strip()

        if args_stripped.startswith("--subs "):
            domain = args_stripped.replace("--subs ", "", 1).strip()
            print_info(f"Enumerating subdomains for {domain}...")
            subs = osint.enumerate_subdomains(domain)
            console.print(f"\n[green]Found {len(subs)} subdomains:[/]\n")
            for s in subs:
                console.print(f"  [cyan]{s.subdomain}[/]  →  {s.ip or '—'}  [{s.source}]")

        elif args_stripped.startswith("--dns "):
            domain = args_stripped.replace("--dns ", "", 1).strip()
            print_info(f"Resolving DNS records for {domain}...")
            records = osint.get_dns_records(domain)
            from rich.table import Table
            table = Table(title=f"DNS Records: {domain}", border_style="dim")
            table.add_column("Type", style="cyan")
            table.add_column("Value")
            table.add_column("TTL", style="dim")
            for r in records:
                table.add_row(r.record_type, r.value[:80], str(r.ttl))
            console.print(table)

        elif args_stripped.startswith("--whois "):
            domain = args_stripped.replace("--whois ", "", 1).strip()
            print_info(f"WHOIS lookup for {domain}...")
            result = osint.whois_lookup(domain)
            if result:
                console.print(f"\n[bold]WHOIS: {domain}[/]")
                if result.registrar:
                    console.print(f"  Registrar: [cyan]{result.registrar}[/]")
                if result.org:
                    console.print(f"  Organization: {result.org}")
                if result.creation_date:
                    console.print(f"  Created: {result.creation_date}")
                if result.expiration_date:
                    console.print(f"  Expires: {result.expiration_date}")
                if result.name_servers:
                    console.print(f"  Name Servers: {', '.join(result.name_servers)}")
                if result.emails:
                    console.print(f"  Contacts: {', '.join(result.emails)}")
            else:
                print_error("WHOIS lookup failed.")

        elif args_stripped.startswith("--tech "):
            domain = args_stripped.replace("--tech ", "", 1).strip()
            print_info(f"Fingerprinting tech stack for {domain}...")
            ts = osint.fingerprint_tech_stack(domain)
            console.print(f"\n[bold]Technology Stack: {ts.url}[/]")
            if ts.server:
                console.print(f"  Server: [cyan]{ts.server}[/]")
            if ts.powered_by:
                console.print(f"  Powered By: [cyan]{ts.powered_by}[/]")
            if ts.technologies:
                console.print(f"\n  [green]Detected Technologies:[/]")
                for tech in ts.technologies:
                    console.print(f"    • {tech['name']} ({tech['category']})")

        elif args_stripped.startswith("--emails "):
            domain = args_stripped.replace("--emails ", "", 1).strip()
            print_info(f"Harvesting emails for {domain}...")
            emails = osint.harvest_emails(domain)
            console.print(f"\n[green]Found {len(emails)} email addresses:[/]\n")
            for e in emails:
                console.print(f"  📧 {e}")

        else:
            # Full OSINT scan
            domain = args_stripped
            print_info(f"Running full OSINT scan on {domain}...")
            console.print()

            def on_progress(stage: str, detail: str) -> None:
                console.print(f"  [dim]{stage}:[/] {detail}")

            report = osint.full_scan(domain, on_progress=on_progress)
            md = OSINTEngine.format_report(report)
            console.print(Markdown(md))

        return True

    def _show_topology(self, args: str) -> bool:
        """Display network topology from scan results."""
        if not args and self.agent and self.agent.runner.history:
            # Try to use the last nmap scan from agent history
            for result in reversed(self.agent.runner.history):
                if "nmap" in result.command.lower() or "masscan" in result.command.lower():
                    args = result.stdout
                    break

        if not args:
            print_error(
                "Usage:\n"
                "  /topology <paste nmap/masscan output>\n"
                "  /topology   (auto-detect from last agent scan)"
            )
            return True

        parser = TopologyParser()
        topo = parser.auto_parse(args)

        # Show ASCII topology
        ascii_map = TopologyParser.render_ascii(topo)
        console.print(ascii_map)

        # Also show markdown summary
        md = TopologyParser.format_markdown(topo)
        console.print(Markdown(md))

        return True

    def _diff_report(self, args: str) -> bool:
        """Compare two agent sessions to show what changed."""
        parts = args.strip().split()

        # If two session IDs provided: /diff <old_id> <new_id>
        if len(parts) >= 2:
            old_id, new_id = parts[0], parts[1]
        elif len(parts) == 1:
            # Compare given session (baseline) vs current agent
            if not self.agent or not self.agent.findings:
                print_error("Need a current agent assessment to compare against. Usage: /diff <old_id> <new_id>")
                return True
            old_id = parts[0]
            new_id = "__current__"
        else:
            # List available sessions
            sessions = list_agent_sessions()
            if not sessions:
                print_info("No saved agent sessions with findings. Run an assessment first.")
                return True

            from rich.table import Table
            table = Table(title="Agent Sessions (with findings)", border_style="dim")
            table.add_column("#", style="dim", width=3)
            table.add_column("Target", style="cyan")
            table.add_column("Findings", justify="right", width=8)
            table.add_column("Date", style="dim")
            table.add_column("ID", style="dim")

            for i, s in enumerate(sessions[:20], 1):
                ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(s.get("updated", 0)))
                table.add_row(
                    str(i),
                    s.get("target", "")[:35],
                    str(s.get("finding_count", 0)),
                    ts,
                    s.get("id", "")[:25],
                )
            console.print(table)
            print_info("Usage: /diff <old_session_id> <new_session_id>")
            print_info("Or: /diff <baseline_session_id>  (compares against current agent)")
            return True

        # Load old session
        old_data = load_session_findings(old_id)
        if not old_data:
            print_error(f"Session not found: {old_id}")
            return True

        # Load new session
        if new_id == "__current__":
            if not self.agent or not self.agent.findings:
                print_error("No active agent with findings.")
                return True
            new_data = {
                "id": self.agent.session_id,
                "name": f"Agent: {self.agent.target}",
                "target": self.agent.target,
                "created": time.time(),
                "findings": [f.to_dict() for f in self.agent.findings],
            }
        else:
            new_data = load_session_findings(new_id)
            if not new_data:
                print_error(f"Session not found: {new_id}")
                return True

        print_info("Comparing assessments...")
        engine = DiffEngine()
        report = engine.compare(old_data, new_data)
        md = report.to_markdown()
        console.print(Markdown(md))
        return True

    def _compliance_map(self, args: str) -> bool:
        """Map current findings to compliance frameworks."""
        if not self.agent or not self.agent.findings:
            print_error("No agent findings to map. Run an agent assessment first with /agent <target>")
            return True

        # Parse framework filters
        frameworks = None
        if args:
            frameworks = [fw.strip() for fw in args.replace(",", " ").split()]

        print_info("Mapping findings to compliance frameworks...")

        mapper = ComplianceMapper(frameworks=frameworks)
        findings_dicts = [f.to_dict() for f in self.agent.findings]
        report = mapper.map_findings(findings_dicts, target=self.agent.target)

        md = ComplianceMapper.format_report(report)
        console.print(Markdown(md))

        return True

    def _show_plugins(self, args: str) -> bool:
        """List, reload, or manage user plugins."""
        sub = args.strip().lower()

        if sub == "reload":
            from hackbot.core.plugins import reset_plugin_manager
            reset_plugin_manager()
            pm = get_plugin_manager()
            count = pm.count
            errors = pm.get_load_errors()
            print_success(f"Plugins reloaded: {count} loaded")
            if errors:
                for err in errors:
                    print_warning(f"  {err['file']}: {err['error']}")
            return True

        if sub == "dir":
            path = ensure_plugins_dir()
            print_info(f"Plugins directory: {path}")
            plugin_files = list(path.glob("*.py"))
            if plugin_files:
                for f in sorted(plugin_files):
                    print_info(f"  {f.name}")
            else:
                print_info("  (empty — place .py plugin files here)")
            return True

        # Default: list registered plugins
        pm = get_plugin_manager()
        plugins = pm.list_plugins()

        if not plugins:
            print_info("No plugins registered.")
            print_info(f"Place plugin .py files in: {PLUGINS_DIR}")
            print_info("Use /plugins reload to rescan after adding new plugins.")
            return True

        from rich.table import Table
        table = Table(title="Registered Plugins", border_style="dim")
        table.add_column("Name", style="cyan")
        table.add_column("Description")
        table.add_column("Args", style="dim")
        table.add_column("Version", style="dim", width=8)
        table.add_column("Category", style="dim")
        table.add_column("Status", width=8)

        for p in plugins:
            args_str = ", ".join(p.get("args", {}).keys()) or "—"
            status = "✅" if p.get("enabled", True) else "❌"
            table.add_row(
                p["name"],
                p.get("description", "")[:50],
                args_str,
                p.get("version", ""),
                p.get("category", "custom"),
                status,
            )
        console.print(table)

        errors = pm.get_load_errors()
        if errors:
            print_warning(f"{len(errors)} plugin(s) failed to load:")
            for err in errors:
                print_warning(f"  {err['file']}: {err['error']}")

        return True

    def _handle_campaign(self, args: str) -> bool:
        """Multi-target campaign management."""
        parts = args.strip().split(maxsplit=1)
        sub = parts[0].lower() if parts else ""
        sub_args = parts[1] if len(parts) > 1 else ""

        if sub == "new":
            return self._campaign_new(sub_args)
        elif sub == "add":
            return self._campaign_add_targets(sub_args)
        elif sub == "remove":
            return self._campaign_remove_target(sub_args)
        elif sub == "start":
            return self._campaign_start(sub_args)
        elif sub == "status":
            return self._campaign_status()
        elif sub == "findings":
            return self._campaign_findings()
        elif sub == "report":
            return self._campaign_export_report()
        elif sub == "skip":
            return self._campaign_skip_target(sub_args)
        elif sub == "pause":
            return self._campaign_pause()
        elif sub == "resume":
            return self._campaign_resume()
        elif sub == "abort":
            return self._campaign_abort()
        elif sub == "list":
            return self._campaign_list()
        elif sub == "load":
            return self._campaign_load(sub_args)
        elif sub == "delete":
            return self._campaign_delete(sub_args)
        elif sub == "next":
            return self._campaign_next()
        else:
            # Show usage help
            self._campaign_help()
            return True

    def _campaign_help(self) -> None:
        help_text = """[bold cyan]Campaign Commands:[/]
  /campaign new <name> <target1> <target2> ...   Create a new campaign
  /campaign add <target1> <target2> ...          Add targets to active campaign
  /campaign remove <target>                      Remove a target
  /campaign start                                Start running the campaign
  /campaign next                                 Advance to next target
  /campaign skip [reason]                        Skip current target
  /campaign status                               Show campaign progress
  /campaign findings                             Show all findings across targets
  /campaign report                               Generate campaign report
  /campaign pause                                Pause campaign
  /campaign resume                               Resume paused campaign
  /campaign abort                                Abort campaign
  /campaign list                                 List saved campaigns
  /campaign load <id>                            Load a saved campaign
  /campaign delete <id>                          Delete a saved campaign"""
        console.print(help_text)

    def _campaign_new(self, args: str) -> bool:
        """Create a new multi-target campaign."""
        parts = args.strip().split()
        if len(parts) < 2:
            print_error("Usage: /campaign new <name> <target1> [target2] ...")
            print_info('Example: /campaign new "Q1 Audit" 192.168.1.1 192.168.1.2 app.example.com')
            return True

        # Parse name — support quoted names
        if args.strip().startswith('"'):
            # Quoted name
            end = args.index('"', 1)
            name = args[1:end]
            rest = args[end + 1:].strip()
        elif args.strip().startswith("'"):
            end = args.index("'", 1)
            name = args[1:end]
            rest = args[end + 1:].strip()
        else:
            name = parts[0]
            rest = " ".join(parts[1:])

        targets = [t.strip() for t in rest.split() if t.strip()]
        if not targets:
            print_error("At least one target is required.")
            return True

        cm = get_campaign_manager()
        campaign = cm.create_campaign(
            name=name,
            targets=targets,
            scope=self.config.agent.allowed_tools and ", ".join(self.config.agent.allowed_tools) or "",
            max_steps_per_target=self.config.agent.max_steps,
        )
        cm.active_campaign = campaign

        print_success(f"Campaign created: {campaign.name}")
        print_info(f"  ID: {campaign.id}")
        print_info(f"  Targets: {campaign.target_count}")
        for i, t in enumerate(campaign.targets, 1):
            print_info(f"    {i}. {t}")
        print_info("Use /campaign start to begin the assessment.")
        return True

    def _campaign_add_targets(self, args: str) -> bool:
        cm = get_campaign_manager()
        campaign = cm.active_campaign
        if not campaign:
            print_error("No active campaign. Create one with /campaign new")
            return True
        targets = [t.strip() for t in args.split() if t.strip()]
        if not targets:
            print_error("Usage: /campaign add <target1> [target2] ...")
            return True
        added = campaign.add_targets(targets)
        cm.save_campaign(campaign)
        print_success(f"Added {added} target(s). Total: {campaign.target_count}")
        return True

    def _campaign_remove_target(self, args: str) -> bool:
        cm = get_campaign_manager()
        campaign = cm.active_campaign
        if not campaign:
            print_error("No active campaign.")
            return True
        target = args.strip()
        if not target:
            print_error("Usage: /campaign remove <target>")
            return True
        if campaign.remove_target(target):
            cm.save_campaign(campaign)
            print_success(f"Removed: {target}")
        else:
            print_error(f"Target not found: {target}")
        return True

    def _campaign_start(self, args: str) -> bool:
        """Start the campaign — begins assessment of first pending target."""
        cm = get_campaign_manager()
        campaign = cm.active_campaign
        if not campaign:
            print_error("No active campaign. Create one with /campaign new")
            return True

        if campaign.status == CampaignStatus.RUNNING:
            # Already running — show next target info
            next_t = campaign.next_pending_target
            if next_t:
                print_info(f"Campaign already running. Next target: {next_t}")
                print_info("Use /campaign next to advance to it.")
            else:
                print_info("All targets have been assessed.")
            return True

        result = cm.start_campaign(campaign)
        if result.startswith("ERROR"):
            print_error(result)
            return True

        first_target = result
        print_success(f"Campaign '{campaign.name}' started!")
        print_info(f"Assessing target 1/{campaign.target_count}: {first_target}")

        # Begin the first target assessment
        self._campaign_assess_target(campaign, first_target)
        return True

    def _campaign_assess_target(self, campaign: Campaign, target: str) -> None:
        """Run an agent assessment against a single campaign target."""
        cm = get_campaign_manager()
        cm.begin_target(campaign, target)

        # Create a fresh agent for this target
        self.mode = "agent"
        show_mode("agent")
        self.agent = AgentMode(
            engine=self.engine,
            config=self.config,
            on_step=self._on_agent_step,
            on_confirm=self._on_confirm,
            on_output=self._on_tool_output,
            on_token=self._on_token,
        )

        # Add campaign context to instructions
        campaign_ctx = campaign.get_agent_context(target)
        instructions = (campaign.instructions or "") + "\n" + campaign_ctx

        print_info(f"Starting assessment against: {target}")
        console.print(f"\n[agent]HackBot Agent:[/]")

        try:
            self.agent.start(target, scope=campaign.scope, instructions=instructions)
            console.print()
        except Exception as e:
            cm.fail_target(campaign, target, error=str(e))
            print_error(f"Assessment failed for {target}: {e}")
            return

        # Store the campaign reference so step/stop can update it
        self._active_campaign_target = target

    def _campaign_next(self) -> bool:
        """Complete current target and advance to the next one."""
        cm = get_campaign_manager()
        campaign = cm.active_campaign
        if not campaign:
            print_error("No active campaign.")
            return True

        # Complete the current target if agent has been running
        current = getattr(self, "_active_campaign_target", None)
        if current and self.agent:
            findings = [f.to_dict() for f in self.agent.findings]
            tool_history = [r.to_dict() for r in self.agent.runner.history]
            cm.complete_target(
                campaign, current,
                findings=findings,
                tool_history=tool_history,
                session_id=self.agent.session_id,
                steps=len(self.agent.steps),
                summary=self.agent.get_findings_summary() if self.agent.findings else "",
            )
            print_success(f"Completed: {current} ({len(findings)} findings)")

        # Advance to next
        next_target = cm.advance_to_next(campaign)
        if not next_target:
            campaign.status = CampaignStatus.COMPLETED
            cm.save_campaign(campaign)
            print_success(f"Campaign '{campaign.name}' complete! "
                          f"{campaign.total_findings} total findings across {campaign.target_count} targets.")
            self._active_campaign_target = None
            return True

        idx = campaign.targets.index(next_target) + 1
        print_info(f"Advancing to target {idx}/{campaign.target_count}: {next_target}")
        self._campaign_assess_target(campaign, next_target)
        return True

    def _campaign_skip_target(self, args: str) -> bool:
        cm = get_campaign_manager()
        campaign = cm.active_campaign
        if not campaign:
            print_error("No active campaign.")
            return True

        current = getattr(self, "_active_campaign_target", None)
        if not current:
            print_error("No target currently being assessed.")
            return True

        cm.skip_target(campaign, current, reason=args.strip() or "Skipped by user")
        print_info(f"Skipped: {current}")

        # Auto-advance
        return self._campaign_next()

    def _campaign_status(self) -> bool:
        cm = get_campaign_manager()
        campaign = cm.active_campaign
        if not campaign:
            print_error("No active campaign. Use /campaign list to see saved campaigns.")
            return True

        from rich.table import Table
        from rich.panel import Panel

        # Summary panel
        summary = (f"[bold]{campaign.name}[/bold]  ({campaign.status.value.upper()})\n"
                   f"Progress: {campaign.completed_count}/{campaign.target_count} "
                   f"({campaign.progress_pct()}%)\n"
                   f"Total findings: {campaign.total_findings}")
        console.print(Panel(summary, title="Campaign Status", border_style="cyan"))

        # Per-target table
        table = Table(title="Targets", border_style="dim")
        table.add_column("#", style="dim", width=3)
        table.add_column("Target", style="cyan")
        table.add_column("Status", width=12)
        table.add_column("Findings", justify="right", width=8)
        table.add_column("Steps", justify="right", width=6)
        table.add_column("Duration", style="dim", width=10)

        icons = {
            TargetStatus.PENDING: "[dim]⏳ pending[/]",
            TargetStatus.RUNNING: "[yellow]🔄 running[/]",
            TargetStatus.COMPLETED: "[green]✅ done[/]",
            TargetStatus.FAILED: "[red]❌ failed[/]",
            TargetStatus.SKIPPED: "[dim]⏭️ skip[/]",
        }

        for i, t in enumerate(campaign.targets, 1):
            r = campaign.results.get(t)
            if r:
                dur = f"{r.completed_at - r.started_at:.0f}s" if r.completed_at else "-"
                table.add_row(
                    str(i), t, icons.get(r.status, "?"),
                    str(len(r.findings)), str(r.steps), dur,
                )
            else:
                table.add_row(str(i), t, icons[TargetStatus.PENDING], "0", "0", "-")

        console.print(table)
        return True

    def _campaign_findings(self) -> bool:
        cm = get_campaign_manager()
        campaign = cm.active_campaign
        if not campaign:
            print_error("No active campaign.")
            return True

        all_f = campaign.all_findings()
        if not all_f:
            print_info("No findings recorded yet.")
            return True

        md = campaign.get_summary_markdown()
        console.print(Markdown(md))
        return True

    def _campaign_export_report(self) -> bool:
        cm = get_campaign_manager()
        campaign = cm.active_campaign
        if not campaign:
            print_error("No active campaign.")
            return True

        path = cm.save_campaign_report(campaign)
        print_success(f"Campaign report saved: {path}")
        return True

    def _campaign_pause(self) -> bool:
        cm = get_campaign_manager()
        campaign = cm.active_campaign
        if not campaign:
            print_error("No active campaign.")
            return True
        cm.pause_campaign(campaign)
        self._active_campaign_target = None
        print_info(f"Campaign '{campaign.name}' paused. Use /campaign resume to continue.")
        return True

    def _campaign_resume(self) -> bool:
        cm = get_campaign_manager()
        campaign = cm.active_campaign
        if not campaign:
            print_error("No active campaign.")
            return True
        next_target = cm.resume_campaign(campaign)
        if not next_target:
            print_error("Campaign cannot be resumed or has no pending targets.")
            return True
        idx = campaign.targets.index(next_target) + 1
        print_info(f"Resuming campaign. Target {idx}/{campaign.target_count}: {next_target}")
        self._campaign_assess_target(campaign, next_target)
        return True

    def _campaign_abort(self) -> bool:
        cm = get_campaign_manager()
        campaign = cm.active_campaign
        if not campaign:
            print_error("No active campaign.")
            return True
        cm.abort_campaign(campaign)
        self._active_campaign_target = None
        print_warning(f"Campaign '{campaign.name}' aborted.")
        return True

    def _campaign_list(self) -> bool:
        cm = get_campaign_manager()
        campaigns = cm.list_campaigns()
        if not campaigns:
            print_info("No saved campaigns. Use /campaign new to create one.")
            return True

        from rich.table import Table
        table = Table(title="Saved Campaigns", border_style="dim")
        table.add_column("#", style="dim", width=3)
        table.add_column("Name", style="cyan")
        table.add_column("Status", width=12)
        table.add_column("Targets", justify="right", width=8)
        table.add_column("Progress", width=10)
        table.add_column("Findings", justify="right", width=8)
        table.add_column("Updated", style="dim")
        table.add_column("ID", style="dim")

        for i, c in enumerate(campaigns, 1):
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(c.get("updated_at", 0)))
            pct = f"{c.get('progress_pct', 0):.0f}%"
            table.add_row(
                str(i),
                c.get("name", "")[:30],
                c.get("status", "draft"),
                str(c.get("target_count", 0)),
                pct,
                str(c.get("total_findings", 0)),
                ts,
                c.get("id", "")[:25],
            )
        console.print(table)
        return True

    def _campaign_load(self, args: str) -> bool:
        campaign_id = args.strip()
        if not campaign_id:
            print_error("Usage: /campaign load <campaign_id>")
            return True
        cm = get_campaign_manager()
        campaign = cm.load_campaign(campaign_id)
        if not campaign:
            print_error(f"Campaign not found: {campaign_id}")
            return True
        cm.active_campaign = campaign
        print_success(f"Loaded campaign: {campaign.name} ({campaign.target_count} targets, {campaign.status.value})")
        return True

    def _campaign_delete(self, args: str) -> bool:
        campaign_id = args.strip()
        if not campaign_id:
            print_error("Usage: /campaign delete <campaign_id>")
            return True
        cm = get_campaign_manager()
        if cm.delete_campaign(campaign_id):
            print_success(f"Campaign deleted: {campaign_id}")
        else:
            print_error(f"Campaign not found: {campaign_id}")
        return True


# ── Prompt Styling ───────────────────────────────────────────────────────────

def get_prompt(mode: str) -> str:
    """Get the colored prompt string for each mode."""
    prompts = {
        "chat": "💬 hackbot> ",
        "agent": "🤖 hackbot[agent]> ",
        "plan": "📋 hackbot[plan]> ",
    }
    return prompts.get(mode, "hackbot> ")


# ── Main CLI ─────────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.option("--model", "-m", default=None, help="AI model to use")
@click.option("--provider", "-p", default=None, help="AI provider (openai/ollama/groq/local)")
@click.option("--api-key", "-k", default=None, help="API key")
@click.option("--base-url", default=None, help="Custom API base URL")
@click.option("--no-banner", is_flag=True, help="Skip banner display")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--safe-mode/--no-safe-mode", default=None, help="Enable/disable safe mode")
@click.option("--gui", "-g", is_flag=True, help="Launch the desktop GUI")
@click.version_option(__version__, prog_name="hackbot")
@click.pass_context
def main(ctx, model, provider, api_key, base_url, no_banner, verbose, safe_mode, gui):
    """HackBot — AI Cybersecurity Assistant"""
    ctx.ensure_object(dict)

    config = load_config()

    # Apply CLI overrides
    if model:
        config.ai.model = model
    if provider:
        config.ai.provider = provider
    if api_key:
        config.ai.api_key = api_key
    if base_url:
        config.ai.base_url = base_url
    if verbose:
        config.ui.verbose = True
    if safe_mode is not None:
        config.agent.safe_mode = safe_mode

    ctx.obj["config"] = config

    if gui:
        # Launch web-based GUI
        try:
            from hackbot.gui.app import launch_gui
            launch_gui(config)
        except ImportError:
            print_error(
                "GUI dependencies not installed. Install with:\n"
                "  pip install hackbot[gui]"
            )
        return

    if ctx.invoked_subcommand is None:
        # Start interactive REPL
        _interactive_repl(config, not no_banner)


@main.command()
@click.argument("target")
@click.option("--scope", "-s", default="", help="Assessment scope")
@click.option("--instructions", "-i", default="", help="Additional instructions")
@click.pass_context
def agent(ctx, target, scope, instructions):
    """Start an autonomous security assessment."""
    config = ctx.obj["config"]
    show_banner(small=True)

    app = HackBotApp(config)
    app._start_agent(target)

    # Enter agent REPL
    _mode_repl(app, "agent")


@main.command()
@click.pass_context
def chat(ctx):
    """Start interactive chat mode."""
    config = ctx.obj["config"]
    show_banner(small=True)

    app = HackBotApp(config)
    app._switch_mode("chat")
    _mode_repl(app, "chat")


@main.command()
@click.argument("target", default="")
@click.option("--type", "-t", "plan_type", default="web_pentest", help="Plan template type")
@click.pass_context
def plan(ctx, target, plan_type):
    """Create a penetration testing plan."""
    config = ctx.obj["config"]
    show_banner(small=True)

    app = HackBotApp(config)
    app._switch_mode("plan")

    if target:
        console.print(f"\n[plan]HackBot Planner:[/]")
        app.plan.create_plan(target, plan_type, on_token=app._on_token)
        console.print()

    _mode_repl(app, "plan")


@main.command()
@click.argument("command", nargs=-1)
@click.pass_context
def run(ctx, command):
    """Execute a security tool directly."""
    config = ctx.obj["config"]
    if not command:
        print_error("Usage: hackbot run <command>")
        return

    cmd = " ".join(command)
    app = HackBotApp(config)
    app._run_command(cmd)


@main.command()
@click.pass_context
def tools(ctx):
    """List available security tools."""
    config = ctx.obj["config"]
    tool_status = detect_tools(config.agent.allowed_tools)
    show_tools_status(tool_status)


@main.command()
@click.option("--host", default="127.0.0.1", help="Host to bind the GUI server")
@click.option("--port", default=1337, type=int, help="Port for the GUI server")
@click.pass_context
def gui(ctx, host, port):
    """Launch the desktop GUI application."""
    config = ctx.obj["config"]
    try:
        from hackbot.gui.app import launch_gui
        launch_gui(config, host=host, port=port)
    except ImportError:
        print_error(
            "GUI dependencies not installed. Install with:\n"
            "  pip install hackbot[gui]"
        )


@main.command()
@click.pass_context
def config(ctx):
    """Show current configuration and available providers."""
    cfg = ctx.obj["config"]
    preset = PROVIDERS.get(cfg.ai.provider, {})
    provider_name = preset.get("name", cfg.ai.provider)
    show_config_status({
        "provider": f"{provider_name} ({cfg.ai.provider})",
        "model": cfg.ai.model,
        "api_key": cfg.ai.api_key,
        "base_url": cfg.ai.base_url or preset.get("base_url", ""),
        "temperature": cfg.ai.temperature,
        "max_tokens": cfg.ai.max_tokens,
        "safe_mode": cfg.agent.safe_mode,
    })
    print_info(f"Config file: {Path(CONFIG_DIR) / 'config.yaml'}")

    # List providers summary
    console.print("\n[dim]Available providers:[/]")
    for key, p in PROVIDERS.items():
        active = " [green]◄ active[/]" if key == cfg.ai.provider else ""
        console.print(f"  [cyan]{key:<12}[/] {p['name']}{active}")
    console.print("[dim]\n  Set with: hackbot setup <API_KEY> --provider <id>[/]")


@main.command()
@click.argument("key")
@click.option("--provider", "-p", default=None, help="AI provider (openai/anthropic/gemini/groq/mistral/deepseek/together/openrouter/ollama/local)")
@click.option("--model", "-m", default=None, help="Model to use (auto-set from provider if omitted)")
@click.pass_context
def setup(ctx, key, provider, model):
    """Quick setup with API key. Optionally set provider and model."""
    cfg = ctx.obj["config"]
    cfg.ai.api_key = key

    if provider:
        provider = provider.lower()
        if provider in PROVIDERS:
            cfg.ai.provider = provider
            preset = PROVIDERS[provider]
            if not model and preset["models"]:
                cfg.ai.model = preset["models"][0]["id"]
            print_success(f"Provider set to: {preset['name']}")
        else:
            print_warning(f"Unknown provider '{provider}', keeping current ({cfg.ai.provider})")

    if model:
        cfg.ai.model = model
        print_success(f"Model set to: {model}")

    save_config(cfg)
    print_success(f"API key saved! Provider: {cfg.ai.provider}, Model: {cfg.ai.model}")

    # Validate the key
    print_info("Validating API key...")
    engine = AIEngine(cfg.ai)
    result = engine.validate_api_key()
    if result["valid"]:
        print_success(result["message"])
    else:
        print_error(result["message"])
        print_warning("Key saved but validation failed. Check your key and try again.")
    print_info("Run 'hackbot' to start.")


# ── Interactive REPL ─────────────────────────────────────────────────────────

def _interactive_repl(config: HackBotConfig, show_banner_flag: bool = True) -> None:
    """Main interactive REPL loop."""
    if show_banner_flag:
        show_banner()
        console.print("[dim]  Type /help for commands, /quit to exit[/]\n")

    # Show warnings
    if not config.ai.api_key:
        print_warning(
            "No API key configured. Set one with:\n"
            "  /key <your-api-key>\n"
            "  export HACKBOT_API_KEY=<your-api-key>\n"
            "  export OPENAI_API_KEY=<your-api-key>"
        )

    plat = detect_platform()
    console.print(
        f"[dim]  Platform: {plat['system']} {plat['machine']} | "
        f"Python {plat['python']} | "
        f"Model: {config.ai.model}[/]\n"
    )

    app = HackBotApp(config)

    # Setup prompt with history
    history_file = CONFIG_DIR / "history"
    try:
        session: PromptSession = PromptSession(
            history=FileHistory(str(history_file)),
            auto_suggest=AutoSuggestFromHistory(),
        )
    except Exception:
        session = PromptSession()

    show_mode(app.mode)

    while True:
        try:
            prompt = get_prompt(app.mode)
            user_input = session.prompt(prompt)
            if not app.handle_input(user_input):
                break
        except KeyboardInterrupt:
            console.print("\n[dim]Press Ctrl+C again to quit, or type /quit[/]")
            try:
                user_input = session.prompt(get_prompt(app.mode))
                if not app.handle_input(user_input):
                    break
            except (KeyboardInterrupt, EOFError):
                break
        except EOFError:
            break

    console.print("\n[dim]Goodbye! Stay safe, hack responsibly. 🛡️[/]\n")


def _mode_repl(app: HackBotApp, mode: str) -> None:
    """REPL for a specific mode."""
    history_file = CONFIG_DIR / "history"
    try:
        session = PromptSession(
            history=FileHistory(str(history_file)),
            auto_suggest=AutoSuggestFromHistory(),
        )
    except Exception:
        session = PromptSession()

    while True:
        try:
            prompt = get_prompt(app.mode)
            user_input = session.prompt(prompt)
            if not app.handle_input(user_input):
                break
        except KeyboardInterrupt:
            console.print("\n[dim]Interrupted[/]")
            continue
        except EOFError:
            break

    console.print("\n[dim]Goodbye! 🛡️[/]\n")


if __name__ == "__main__":
    main()
