"""
HackBot Agent Mode
==================
Autonomous cybersecurity testing agent that:
- Plans and executes security assessments
- Runs real security tools (nmap, nikto, sqlmap, etc.)
- Analyzes results and determines next steps
- Tracks findings with severity ratings
- Summarizes conversation history to reduce hallucination
- Supports continue/resume after interruptions
- Generates comprehensive reports

This is the core differentiator — real cybersecurity testing automation.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from hackbot.config import HackBotConfig, REPORTS_DIR
from hackbot.core.engine import AIEngine, Conversation, create_conversation
from hackbot.core.runner import ToolResult, ToolRunner
from hackbot.memory import ConversationSummarizer, MemoryManager, CONTINUE_PROMPT

try:
    from hackbot.core.pdf_report import PDFReportGenerator, HAS_REPORTLAB
except ImportError:
    HAS_REPORTLAB = False

try:
    from hackbot.core.plugins import get_plugin_manager
except ImportError:
    get_plugin_manager = None


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class Finding:
    """A security finding discovered during assessment."""
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    recommendation: str = ""
    tool: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "tool": self.tool,
            "timestamp": self.timestamp,
        }


@dataclass
class AgentStep:
    """A single step in the agent's execution."""
    step_num: int
    action: str  # "execute" | "finding" | "analysis" | "complete"
    description: str
    tool_result: Optional[ToolResult] = None
    finding: Optional[Finding] = None
    ai_analysis: str = ""
    timestamp: float = field(default_factory=time.time)


class AgentMode:
    """
    Autonomous cybersecurity testing agent.

    Flow:
    1. User provides target and scope
    2. Agent plans the assessment
    3. Agent executes tools step by step
    4. Agent analyzes results and adapts
    5. Agent reports findings
    """

    def __init__(
        self,
        engine: AIEngine,
        config: HackBotConfig,
        on_step: Optional[Callable[[AgentStep], None]] = None,
        on_confirm: Optional[Callable[[str, str], bool]] = None,
        on_output: Optional[Callable[[str], None]] = None,
        on_token: Optional[Callable[[str], None]] = None,
    ):
        self.engine = engine
        self.config = config
        self.on_step = on_step
        self.on_token = on_token

        self.runner = ToolRunner(
            allowed_tools=config.agent.allowed_tools,
            timeout=config.agent.timeout,
            safe_mode=config.agent.safe_mode,
            auto_confirm=config.agent.auto_confirm,
            on_confirm=on_confirm,
            on_output=on_output,
        )

        self.conversation: Optional[Conversation] = None
        self.target: str = ""
        self.scope: str = ""
        self.steps: List[AgentStep] = []
        self.findings: List[Finding] = []
        self.is_running: bool = False
        self._step_count: int = 0
        self._last_response: str = ""
        self._was_truncated: bool = False

        # Memory & summarization
        self.memory = MemoryManager()
        self.session_id = self.memory.new_session_id("agent")
        self.summarizer = ConversationSummarizer(
            engine=engine,
            max_messages=20,  # Smaller threshold for agent (tool outputs are large)
            keep_recent=6,
        )

    def start(self, target: str, scope: str = "", instructions: str = "") -> str:
        """
        Start a new assessment against a target.

        Args:
            target: Target IP, domain, or URL
            scope: Scope limitations
            instructions: Additional instructions for the agent
        """
        self.target = target
        self.scope = scope
        self.steps = []
        self.findings = []
        self._step_count = 0
        self.is_running = True

        self.conversation = create_conversation("agent", target)

        # Add scope and available tools context
        available_tools = self.runner.get_available_tools()
        installed = [t for t, avail in available_tools.items() if avail]
        not_installed = [t for t, avail in available_tools.items() if not avail]

        context = f"""Assessment Context:
- Target: {target}
- Scope: {scope or 'Full assessment as authorized'}
- Safe Mode: {'Enabled' if self.config.agent.safe_mode else 'Disabled'}
- Available Tools: {', '.join(installed) if installed else 'None detected'}
- Unavailable Tools: {', '.join(not_installed) if not_installed else 'None'}
- Max Steps: {self.config.agent.max_steps}
"""

        # Add custom plugin context
        if get_plugin_manager is not None:
            try:
                pm = get_plugin_manager()
                plugin_desc = pm.get_agent_tool_descriptions()
                if plugin_desc:
                    context += plugin_desc + "\n"
            except Exception:
                pass

        context += f"""
{f'Additional Instructions: {instructions}' if instructions else ''}

Begin the assessment. Start with reconnaissance and work methodically through each phase.
Explain your reasoning at each step."""

        self.conversation.add("user", context)

        # Get initial plan from AI
        response = self.engine.chat(
            self.conversation,
            stream=bool(self.on_token),
            on_token=self.on_token,
        )
        self.conversation.add("assistant", response)
        self._last_response = response
        self._was_truncated = self._detect_truncation(response)

        # Auto-save
        self._auto_save()

        return response

    def step(self, user_input: str = "") -> tuple[str, bool]:
        """
        Execute the next step in the assessment.

        Returns:
            (ai_response, is_complete)
        """
        if not self.is_running or not self.conversation:
            return "No active assessment. Use 'start' first.", True

        if self._step_count >= self.config.agent.max_steps:
            self.is_running = False
            return "Maximum steps reached. Generating final report...", True

        self._step_count += 1

        # Summarize conversation if it's getting too long (reduces hallucination)
        if self.summarizer.needs_summarization(self.conversation.messages):
            self.summarizer.summarize(self.conversation)

        # If user provided feedback, add it
        if user_input:
            self.conversation.add("user", user_input)
        else:
            self.conversation.add("user", "Continue with the next step of the assessment.")

        # Get AI response
        response = self.engine.chat(
            self.conversation,
            stream=bool(self.on_token),
            on_token=self.on_token,
        )
        self.conversation.add("assistant", response)
        self._last_response = response
        self._was_truncated = self._detect_truncation(response)

        # Parse and execute any actions in the response
        actions = self._parse_actions(response)
        results_text = []

        for action in actions:
            if action.get("action") == "execute":
                result = self._execute_action(action)
                results_text.append(result)
            elif action.get("action") == "finding":
                self._record_finding(action)
            elif action.get("action") == "generate_report":
                report_result = self._generate_report(action)
                results_text.append(report_result)
            elif action.get("action") == "complete":
                self.is_running = False
                return response, True

        # Feed results back to AI if we executed commands
        if results_text:
            result_msg = "\n\n---\n\n".join(results_text)
            self.conversation.add("user", f"Tool execution results:\n\n{result_msg}")

            # Get AI analysis of results
            analysis = self.engine.chat(
                self.conversation,
                stream=bool(self.on_token),
                on_token=self.on_token,
            )
            self.conversation.add("assistant", analysis)
            self._last_response = analysis
            self._was_truncated = self._detect_truncation(analysis)

            # Check for additional actions in analysis
            more_actions = self._parse_actions(analysis)
            for action in more_actions:
                if action.get("action") == "finding":
                    self._record_finding(action)
                elif action.get("action") == "generate_report":
                    self._generate_report(action)
                elif action.get("action") == "complete":
                    self.is_running = False
                    self._auto_save()
                    return analysis, True

            self._auto_save()
            return analysis, False

        self._auto_save()
        return response, False

    def continue_response(
        self,
        on_token: Optional[Callable[[str], None]] = None,
    ) -> tuple[str, bool]:
        """Continue a response that was cut off mid-stream."""
        if not self.conversation:
            return "No active conversation to continue.", True

        self.conversation.add("user", CONTINUE_PROMPT)

        token_cb = on_token or self.on_token
        response = self.engine.chat(
            self.conversation,
            stream=bool(token_cb),
            on_token=token_cb,
        )
        self.conversation.add("assistant", response)
        self._last_response = response
        self._was_truncated = self._detect_truncation(response)

        # Parse any actions in the continuation
        actions = self._parse_actions(response)
        for action in actions:
            if action.get("action") == "finding":
                self._record_finding(action)
            elif action.get("action") == "generate_report":
                self._generate_report(action)
            elif action.get("action") == "complete":
                self.is_running = False
                self._auto_save()
                return response, True

        self._auto_save()
        return response, False

    @property
    def was_truncated(self) -> bool:
        """Check if the last response was likely truncated."""
        return self._was_truncated

    def _detect_truncation(self, text: str) -> bool:
        """Heuristically detect if a response was truncated."""
        if not text or len(text) < 50:
            return False
        stripped = text.rstrip()
        if not stripped:
            return False
        last_char = stripped[-1]
        open_blocks = stripped.count("```") % 2 != 0
        ends_incomplete = last_char not in '.!?"\')]}>`\n*-' and not stripped.endswith("---")
        return open_blocks or ends_incomplete

    def _auto_save(self) -> None:
        """Auto-save current agent session."""
        if not self.conversation:
            return
        try:
            messages = [
                {"role": m.role, "content": m.content, "timestamp": m.timestamp}
                for m in self.conversation.messages
                if m.role != "system"
            ]
            findings = [f.to_dict() for f in self.findings]
            self.memory.auto_save_agent(
                session_id=self.session_id,
                messages=messages,
                target=self.target,
                findings=findings,
            )
        except Exception:
            pass

    def run_command(self, command: str, explanation: str = "") -> ToolResult:
        """Manually execute a command through the agent."""
        tool_name = command.split()[0] if command.split() else "unknown"
        result = self.runner.execute(command, tool_name=tool_name, explanation=explanation)

        step = AgentStep(
            step_num=len(self.steps) + 1,
            action="execute",
            description=explanation or command,
            tool_result=result,
        )
        self.steps.append(step)

        if self.on_step:
            self.on_step(step)

        return result

    def ask(self, question: str) -> str:
        """Ask the agent a question in the context of the current assessment."""
        if not self.conversation:
            self.conversation = create_conversation("agent", self.target)

        self.conversation.add("user", question)
        response = self.engine.chat(
            self.conversation,
            stream=bool(self.on_token),
            on_token=self.on_token,
        )
        self.conversation.add("assistant", response)
        return response

    def stop(self) -> str:
        """Stop the current assessment and generate a summary."""
        self.is_running = False
        if self.conversation:
            self.conversation.add(
                "user",
                "The assessment has been stopped. Please provide a summary of findings so far.",
            )
            response = self.engine.chat(self.conversation, stream=False)
            self.conversation.add("assistant", response)
            return response
        return "No active assessment."

    def get_findings_summary(self) -> str:
        """Get a markdown summary of all findings."""
        if not self.findings:
            return "No findings recorded yet."

        lines = ["# Security Findings\n"]
        by_severity = {}
        for f in self.findings:
            sev = f.severity.value
            by_severity.setdefault(sev, []).append(f)

        stats = {s: len(fs) for s, fs in by_severity.items()}
        lines.append(f"**Total: {len(self.findings)}** | " +
                      " | ".join(f"{s}: {c}" for s, c in stats.items()))
        lines.append("")

        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            findings = by_severity.get(severity, [])
            if not findings:
                continue
            lines.append(f"\n## {severity} ({len(findings)})\n")
            for i, f in enumerate(findings, 1):
                lines.append(f"### {i}. {f.title}")
                lines.append(f"\n{f.description}")
                if f.evidence:
                    lines.append(f"\n**Evidence:**\n```\n{f.evidence}\n```")
                if f.recommendation:
                    lines.append(f"\n**Recommendation:** {f.recommendation}")
                lines.append("")

        return "\n".join(lines)

    def _parse_actions(self, text: str) -> List[Dict[str, Any]]:
        """Extract JSON action blocks from AI response."""
        actions = []
        # Match JSON blocks in code fences or standalone
        patterns = [
            r'```json\s*\n({.*?})\s*\n```',
            r'```\s*\n({.*?"action".*?})\s*\n```',
            r'(\{[^{}]*"action"\s*:\s*"(?:execute|finding|complete|generate_report)"[^{}]*\})',
        ]

        seen_spans: set[tuple[int, int]] = set()
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.DOTALL):
                # Deduplicate overlapping matches from different patterns
                inner_span = match.span(1)
                if inner_span in seen_spans:
                    continue
                # Also skip if this match's inner text is contained within an already-seen span
                skip = False
                for s_start, s_end in seen_spans:
                    if inner_span[0] >= s_start and inner_span[1] <= s_end:
                        skip = True
                        break
                if skip:
                    continue
                try:
                    action = json.loads(match.group(1))
                    if "action" in action:
                        actions.append(action)
                        seen_spans.add(inner_span)
                except (json.JSONDecodeError, IndexError):
                    continue

        return actions

    def _execute_action(self, action: Dict[str, Any]) -> str:
        """Execute a tool action and return formatted result."""
        command = action.get("command", "")
        tool = action.get("tool", command.split()[0] if command else "unknown")
        explanation = action.get("explanation", "")

        result = self.runner.execute(command, tool_name=tool, explanation=explanation)

        step = AgentStep(
            step_num=len(self.steps) + 1,
            action="execute",
            description=explanation,
            tool_result=result,
        )
        self.steps.append(step)

        if self.on_step:
            self.on_step(step)

        status = "SUCCESS" if result.success else "FAILED"
        return (
            f"**[{tool}]** {status} (exit={result.return_code}, {result.duration:.1f}s)\n"
            f"Command: `{command}`\n\n"
            f"```\n{result.output[:5000]}\n```"
        )

    def _record_finding(self, action: Dict[str, Any]) -> None:
        """Record a security finding."""
        try:
            severity = Severity(action.get("severity", "Info"))
        except ValueError:
            severity = Severity.INFO

        finding = Finding(
            title=action.get("title", "Untitled Finding"),
            severity=severity,
            description=action.get("description", ""),
            evidence=action.get("evidence", ""),
            recommendation=action.get("recommendation", ""),
        )

        self.findings.append(finding)

        step = AgentStep(
            step_num=len(self.steps) + 1,
            action="finding",
            description=f"[{severity.value}] {finding.title}",
            finding=finding,
        )
        self.steps.append(step)

        if self.on_step:
            self.on_step(step)

    def _generate_report(self, action: Dict[str, Any]) -> str:
        """Generate a PDF report from current findings."""
        if not HAS_REPORTLAB:
            msg = "PDF report generation unavailable — reportlab not installed."
            step = AgentStep(
                step_num=len(self.steps) + 1,
                action="report",
                description=msg,
            )
            self.steps.append(step)
            if self.on_step:
                self.on_step(step)
            return msg

        findings_data = [f.to_dict() for f in self.findings]
        tool_history = [r.to_dict() for r in self.runner.history]

        # Build compliance data if requested and findings exist
        compliance_data = None
        if action.get("include_compliance", True) and findings_data:
            try:
                from hackbot.core.compliance import ComplianceMapper
                mapper = ComplianceMapper()
                creport = mapper.map_findings(findings_data, target=self.target)
                if creport.mappings:
                    compliance_data = creport.to_dict()
            except Exception:
                pass

        try:
            gen = PDFReportGenerator(include_raw=True)
            path = gen.generate(
                target=self.target,
                findings=findings_data,
                tool_history=tool_history,
                scope=self.scope,
                summary="",
                start_time=self.steps[0].timestamp if self.steps else 0,
                compliance_data=compliance_data,
            )

            step = AgentStep(
                step_num=len(self.steps) + 1,
                action="report",
                description=f"PDF report saved: {path}",
            )
            self.steps.append(step)
            if self.on_step:
                self.on_step(step)

            return f"**[Report]** PDF report generated successfully.\nSaved to: `{path}`"

        except Exception as e:
            msg = f"Report generation failed: {e}"
            step = AgentStep(
                step_num=len(self.steps) + 1,
                action="report",
                description=msg,
            )
            self.steps.append(step)
            if self.on_step:
                self.on_step(step)
            return msg

    def save_assessment(self) -> Path:
        """Save the full assessment data."""
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"assessment_{self.target.replace('/', '_')}_{ts}.json"

        data = {
            "target": self.target,
            "scope": self.scope,
            "timestamp": time.time(),
            "steps": len(self.steps),
            "findings": [f.to_dict() for f in self.findings],
            "tool_history": [r.to_dict() for r in self.runner.history],
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        return path
