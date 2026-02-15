"""
HackBot Tool Runner
===================
Executes security tools in a sandboxed subprocess with timeout, logging, and output capture.
Cross-platform compatible (Linux, macOS, Windows).
"""

from __future__ import annotations

import asyncio
import os
import platform
import shlex
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from hackbot.config import LOGS_DIR

# Lazy reference — filled at runtime to avoid circular imports
_plugin_manager = None

def _get_plugin_manager():
    """Lazy-load the plugin manager."""
    global _plugin_manager
    if _plugin_manager is None:
        try:
            from hackbot.core.plugins import get_plugin_manager
            _plugin_manager = get_plugin_manager()
        except Exception:
            pass
    return _plugin_manager


@dataclass
class ToolResult:
    """Result of a tool execution."""
    tool: str
    command: str
    stdout: str
    stderr: str
    return_code: int
    duration: float
    success: bool
    timestamp: float = field(default_factory=time.time)
    truncated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "command": self.command,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.return_code,
            "duration": round(self.duration, 2),
            "success": self.success,
            "timestamp": self.timestamp,
        }

    @property
    def output(self) -> str:
        """Combined stdout + stderr."""
        parts = []
        if self.stdout.strip():
            parts.append(self.stdout.strip())
        if self.stderr.strip():
            parts.append(f"[STDERR]\n{self.stderr.strip()}")
        return "\n".join(parts) if parts else "(no output)"


# Commands that are NEVER allowed (destructive to host system)
BLOCKED_COMMANDS = [
    "rm -rf /",
    "mkfs",
    "dd if=/dev/zero",
    ":(){ :|:& };:",
    "chmod -R 777 /",
    "mv /* /dev/null",
    "> /dev/sda",
    "shutdown",
    "reboot",
    "halt",
    "init 0",
    "init 6",
]

# Dangerous patterns that require confirmation
RISKY_PATTERNS = [
    "rm -rf",
    "rm -r",
    "format",
    "fdisk",
    "mkfs",
    "dd ",
    "exploit",
    "payload",
    "reverse_tcp",
    "meterpreter",
    "chmod 777",
    "wget.*|.*sh",
    "curl.*|.*sh",
    "nc -e",
    "netcat -e",
    "bash -i",
]


class ToolRunner:
    """
    Executes security tools in controlled subprocesses.
    Features:
    - Command validation and safety checks
    - Timeout enforcement
    - Output capture and truncation
    - Execution logging
    - Cross-platform support
    """

    MAX_OUTPUT_SIZE = 100_000  # 100KB max output per command

    def __init__(
        self,
        allowed_tools: List[str],
        timeout: int = 300,
        safe_mode: bool = True,
        auto_confirm: bool = False,
        on_confirm: Optional[Callable[[str, str], bool]] = None,
        on_output: Optional[Callable[[str], None]] = None,
    ):
        self.allowed_tools = allowed_tools
        self.timeout = timeout
        self.safe_mode = safe_mode
        self.auto_confirm = auto_confirm
        self.on_confirm = on_confirm
        self.on_output = on_output
        self.history: List[ToolResult] = []

    def is_tool_available(self, tool: str) -> bool:
        """Check if a tool is installed on the system."""
        return shutil.which(tool) is not None

    def is_tool_allowed(self, tool: str) -> bool:
        """Check if a tool is in the allowed list."""
        return tool in self.allowed_tools

    def validate_command(self, command: str) -> tuple[bool, str]:
        """
        Validate a command for safety.
        Returns (is_safe, reason).
        """
        cmd_lower = command.lower().strip()

        # Plugin commands are always allowed
        if cmd_lower.startswith("hackbot-plugin "):
            return True, "OK"

        # Check blocked commands
        for blocked in BLOCKED_COMMANDS:
            if blocked in cmd_lower:
                return False, f"Blocked command detected: {blocked}"

        # Extract tool name
        parts = shlex.split(command) if platform.system() != "Windows" else command.split()
        if not parts:
            return False, "Empty command"

        tool = os.path.basename(parts[0])

        # Check if tool is allowed
        if not self.is_tool_allowed(tool):
            return False, f"Tool '{tool}' is not in the allowed list"

        # Check risky patterns in safe mode
        if self.safe_mode:
            for pattern in RISKY_PATTERNS:
                if pattern in cmd_lower:
                    return True, f"RISKY: Contains '{pattern}' — requires confirmation"

        return True, "OK"

    def execute(self, command: str, tool_name: str = "", explanation: str = "") -> ToolResult:
        """
        Execute a command synchronously with timeout and output capture.
        """
        # Plugin execution — intercept hackbot-plugin commands
        if command.strip().startswith("hackbot-plugin "):
            return self._execute_plugin(command, tool_name)

        # Validate
        is_safe, reason = self.validate_command(command)

        if not is_safe:
            return ToolResult(
                tool=tool_name or command.split()[0],
                command=command,
                stdout="",
                stderr=f"BLOCKED: {reason}",
                return_code=-1,
                duration=0,
                success=False,
            )

        # Check for risky commands
        if "RISKY" in reason and not self.auto_confirm:
            if self.on_confirm:
                confirmed = self.on_confirm(command, reason)
                if not confirmed:
                    return ToolResult(
                        tool=tool_name or command.split()[0],
                        command=command,
                        stdout="",
                        stderr="User declined execution",
                        return_code=-2,
                        duration=0,
                        success=False,
                    )

        # Execute
        start = time.time()

        try:
            is_windows = platform.system() == "Windows"
            proc = subprocess.Popen(
                command if is_windows else shlex.split(command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=is_windows,
                text=True,
                env=self._get_env(),
            )

            try:
                stdout, stderr = proc.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                self._kill_process(proc)
                stdout, stderr = proc.communicate()
                stderr += f"\n[TIMEOUT after {self.timeout}s]"

            duration = time.time() - start

            # Truncate if needed
            truncated = False
            if len(stdout) > self.MAX_OUTPUT_SIZE:
                stdout = stdout[: self.MAX_OUTPUT_SIZE] + f"\n\n[OUTPUT TRUNCATED at {self.MAX_OUTPUT_SIZE} bytes]"
                truncated = True

            result = ToolResult(
                tool=tool_name or command.split()[0],
                command=command,
                stdout=stdout,
                stderr=stderr,
                return_code=proc.returncode,
                duration=duration,
                success=proc.returncode == 0,
                truncated=truncated,
            )

        except FileNotFoundError:
            duration = time.time() - start
            result = ToolResult(
                tool=tool_name or command.split()[0],
                command=command,
                stdout="",
                stderr=f"Tool not found: {command.split()[0]}",
                return_code=-3,
                duration=duration,
                success=False,
            )
        except Exception as e:
            duration = time.time() - start
            result = ToolResult(
                tool=tool_name or command.split()[0],
                command=command,
                stdout="",
                stderr=f"Execution error: {str(e)}",
                return_code=-4,
                duration=duration,
                success=False,
            )

        # Log and store
        self.history.append(result)
        self._log_execution(result)

        if self.on_output:
            self.on_output(result.output)

        return result

    async def execute_async(self, command: str, tool_name: str = "") -> ToolResult:
        """Execute a command asynchronously."""
        is_safe, reason = self.validate_command(command)
        if not is_safe:
            return ToolResult(
                tool=tool_name or command.split()[0],
                command=command,
                stdout="",
                stderr=f"BLOCKED: {reason}",
                return_code=-1,
                duration=0,
                success=False,
            )

        start = time.time()
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._get_env(),
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout
                )
                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")
            except asyncio.TimeoutError:
                proc.kill()
                stdout, stderr = "", f"[TIMEOUT after {self.timeout}s]"

            duration = time.time() - start

            result = ToolResult(
                tool=tool_name or command.split()[0],
                command=command,
                stdout=stdout,
                stderr=stderr,
                return_code=proc.returncode or 0,
                duration=duration,
                success=(proc.returncode or 0) == 0,
            )
        except Exception as e:
            duration = time.time() - start
            result = ToolResult(
                tool=tool_name or command.split()[0],
                command=command,
                stdout="",
                stderr=f"Execution error: {str(e)}",
                return_code=-4,
                duration=duration,
                success=False,
            )

        self.history.append(result)
        return result

    def _get_env(self) -> Dict[str, str]:
        """Get sanitized environment for subprocess execution."""
        env = os.environ.copy()
        # Remove sensitive vars from subprocess env
        for key in ["HACKBOT_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
            env.pop(key, None)
        return env

    def _kill_process(self, proc: subprocess.Popen) -> None:
        """Cross-platform process killing."""
        try:
            if platform.system() == "Windows":
                proc.kill()
            else:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                time.sleep(1)
                if proc.poll() is None:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except Exception:
                pass

    def _log_execution(self, result: ToolResult) -> None:
        """Log tool execution to disk."""
        try:
            LOGS_DIR.mkdir(parents=True, exist_ok=True)
            log_file = LOGS_DIR / "execution.log"
            with open(log_file, "a") as f:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result.timestamp))
                f.write(
                    f"[{ts}] [{result.tool}] rc={result.return_code} "
                    f"t={result.duration:.1f}s cmd={result.command}\n"
                )
        except Exception:
            pass

    def get_available_tools(self) -> Dict[str, bool]:
        """Get all allowed tools and their availability status."""
        return {tool: self.is_tool_available(tool) for tool in self.allowed_tools}

    def _execute_plugin(self, command: str, tool_name: str = "") -> ToolResult:
        """
        Execute a hackbot-plugin command by delegating to the PluginManager.

        Command format: hackbot-plugin <name> [--arg1 val1 --arg2 val2 ...]
        """
        start = time.time()
        parts = command.strip().split()
        # parts[0] = "hackbot-plugin", parts[1] = plugin_name, rest = --key val pairs
        if len(parts) < 2:
            return ToolResult(
                tool=tool_name or "hackbot-plugin",
                command=command,
                stdout="",
                stderr="Usage: hackbot-plugin <name> [--arg value ...]",
                return_code=-1,
                duration=0,
                success=False,
            )

        plugin_name = parts[1]
        # Parse --key value pairs
        kwargs: Dict[str, str] = {}
        i = 2
        while i < len(parts):
            token = parts[i]
            if token.startswith("--") and i + 1 < len(parts):
                key = token[2:]  # strip --
                kwargs[key] = parts[i + 1]
                i += 2
            else:
                i += 1

        pm = _get_plugin_manager()
        if pm is None:
            duration = time.time() - start
            return ToolResult(
                tool=tool_name or plugin_name,
                command=command,
                stdout="",
                stderr="Plugin system is not available",
                return_code=-1,
                duration=duration,
                success=False,
            )

        result = pm.execute(plugin_name, **kwargs)
        duration = time.time() - start

        tool_result = ToolResult(
            tool=tool_name or plugin_name,
            command=command,
            stdout=result.output if result.success else "",
            stderr=result.error if not result.success else "",
            return_code=0 if result.success else -1,
            duration=duration,
            success=result.success,
        )

        self.history.append(tool_result)
        self._log_execution(tool_result)

        if self.on_output:
            self.on_output(tool_result.output)

        return tool_result
