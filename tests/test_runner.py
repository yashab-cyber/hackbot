"""Tests for HackBot Tool Runner."""

import platform
import pytest

from hackbot.core.runner import ToolRunner, ToolResult, BLOCKED_COMMANDS


@pytest.fixture
def runner():
    """Create a tool runner with test configuration."""
    return ToolRunner(
        allowed_tools=["echo", "cat", "ls", "nmap", "python3", "curl", "ping"],
        timeout=10,
        safe_mode=True,
        auto_confirm=False,
    )


def test_tool_validation_allowed(runner):
    """Test that allowed commands pass validation."""
    is_safe, reason = runner.validate_command("echo hello")
    assert is_safe
    assert reason == "OK"


def test_tool_validation_blocked(runner):
    """Test that disallowed tools are blocked."""
    is_safe, reason = runner.validate_command("metasploit some-args")
    assert not is_safe
    assert "not in the allowed list" in reason


def test_blocked_commands(runner):
    """Test that dangerous commands are blocked."""
    for blocked in ["rm -rf /", "mkfs something"]:
        is_safe, reason = runner.validate_command(blocked)
        assert not is_safe, f"Should block: {blocked}"


def test_execute_simple_command(runner):
    """Test executing a simple command."""
    result = runner.execute("echo hackbot_test", tool_name="echo")
    assert result.success
    assert "hackbot_test" in result.stdout
    assert result.return_code == 0
    assert result.duration >= 0


def test_execute_nonexistent_tool(runner):
    """Test executing a nonexistent tool."""
    runner.allowed_tools.append("nonexistent_tool_abc")
    result = runner.execute("nonexistent_tool_abc", tool_name="nonexistent_tool_abc")
    assert not result.success


def test_execute_with_timeout(runner):
    """Test timeout handling."""
    runner.timeout = 2
    if platform.system() != "Windows":
        result = runner.execute("ping -c 100 127.0.0.1", tool_name="ping")
        # Should either timeout or succeed quickly
        assert isinstance(result, ToolResult)


def test_tool_result_output():
    """Test ToolResult output property."""
    result = ToolResult(
        tool="test",
        command="test cmd",
        stdout="hello\n",
        stderr="",
        return_code=0,
        duration=1.0,
        success=True,
    )
    assert "hello" in result.output


def test_tool_result_combined_output():
    """Test ToolResult with both stdout and stderr."""
    result = ToolResult(
        tool="test",
        command="test cmd",
        stdout="output\n",
        stderr="warning\n",
        return_code=0,
        duration=1.0,
        success=True,
    )
    assert "output" in result.output
    assert "warning" in result.output


def test_empty_command(runner):
    """Test empty command handling."""
    is_safe, reason = runner.validate_command("")
    assert not is_safe


def test_history_tracking(runner):
    """Test that execution history is tracked."""
    runner.execute("echo test1", tool_name="echo")
    runner.execute("echo test2", tool_name="echo")
    assert len(runner.history) == 2


def test_get_available_tools(runner):
    """Test tool availability detection."""
    tools = runner.get_available_tools()
    assert isinstance(tools, dict)
    assert "echo" in tools
