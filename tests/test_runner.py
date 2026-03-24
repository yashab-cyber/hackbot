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


def test_sudo_mode_disabled():
    """Test that sudo_mode=False does not modify commands."""
    r = ToolRunner(
        allowed_tools=["echo"],
        timeout=10,
        safe_mode=False,
        sudo_mode=False,
    )
    assert r._apply_sudo("echo hello") == "echo hello"


def test_sudo_mode_enabled():
    """Test that sudo_mode=True prepends sudo -n (non-interactive) to commands."""
    r = ToolRunner(
        allowed_tools=["echo"],
        timeout=10,
        safe_mode=False,
        sudo_mode=True,
    )
    if platform.system() != "Windows":
        # Without password: uses sudo -n (non-interactive, fails if password needed)
        assert r._apply_sudo("echo hello") == "sudo -n echo hello"
        # Should not double-prefix
        assert r._apply_sudo("sudo echo hello") == "sudo echo hello"

    # With password: uses sudo -S (reads password from stdin)
    r2 = ToolRunner(
        allowed_tools=["echo"],
        timeout=10,
        safe_mode=False,
        sudo_mode=True,
        sudo_password="secret",
    )
    if platform.system() != "Windows":
        assert r2._apply_sudo("echo hello") == "sudo -S echo hello"
        assert r2._apply_sudo("sudo echo hello") == "sudo echo hello"
        assert r2._feed_sudo_password() == "secret\n"

    # Password not fed when sudo_mode off
    r3 = ToolRunner(
        allowed_tools=["echo"],
        timeout=10,
        safe_mode=False,
        sudo_mode=False,
        sudo_password="secret",
    )
    assert r3._apply_sudo("echo hello") == "echo hello"


def test_check_sudo_not_needed():
    """check_sudo returns OK when sudo_mode is off."""
    r = ToolRunner(allowed_tools=["echo"], timeout=10, safe_mode=False, sudo_mode=False)
    ok, msg = r.check_sudo()
    assert ok
    assert "not required" in msg


def test_check_sudo_caches_result():
    """check_sudo only validates once per runner lifetime."""
    r = ToolRunner(allowed_tools=["echo"], timeout=10, safe_mode=False, sudo_mode=True)
    r._sudo_validated = True  # Simulate prior success
    ok, msg = r.check_sudo()
    assert ok
    assert "already validated" in msg


def test_validate_command_with_sudo_prefix(runner):
    """Test that validate_command handles sudo-prefixed commands correctly."""
    is_safe, reason = runner.validate_command("sudo nmap -sV target")
    assert is_safe
    assert reason == "OK"


def test_validate_command_with_sudo_flag_prefix(runner):
    """sudo flags like -n should not be treated as the executable."""
    is_safe, reason = runner.validate_command("sudo -n nmap -sV target")
    assert is_safe
    assert reason == "OK"


def test_validate_command_with_sudo_end_of_options(runner):
    """sudo '--' end-of-options marker should still resolve the real tool."""
    is_safe, reason = runner.validate_command("sudo -- nmap -sV target")
    assert is_safe
    assert reason == "OK"


def test_validate_command_with_backticks_and_prompt(runner):
    """Backticks and shell prompt prefixes should not break validation."""
    is_safe, reason = runner.validate_command("`$ nmap -sV 127.0.0.1`")
    assert is_safe
    assert reason == "OK"


def test_tool_allowed_case_insensitive():
    """Allowed tool checks should be case-insensitive."""
    r = ToolRunner(allowed_tools=["nmap", "curl"], timeout=10)
    assert r.is_tool_allowed("NMAP")
    assert r.is_tool_allowed("nmap")


def test_tool_allowed_via_resolved_alias(monkeypatch):
    """Alias binary (alive6) should be allowed when thc-ipv6 is whitelisted."""
    r = ToolRunner(allowed_tools=["thc-ipv6"], timeout=10)

    def fake_resolve(tool: str):
        if tool == "thc-ipv6":
            return "/usr/bin/alive6"
        return None

    monkeypatch.setattr("hackbot.core.runner.resolve_tool_path", fake_resolve)
    assert r.is_tool_allowed("alive6")


# ── New tests for double-sudo, malformed commands, and sudo stripping ──


def test_validate_double_sudo_command(runner):
    """Double-sudo commands should be normalized and the real tool extracted."""
    is_safe, reason = runner.validate_command("sudo -n nmap -sV 192.168.1.1")
    assert is_safe
    assert reason == "OK"


def test_validate_nested_sudo(runner):
    """Nested sudo (sudo -n sudo -n nmap) should resolve to the real tool."""
    is_safe, reason = runner.validate_command("sudo -n sudo -n nmap -sV target")
    assert is_safe
    assert reason == "OK"


def test_validate_malformed_flags_only():
    """Command with only flags and no tool binary should be rejected."""
    r = ToolRunner(allowed_tools=["nmap", "dnsrecon"], timeout=10)
    is_safe, reason = r.validate_command("--target 192.168.1.1 --output json")
    assert not is_safe


def test_strip_sudo_prefix():
    """_strip_sudo_prefix should remove sudo and its flags."""
    assert ToolRunner._strip_sudo_prefix("sudo -n nmap -sV target") == "nmap -sV target"
    assert ToolRunner._strip_sudo_prefix("sudo -S nmap 10.0.0.1") == "nmap 10.0.0.1"
    assert ToolRunner._strip_sudo_prefix("sudo nmap 10.0.0.1") == "nmap 10.0.0.1"
    assert ToolRunner._strip_sudo_prefix("sudo -n -u root nmap 10.0.0.1") == "nmap 10.0.0.1"
    assert ToolRunner._strip_sudo_prefix("nmap 10.0.0.1") == "nmap 10.0.0.1"  # no-op
    assert ToolRunner._strip_sudo_prefix("sudo -- nmap 10.0.0.1") == "nmap 10.0.0.1"


def test_normalize_strips_sudo(runner):
    """_normalize_command should strip AI-generated sudo prefix."""
    assert runner._normalize_command("sudo -n nmap -sV 10.0.0.1") == "nmap -sV 10.0.0.1"
    assert runner._normalize_command("sudo -S dnsrecon -d example.com") == "dnsrecon -d example.com"


def test_validate_sudo_only_no_tool():
    """sudo with only flags and no actual tool should be rejected."""
    r = ToolRunner(allowed_tools=["nmap"], timeout=10)
    is_safe, reason = r.validate_command("sudo -n")
    assert not is_safe
