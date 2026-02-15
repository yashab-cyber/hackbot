"""Tests for HackBot AI Engine."""

import pytest

from hackbot.core.engine import (
    AIEngine,
    Conversation,
    Message,
    create_conversation,
    SYSTEM_PROMPT_CHAT,
    SYSTEM_PROMPT_AGENT,
    SYSTEM_PROMPT_PLAN,
)
from hackbot.config import AIConfig


def test_message_creation():
    """Test Message dataclass."""
    msg = Message(role="user", content="test question")
    assert msg.role == "user"
    assert msg.content == "test question"
    assert msg.timestamp > 0

    api = msg.to_api()
    assert api["role"] == "user"
    assert api["content"] == "test question"


def test_conversation_creation():
    """Test Conversation basics."""
    conv = Conversation()
    conv.add("system", "You are a bot")
    conv.add("user", "Hello")
    conv.add("assistant", "Hi there")

    assert len(conv.messages) == 3
    api = conv.to_api_messages()
    assert len(api) == 3
    assert api[0]["role"] == "system"


def test_conversation_clear():
    """Test that clear preserves system messages."""
    conv = Conversation()
    conv.add("system", "System prompt")
    conv.add("user", "Hello")
    conv.add("assistant", "Hi")

    conv.clear()
    assert len(conv.messages) == 1
    assert conv.messages[0].role == "system"


def test_create_conversation_chat():
    """Test chat mode conversation creation."""
    conv = create_conversation("chat")
    assert conv.mode == "chat"
    assert len(conv.messages) == 1
    assert conv.messages[0].role == "system"
    assert "HackBot" in conv.messages[0].content


def test_create_conversation_agent():
    """Test agent mode conversation creation."""
    conv = create_conversation("agent", target="192.168.1.1")
    assert conv.mode == "agent"
    assert conv.target == "192.168.1.1"
    assert "192.168.1.1" in conv.messages[0].content


def test_create_conversation_plan():
    """Test plan mode conversation creation."""
    conv = create_conversation("plan")
    assert conv.mode == "plan"


def test_ai_engine_not_configured():
    """Test engine reports unconfigured state."""
    cfg = AIConfig(api_key="")
    engine = AIEngine(cfg)
    assert not engine.is_configured()


def test_ai_engine_configured():
    """Test engine reports configured state."""
    cfg = AIConfig(api_key="test-key")
    engine = AIEngine(cfg)
    assert engine.is_configured()


def test_system_prompts_exist():
    """Test system prompts are non-empty."""
    assert len(SYSTEM_PROMPT_CHAT) > 100
    assert len(SYSTEM_PROMPT_AGENT) > 100
    assert len(SYSTEM_PROMPT_PLAN) > 100
