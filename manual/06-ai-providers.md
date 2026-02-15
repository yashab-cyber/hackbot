# 6. AI Providers

HackBot supports **10 AI providers** out of the box. All providers use the OpenAI-compatible API format.

---

## Switching Providers

### CLI
```
/provider openai                     # Switch to OpenAI
/provider anthropic                  # Switch to Anthropic
/providers                           # List all providers
/models                              # List models for current provider
/models groq                         # List models for a specific provider
/key YOUR_API_KEY                    # Set API key (validates immediately)
```

### Terminal
```bash
hackbot setup YOUR_API_KEY --provider anthropic --model claude-sonnet-4-20250514
```

### GUI
Use the **Settings** panel — select provider from dropdown, pick a model, enter your API key, and click Validate.

---

## Provider Reference

### 1. OpenAI

| Field | Value |
|-------|-------|
| ID | `openai` |
| Base URL | `https://api.openai.com/v1` |
| Env Variable | `OPENAI_API_KEY` |

**Models:**
| Model | Description |
|-------|-------------|
| `gpt-5.2` | Latest GPT-5 series |
| `gpt-5.1` | GPT-5.1 |
| `gpt-5.2-codex` | Code-focused GPT-5 |
| `gpt-5.2-codex-mini` | Smaller code model |
| `gpt-4o` | Fast multimodal flagship |
| `gpt-4o-mini` | Cost-effective small model |
| `gpt-4-turbo` | Previous generation turbo |
| `o3-mini` | Reasoning model (mini) |
| `o1` | Reasoning model |

---

### 2. Anthropic (Claude)

| Field | Value |
|-------|-------|
| ID | `anthropic` |
| Base URL | `https://api.anthropic.com/v1` |
| Env Variable | `ANTHROPIC_API_KEY` |

**Models:**
| Model | Description |
|-------|-------------|
| `claude-opus-4.6` | Latest Opus |
| `claude-opus-4.5` | Opus 4.5 |
| `claude-sonnet-4` | Sonnet 4 |
| `claude-opus-4` | Opus 4 |
| `claude-3-7-sonnet` | Claude 3.7 Sonnet |
| `claude-3-5-haiku` | Fast & affordable |

---

### 3. Google Gemini

| Field | Value |
|-------|-------|
| ID | `gemini` |
| Base URL | `https://generativelanguage.googleapis.com/...` |
| Env Variable | `GEMINI_API_KEY` or `GOOGLE_API_KEY` |

**Models:**
| Model | Description |
|-------|-------------|
| `gemini-3-pro` | Latest Gemini 3 Pro |
| `gemini-3-flash-preview` | Gemini 3 Flash preview |
| `gemini-2.5-pro` | Gemini 2.5 Pro |
| `gemini-2.5-flash` | Gemini 2.5 Flash |
| `gemini-2.0-flash` | Gemini 2.0 Flash |

---

### 4. Groq (Ultra-fast Inference)

| Field | Value |
|-------|-------|
| ID | `groq` |
| Base URL | `https://api.groq.com/openai/v1` |
| Env Variable | `GROQ_API_KEY` |

**Models:**
| Model | Description |
|-------|-------------|
| `llama-3.3-70b-versatile` | Llama 3.3 70B |
| `llama-3.1-405b-reasoning` | Llama 3.1 405B |
| `llama-3.1-8b-instant` | Fast 8B model |
| `mixtral-8x7b-32768` | Mixtral MoE |
| `gemma2-9b-it` | Google Gemma 2 |

---

### 5. Mistral AI

| Field | Value |
|-------|-------|
| ID | `mistral` |
| Base URL | `https://api.mistral.ai/v1` |
| Env Variable | `MISTRAL_API_KEY` |

**Models:**
| Model | Description |
|-------|-------------|
| `mistral-large-2` | Latest large model |
| `mistral-large-latest` | Large (latest alias) |
| `mistral-small-latest` | Small fast model |
| `codestral-latest` | Code-focused |
| `open-mistral-nemo` | Open Nemo model |

---

### 6. DeepSeek

| Field | Value |
|-------|-------|
| ID | `deepseek` |
| Base URL | `https://api.deepseek.com/v1` |
| Env Variable | `DEEPSEEK_API_KEY` |

**Models:**
| Model | Description |
|-------|-------------|
| `deepseek-chat` | DeepSeek V3 |
| `deepseek-reasoner` | DeepSeek R1 (reasoning) |

---

### 7. Together AI

| Field | Value |
|-------|-------|
| ID | `together` |
| Base URL | `https://api.together.xyz/v1` |
| Env Variable | `TOGETHER_API_KEY` |

**Models:**
| Model | Description |
|-------|-------------|
| `meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo` | Llama 405B Turbo |
| `meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo` | Llama 70B Turbo |
| `Qwen/Qwen2.5-72B-Instruct-Turbo` | Qwen 2.5 72B |
| `mistralai/Mistral-Large-2-Instruct-2411` | Mistral Large 2 |
| `deepseek-ai/DeepSeek-R1` | DeepSeek R1 |

---

### 8. OpenRouter (Multi-provider Gateway)

| Field | Value |
|-------|-------|
| ID | `openrouter` |
| Base URL | `https://openrouter.ai/api/v1` |
| Env Variable | `OPENROUTER_API_KEY` |

**Models:**
| Model | Description |
|-------|-------------|
| `openai/gpt-5.2` | GPT-5.2 via OpenRouter |
| `openai/gpt-5.1` | GPT-5.1 via OpenRouter |
| `anthropic/claude-opus-4.6` | Claude Opus 4.6 |
| `anthropic/claude-opus-4.5` | Claude Opus 4.5 |
| `google/gemini-3-pro` | Gemini 3 Pro |
| `openai/gpt-4o` | GPT-4o |
| `meta-llama/llama-3.1-405b-instruct` | Llama 405B |
| `deepseek/deepseek-r1` | DeepSeek R1 |
| `mistralai/mistral-large-2` | Mistral Large 2 |

---

### 9. Ollama (Local Models)

| Field | Value |
|-------|-------|
| ID | `ollama` |
| Base URL | `http://localhost:11434/v1` |
| API Key | Not required |

**Models:**
| Model | Description |
|-------|-------------|
| `llama3.1:405b` | Llama 3.1 405B (local) |
| `llama3.1:70b` | Llama 3.1 70B |
| `llama3.2` | Llama 3.2 |
| `mistral` | Mistral 7B |
| `mixtral` | Mixtral MoE |
| `vicuna:13b` | Vicuna 13B |
| `deepseek-r1:14b` | DeepSeek R1 14B |
| `qwen2.5:14b` | Qwen 2.5 14B |
| `glm4:9b` | GLM-4 9B |

> Install Ollama from [ollama.com](https://ollama.com), then `ollama pull llama3.1:70b`.

---

### 10. Local / Custom Endpoint

| Field | Value |
|-------|-------|
| ID | `local` |
| Base URL | `http://localhost:8080/v1` |
| API Key | Not required |

**Models:**
| Model | Description |
|-------|-------------|
| `default` | Uses whatever model is served at the endpoint |

> Use this for any OpenAI-compatible local server (vLLM, text-generation-webui, LocalAI, etc.).
> Override the base URL: `/provider local` then set `base_url` in config.

---

## Environment Variables

You can set API keys via environment variables instead of `/key`:

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
export GEMINI_API_KEY=AIza...
export GROQ_API_KEY=gsk_...
export MISTRAL_API_KEY=...
export DEEPSEEK_API_KEY=sk-...
export TOGETHER_API_KEY=...
export OPENROUTER_API_KEY=sk-or-...

# Or the universal override:
export HACKBOT_API_KEY=your-key
export HACKBOT_PROVIDER=openai
export HACKBOT_MODEL=gpt-4o
```

---

Next: [Reporting →](07-reporting.md)
