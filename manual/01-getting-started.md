# 1. Getting Started

## Installation

### One-Line Installer (Recommended)

**Linux / macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/yashab-cyber/hackbot/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yashab-cyber/hackbot/main/install.bat" -OutFile install.bat; .\install.bat
```

### pip Install

```bash
# CLI only
pip install "hackbot @ git+https://github.com/yashab-cyber/hackbot.git"

# CLI + GUI
pip install "hackbot[gui] @ git+https://github.com/yashab-cyber/hackbot.git"

# Everything (CLI + GUI + PDF reports + all optional deps)
pip install "hackbot[all] @ git+https://github.com/yashab-cyber/hackbot.git"
```

### From Source (Developer Mode)

```bash
git clone https://github.com/yashab-cyber/hackbot.git
cd hackbot
pip install -e ".[all,dev]"
```

### Docker

```bash
docker pull ghcr.io/yashab-cyber/hackbot:latest
docker run -it --rm -e HACKBOT_API_KEY=your-key ghcr.io/yashab-cyber/hackbot
```

---

## First Run

```bash
hackbot
```

This launches the interactive REPL with the HackBot banner showing version, author, and links.

---

## Quick Setup

Set your API key and optional provider/model in one command:

```bash
hackbot setup YOUR_API_KEY --provider openai --model gpt-4o
```

Or inside the interactive REPL:

```
/key YOUR_API_KEY
/provider openai
/model gpt-4o
```

The key is **validated immediately** against the provider's API. If invalid, you'll see an error.

---

## Verify Installation

```bash
# Check version
hackbot --version

# Check available security tools
hackbot tools

# Show config
hackbot config
```

---

## Launch Modes

| Command | What it does |
|---------|-------------|
| `hackbot` | Interactive REPL (default) |
| `hackbot chat` | Jump straight to Chat mode |
| `hackbot agent 10.0.0.1` | Start Agent mode against a target |
| `hackbot plan example.com` | Generate a pentest plan |
| `hackbot gui` | Launch the desktop GUI |
| `hackbot tools` | List installed security tools |
| `hackbot config` | Show current config |

---

## Directory Structure

HackBot stores its data in platform-appropriate directories:

| Purpose | Path |
|---------|------|
| Config file | `~/.config/hackbot/config.yaml` |
| Sessions | `~/.local/share/hackbot/sessions/` |
| Reports | `~/.local/share/hackbot/reports/` |
| Logs | `~/.local/share/hackbot/logs/` |
| Plugins | `~/.local/share/hackbot/plugins/` |
| Campaigns | `~/.local/share/hackbot/campaigns/` |

---

Next: [CLI Reference →](02-cli-reference.md)
