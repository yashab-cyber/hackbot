## HackBot v1.1.1

### New Features
- Added generated script support in Agent Mode with a new script action format.
- Added script persistence in assessment state and auto-save memory.
- Added a new Scripts panel in GUI to view generated scripts.
- Added GUI API endpoint for scripts: /api/agent/scripts.
- Added script inclusion in HTML, Markdown, JSON, and PDF reports.
- Added plugin marketplace button in GUI Plugins panel.
- Added official HackBot website link in GUI sidebar footer.
- Expanded default Kali/security tool allowlist (Metasploit, wireless, recon, sniffing, enum tools, and more).
- Added backward-compatible allowlist migration so existing configs auto-include newly added default tools.
- Added Telegram /tools command for installed, missing, and full tool inventory.
- Enhanced Telegram /config output with allowed tools summary and sample list.

### Bug Fixes
- Fixed second-run tool execution reliability by normalizing fenced/prompt/backticked commands.
- Fixed tool allowlist checks to be case-insensitive and extension-normalized.
- Fixed tool name inference edge cases for malformed/empty commands.
- Fixed report export wiring to always use tool_history (Telegram regression).
- Fixed report output to include explicit Tool + Command in execution logs.
- Hardened agent action parsing so JSON actions are extracted reliably when script content contains braces.
- Fixed report generation paths to include generated scripts in CLI, GUI, and Telegram exports.

### Tests and Docs
- Added/updated tests for runner normalization and case-insensitive tool allowlist behavior.
- Added/updated tests for report normalization and tool log rendering.
- Added/updated tests for config allowlist migration behavior.
- Added/updated tests for Telegram tools command registration and report generation keyword usage.
- Updated configuration manual with expanded default allowed tools list.

### Full Changelog
- Compare: https://github.com/yashab-cyber/hackbot/compare/v1.1.0...v1.1.1
