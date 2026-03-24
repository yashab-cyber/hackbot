## HackBot v1.2.2

### Highlights
- 🛡️ **Stable Agent Execution** — Resolved critical command validation issues.
  - Fixed "BLOCKED: Tool is not in the allowed list" errors caused by double-sudo prefixing.
  - Implemented automatic command repair for malformed AI-generated commands.
  - Enhanced tool extraction logic to handle nested sudo and flag-like tokens accurately.
- 🖥️ **UI Reliability Fixes** — Restored Agent execution visibility.
  - Fixed a bug where "EXECUTION STEPS" and "LIVE TERMINAL" panels remained empty during assessments.
  - Corrected SSE streaming event handling in the GUI.
- 🧠 **Improved AI Guidance** — Enhanced system prompts for better autonomy.
  - Updated Agent system instructions with concrete command examples and formatting rules.
  - Explicitly prohibited sudo inclusions in AI-generated command fields for consistent handling.

### Improvements & Bug Fixes
- Fixed normalization ordering in the tool runner (backticks vs. shell prompts).
- Added comprehensive test suite for agent command validation and sudo stripping (6+ new tests).
- Updated internal versioning across all core components.

### Full Changelog
- Compare: https://github.com/yashab-cyber/hackbot/compare/v1.2.1...v1.2.2
