## HackBot v1.2.1

### Highlights
- 🚀 **Agent Execution Logging & Replay System** — Complete visibility into AI actions.
  - Transparent tracking: Agent reasoning and thoughts are explicitly captured before JSON tool outputs.
  - Persistent storage: `execution_log.json` and `execution_log.txt` automatically exported to your sessions/reports folder.
- 🖥️ **Live Output Panel Redesign** — Real-time tracking of AI workflows:
  - Beautiful 3-pane layout during active assessments.
  - Left Pane: Chronological execution steps and tool statuses.
  - Right Pane: Emulated terminal rendering `stdout`/`stderr` securely.
  - Bottom Pane: Monitored AI reasoning and conversational thought-streams.
- ⏪ **Interactive Replay Mode** — Rewind and review past sessions:
  - Dedicated player accessible from the "Sessions" tab.
  - Full playback controls: Play, Pause, Next Step, Previous Step, and 1x-10x Speed Slider.
  - Reconstructs accurate tool execution history dynamically.
- 📄 **Enhanced PDF Reports** — Fully auditable penetration testing trails:
  - Appends `6. Agent Execution Log` to all generated PDFs mapping chronological thoughts + logs for clients and debriefings.

### Tests
- Execution loop and real-time streaming mechanisms thoroughly verified.
- Playback consistency verified for complex, multi-round agent interactions.

### Full Changelog
- Compare: https://github.com/yashab-cyber/hackbot/compare/v1.2.0...v1.2.1
