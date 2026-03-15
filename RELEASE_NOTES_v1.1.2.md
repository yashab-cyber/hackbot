## HackBot v1.1.2

### Highlights
- Fixed tool validation for `sudo -n ...` commands by correctly resolving the real executable after sudo flags.
- Added loop-guard protection in Agent mode to stop repeated identical failing command retries.
- Improved Kali detection of `thc-ipv6` by supporting alias binaries (for example `alive6`).
- Enhanced report outputs (HTML/Markdown/JSON/PDF) with:
  - **4. List of Commands Executed** (including whether sudo was used)
  - **5. Technical Annex (Agent Output)**
- Improved GUI startup diagnostics for missing native backends and fallback guidance.
- Added root/sudo GUI launch guard with clear remediation instructions.

### Documentation
- Added Plugin Creation Guide and linked it in manual index.
- Updated plugin path documentation to `~/.config/hackbot/plugins/` for consistency with runtime behavior.
- Expanded GUI troubleshooting guidance for Qt/GTK backend dependencies and venv notes.

### Tests
- Added regression coverage for sudo option parsing and alias tool resolution.
- Added report normalization checks for sudo markers and technical annex output.

### Full Changelog
- Compare: https://github.com/yashab-cyber/hackbot/compare/v1.1.1...v1.1.2
