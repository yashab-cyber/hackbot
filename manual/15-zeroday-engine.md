# 15. Zero-Day Discovery Engine

HackBot's Zero-Day Discovery Engine is a proactive vulnerability research module that goes beyond known CVE scanning. It uses response anomaly detection, intelligent fuzzing, exploit chain analysis, and version gap analysis to identify undisclosed vulnerabilities.

---

## Overview

The Zero-Day Engine is integrated directly into Agent Mode and operates at three levels:

1. **Passive Analysis** — Every tool output is automatically scanned for anomaly signals
2. **Active Testing** — The AI agent can invoke smart fuzzing against discovered endpoints
3. **Strategic Analysis** — Findings are combined into exploit chains for maximum impact assessment

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Agent Mode                             │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Tool Run │──│ Auto-Enrich  │──│  AI Decision Loop │  │
│  │ (nmap,   │  │ (anomaly     │  │  (next action)    │  │
│  │  nikto)  │  │  detection)  │  │                   │  │
│  └──────────┘  └──────────────┘  └───────────────────┘  │
│                        │                    │            │
│                        ▼                    ▼            │
│              ┌─────────────────┐  ┌──────────────────┐  │
│              │ ZeroDayEngine   │  │ Agent Actions     │  │
│              │ • analyze()     │  │ • fuzz            │  │
│              │ • fuzz()        │  │ • analyze_anomaly │  │
│              │ • chain()       │  │ • chain_exploits  │  │
│              │ • version_gap() │  │                   │  │
│              └─────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## Response Anomaly Detection

Every tool execution output is automatically analyzed for signals that indicate exploitable conditions.

### Detection Categories

| Category | Severity | Patterns | What It Detects |
|----------|----------|----------|-----------------|
| `stack_trace` | High | 9 | Python, Java, PHP, .NET, Node.js, Go stack traces, panics, segfaults |
| `error_leak` | Medium | 8 | SQL syntax errors, database error codes, PDO/SQLSTATE, Oracle errors |
| `path_disclosure` | Medium | 4 | Unix/Windows file paths, web server DocumentRoot, Java WEB-INF paths |
| `debug_info` | High | 6 | Debug headers, phpinfo, Werkzeug/Django debugger, environment variables |
| `memory_address` | Critical | 4 | Memory address leaks (ASLR bypass), ASAN/sanitizer output, crash signals |
| `auth_leak` | Critical | 5 | API keys, passwords, private keys, AWS credentials, JWT tokens |
| `injection_signal` | High | 5 | Confirmed SQL injection, command injection, /etc/passwd content, XXE |

### Additional Detections

- **Timing anomalies** — Response times >3× the baseline suggest blind injection points
- **HTTP 500 errors** — Internal server errors indicate unhandled exceptions from injected input
- **HTTP 502/503 errors** — Backend crashes suggest potential DoS or overflow conditions
- **Verbose error responses** — Error pages >5KB may leak internal architecture details

### How It Works

```
Tool Output → Pattern Matching (40+ regexes) → Anomaly Signals
                                              ↓
                                    Auto-appended to AI context
                                              ↓
                                    AI receives: "Zero-Day Analysis:
                                    🔴 [memory_address] Memory address leak detected
                                    💡 Memory address leaks defeat ASLR..."
```

The AI then uses these signals to decide on deeper investigation — running targeted fuzzing, analyzing the response further, or recording a finding.

---

## Smart Fuzzing

The AI agent can invoke intelligent fuzzing against specific endpoints and parameters.

### Payload Categories

| Category | Count | Description |
|----------|-------|-------------|
| `buffer_overflow` | 14 | Various buffer sizes (256B–64KB), format strings (%s, %n, %x), null bytes |
| `integer_overflow` | 20 | Boundary values (MAX_INT, MIN_INT, 0, -1), NaN, Infinity, huge numbers |
| `path_traversal` | 14 | `../` sequences, URL encoding bypasses, null bytes, `/proc/self/environ` |
| `template_injection` | 14 | Jinja2 `{{7*7}}`, FreeMarker, Twig, Handlebars, Mako, ERB payloads |
| `ssrf` | 16 | `127.0.0.1`, `[::1]`, cloud metadata (AWS/GCP/Azure), gopher://, dict:// |
| `deserialization` | 7 | PHP `O:8:"stdClass"`, Java serialized, Python pickle, prototype pollution |
| `command_injection` | 20 | `;id`, `$(id)`, `` `id` ``, `${IFS}`, newline injection, various escapes |
| `xss` | 12 | `<script>`, `<svg onload>`, `<img onerror>`, DOM-based, filter bypasses |
| `header_injection` | 6 | CRLF injection, `Set-Cookie` injection, response splitting |
| `xxe` | 4 | XML external entity with `file://`, `http://`, parameter entities |
| `request_smuggling` | 2 | CL.TE and TE.CL smuggling payloads |
| `race_condition` | 2 | Concurrent request markers for TOCTOU testing |

### Agent Usage

The AI invokes fuzzing with:
```json
{
  "action": "fuzz",
  "target_url": "http://target.com/api/search",
  "parameter": "q",
  "categories": ["xss", "command_injection", "template_injection"],
  "explanation": "Search parameter reflects input — testing for injection"
}
```

### Context-Aware Selection

When a context hint is provided, payloads are prioritized:

| Context | Priority Categories |
|---------|--------------------|
| `json_param` | command_injection, template_injection, deserialization, xss |
| `url_path` | path_traversal, command_injection, ssrf |
| `header` | header_injection, ssrf, command_injection |
| `xml_body` | xxe, command_injection, buffer_overflow |

---

## Exploit Chain Analysis

The engine analyzes multiple findings to propose high-impact attack paths that combine low/medium vulnerabilities into critical chains.

### Supported Chains

| Chain | Components | Impact |
|-------|-----------|--------|
| **SSRF → Internal Service → RCE** | SSRF + internal Redis/Docker/etc. | Full internal network access |
| **SQLi → File Write → WebShell** | SQL injection + FILE privilege | Remote code execution |
| **LFI → Log Poisoning → RCE** | Local file inclusion + log access | Code execution without file upload |
| **XSS → CSRF → Account Takeover** | Stored XSS + missing CSRF tokens | Complete application takeover |
| **Info Disclosure → Credential Attack** | User enumeration + weak auth | Unauthorized account access |
| **Open Redirect → Phishing** | Unvalidated redirect | Credential theft via trusted domain |

### Agent Usage

```json
{
  "action": "chain_exploits",
  "explanation": "Analyze current findings for exploit chains"
}
```

The engine returns a formatted report with:
- Attack path steps
- Overall severity and likelihood
- Prerequisites for exploitation
- Recommended mitigations

---

## Version Gap Analysis

Identifies services where the exact detected version has no known CVE, but nearby versions do — flagging them as zero-day candidates.

### How It Works

1. Agent detects service + version (e.g., via nmap)
2. CVE lookup finds known vulnerabilities for the service
3. If the exact version has no CVE but adjacent versions do:
   - Flags as "between_cves" gap
   - Recommends targeted fuzzing focused on vulnerability classes from nearby versions
   - Suggests checking changelogs for security-relevant patches

---

## New Tools Added

The following tools were added to support zero-day discovery:

| Tool | Purpose |
|------|---------|
| `wpscan` | WordPress vulnerability scanner |
| `dalfox` | XSS scanner with fuzzing capabilities |
| `commix` | Command injection exploiter |
| `tplmap` | Server-side template injection detector |
| `ghauri` | Advanced SQL injection tool |
| `arjun` | HTTP parameter discovery |
| `paramspider` | Parameter mining from web archives |
| `katana` | Next-generation web crawler |
| `gau` | URL fetching from web archives |
| `waybackurls` | Wayback Machine URL extractor |
| `crlfuzz` | CRLF injection scanner |
| `jwt_tool` | JWT token analyzer and attacker |
| `xxeinjector` | XXE injection tool |
| `ysoserial` | Java deserialization exploit generator |
| `python3` | Custom exploit script execution |
| `ruby` | Metasploit modules and Ruby scripts |
| `perl` | Legacy exploit script execution |
| `php` | PHP exploit script execution |
| `gcc` | Compiling C exploits |
| `go` | Go-based security tools |

---

## Module: `hackbot.core.zeroday`

### Classes

| Class | Description |
|-------|-------------|
| `ZeroDayEngine` | Main engine class with all analysis methods |
| `AnomalySignal` | Detected anomaly with category, severity, evidence, exploit potential |
| `ExploitChain` | Proposed exploit chain with steps, impact, and mitigations |
| `VersionGapResult` | Version gap analysis result |
| `FuzzResult` | Individual fuzz test result |

### Key Methods

| Method | Description |
|--------|-------------|
| `analyze_response()` | Analyze HTTP response for anomaly signals |
| `get_fuzz_payloads()` | Get smart fuzz payloads by category and context |
| `build_exploit_chains()` | Build exploit chains from findings list |
| `analyze_version_gap()` | Check if a service version falls in a CVE gap |
| `enrich_tool_output()` | Auto-analyze tool output for zero-day signals |
| `get_payload_categories()` | List all available fuzz categories with counts |
| `format_chains_report()` | Format exploit chains as markdown |
| `format_anomalies_report()` | Format anomaly signals as markdown |

---

Next: [Getting Started →](01-getting-started.md) · [Intelligence Modules →](05-intelligence-modules.md) · [Modes →](04-modes.md)
