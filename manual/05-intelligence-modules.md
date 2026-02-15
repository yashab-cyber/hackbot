# 5. Intelligence Modules

HackBot includes 9 built-in intelligence modules that extend beyond basic scanning.

---

## 🛡 CVE / Exploit Lookup

Search CVE vulnerabilities and find exploit proof-of-concepts.

### CLI Usage
```
/cve CVE-2021-44228                  # Lookup specific CVE
/cve log4j                           # Search by keyword
/cve --nmap <paste nmap output>      # Map nmap services to CVEs
```

### Features
- **CVE Lookup**: Fetch full details from NVD (description, severity, CVSS score, references)
- **Keyword Search**: Search NVD by keyword with optional severity filter (up to 15 results)
- **Nmap-to-CVE Mapping**: Parses nmap service output, maps each service to known CVEs (5 per service)
- **Exploit Search**: Find PoC exploits via GitHub

### GUI
Use the **CVE Lookup** panel with 4 tabs: CVE Lookup, Keyword Search, Exploit Search, Nmap to CVE.

---

## 🔍 OSINT Module

Open-source intelligence gathering for domains.

### CLI Usage
```
/osint example.com                  # Full scan (all modules)
/osint example.com --subs           # Subdomains only
/osint example.com --dns            # DNS records only
/osint example.com --whois          # WHOIS data only
/osint example.com --tech           # Technology stack only
/osint example.com --emails         # Email harvesting only
```

### Capabilities
| Module | What it discovers |
|--------|------------------|
| **Subdomains** | Enumerate subdomains using multiple techniques |
| **DNS** | A, AAAA, MX, NS, TXT, SOA, CNAME records |
| **WHOIS** | Registrar, creation/expiry dates, contact info |
| **Tech Stack** | Web server, framework, programming language, CMS |
| **Emails** | Email addresses associated with the domain |

### GUI
Use the **OSINT** panel — enter a domain and pick a scan type. Full scan shows real-time progress via SSE.

---

## 🌐 Network Topology Visualizer

Visualize network structure from scan results.

### CLI Usage
```
/topology                           # Auto-detect from agent scan history
/topology <paste nmap output>       # Parse specific output
```

### Output
- **ASCII network map** — terminal-friendly topology diagram
- **Markdown summary** — host details with ports, services, and states
- **Graph data** — JSON structure for GUI visualization

### GUI
Use the **Topology** panel:
- Paste scan output or click "From Agent" to auto-parse
- View as ASCII, interactive D3.js graph, or markdown

---

## 📋 Compliance Mapping

Map security findings to industry compliance frameworks.

### CLI Usage
```
/compliance                         # Map agent findings to all frameworks
/compliance pci nist                # Map to specific frameworks only
```

### Supported Frameworks

| Framework | Full Name | Controls |
|-----------|-----------|----------|
| `pci` | PCI DSS v4.0 | Payment card security requirements |
| `nist` | NIST 800-53 | Federal information security controls |
| `owasp` | OWASP Top 10 | Web application security risks |
| `iso27001` | ISO/IEC 27001 | Information security management |

### Output
For each finding, shows:
- Mapped control IDs and names
- Control descriptions
- Compliance status
- Framework-specific recommendations

### GUI
Use the **Compliance** panel:
- "From Agent" to auto-map current findings
- Or paste custom findings text
- Filter by framework
- Browse all controls within a framework

---

## 📊 Diff Reports

Compare two assessments to track remediation progress.

### CLI Usage
```
/diff                               # Lists available sessions to compare
/diff session1_id session2_id       # Compare specific sessions
```

### Output Categories
| Category | Meaning |
|----------|---------|
| 🆕 **New** | Findings in the new session that weren't in the old one |
| ✅ **Fixed** | Findings from the old session that are no longer present |
| ⏳ **Persistent** | Findings that exist in both sessions |

### GUI
Use the **Diff Report** panel — select two sessions from dropdowns and click Compare.

---

## 🎯 Multi-Target Campaigns

Manage coordinated assessments across multiple targets.

### CLI Usage
```
/campaign new webapp_audit app1.com app2.com api.internal.com
/campaign start
/campaign status
/campaign next
/campaign findings
/campaign report
```

### Campaign Lifecycle
1. **Create** — define campaign name and targets
2. **Start** — begin assessing first target
3. **Next** — mark current target complete, move to next
4. **Skip** — skip a target with optional reason
5. **Pause/Resume** — temporarily halt
6. **Abort** — cancel entire campaign

### Campaign States
| State | Description |
|-------|-------------|
| `draft` | Created but not started |
| `running` | Active assessment in progress |
| `paused` | Temporarily halted |
| `completed` | All targets assessed |
| `aborted` | Cancelled |

### Target States
| State | Description |
|-------|-------------|
| `pending` | Not yet assessed |
| `running` | Currently being assessed |
| `completed` | Assessment finished |
| `failed` | Assessment failed |
| `skipped` | Skipped by user |

### Intelligence Sharing
Campaign context is shared between targets — findings from one target inform the assessment of the next.

### GUI
Use the **Campaigns** panel — create campaigns, manage targets, track progress, generate aggregate reports.

---

## 🧩 Custom Plugins

Extend HackBot with your own Python tools.

### Plugin Directory
```
~/.local/share/hackbot/plugins/
```

### Creating a Plugin

Create a `.py` file in the plugins directory:

```python
"""
HackBot Plugin: My Custom Scanner
"""

PLUGIN_MANIFEST = {
    "name": "my_scanner",
    "description": "Runs a custom security scan",
    "version": "1.0",
    "category": "scanning",
    "args": [
        {"name": "target", "description": "Target to scan", "required": True},
        {"name": "port", "description": "Port to scan", "required": False, "default": "80"},
    ],
}

def run(target, port="80"):
    """Execute the plugin."""
    # Your code here
    return f"Scanned {target}:{port} — no issues found"
```

### CLI Usage
```
/plugins                  # List all registered plugins
/plugins reload           # Rediscover plugins from disk
/plugins dir              # Show plugins directory path
```

Plugins appear as agent-callable tools and can also be executed directly from the GUI.

### GUI
Use the **Plugins** panel — view, reload, and execute plugins.

---

## 🔧 AI Remediation Engine

Generate fix commands and patches for security findings.

### CLI Usage
```
/remediate                # Rule-based fixes for ALL findings
/remediate #3             # Fix for finding #3 only
/remediate --ai           # AI-enhanced fixes (uses API key)
/remediate #3 --ai        # AI fix for finding #3
```

### Two Modes

| Mode | Speed | Requires API Key | Description |
|------|-------|-----------------|-------------|
| **Rule-based** | Instant | No | ~60 built-in vulnerability patterns |
| **AI-enhanced** | Seconds | Yes | LLM generates tailored fixes |

### Remediation Output
Each fix includes:
- **Summary** — one-liner description
- **Shell commands** — apt install, systemctl, sysctl, iptables, etc.
- **Config patches** — nginx.conf, sshd_config, apache, etc.
- **Code snippets** — Python, PHP, JavaScript, Java, etc.
- **References** — CVE links, CIS benchmarks, OWASP pages

### Priority Levels
| Priority | Action needed |
|----------|--------------|
| `immediate` | Fix now — active exploitation risk |
| `high` | Fix within 24 hours |
| `medium` | Fix within 1 week |
| `low` | Fix in next maintenance window |
| `informational` | Best practice improvement |

### GUI
In the **Agent** panel or **Findings** panel, click "Remediate" for any finding.

---

## 🔌 HTTP Proxy / Traffic Capture

Built-in intercepting proxy for capturing and analyzing web traffic.

### CLI Usage
```
/proxy start 8080         # Start proxy on port 8080
/proxy status             # Show proxy stats
/proxy scope example.com  # Capture only this domain
/proxy traffic 20         # Show last 20 requests
/proxy flags              # Show security-interesting requests
/proxy detail 5           # Full details for request #5
/proxy replay 5           # Replay request #5
/proxy filter login       # Filter traffic containing "login"
/proxy export dump.json   # Export traffic to file
/proxy clear              # Clear captured traffic
/proxy stop               # Stop proxy
```

### Auto-Flagged Patterns
The proxy automatically flags requests matching these patterns:

| Flag | Description |
|------|-------------|
| `auth_token` | Authorization headers, Bearer tokens |
| `cookie` | Cookie headers |
| `credentials` | Username/password in body |
| `error_response` | 4xx/5xx status codes |
| `redirect` | 3xx redirect responses |
| `sensitive_data` | SSN, credit card patterns |
| `sql_pattern` | SQL injection indicators |
| `file_upload` | File upload requests |
| `api_key` | API key parameters |
| `cors_header` | CORS headers |

### Using with Tools
```bash
# Use HackBot proxy with curl
curl -x http://127.0.0.1:8080 http://target.com/api/login

# Use with sqlmap
sqlmap -u "http://target.com/search?q=test" --proxy="http://127.0.0.1:8080"
```

### GUI
Use the **Proxy** panel — start/stop, view traffic table, filter, inspect details, replay requests, export.

---

Next: [AI Providers →](06-ai-providers.md)
