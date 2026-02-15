"""
HackBot CVE / Exploit Lookup
=============================
Real-time vulnerability intelligence from NVD, ExploitDB, and other sources.
Supports keyword search, CVE-ID lookup, and automatic service→CVE mapping.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

import requests

# ── Data Models ──────────────────────────────────────────────────────────────


@dataclass
class CVEEntry:
    """Single CVE record."""

    cve_id: str
    description: str
    severity: str = "Unknown"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    published: str = ""
    modified: str = ""
    references: List[str] = field(default_factory=list)
    cpe_matches: List[str] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    exploits: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "published": self.published,
            "modified": self.modified,
            "references": self.references,
            "cpe_matches": self.cpe_matches,
            "weaknesses": self.weaknesses,
            "exploits": [e for e in self.exploits],
        }

    @property
    def severity_color(self) -> str:
        if self.cvss_score >= 9.0:
            return "Critical"
        elif self.cvss_score >= 7.0:
            return "High"
        elif self.cvss_score >= 4.0:
            return "Medium"
        elif self.cvss_score > 0:
            return "Low"
        return "Info"

    def summary(self) -> str:
        desc = self.description[:200] + "..." if len(self.description) > 200 else self.description
        return (
            f"[{self.severity_color}] {self.cve_id} (CVSS {self.cvss_score})\n"
            f"  {desc}"
        )


@dataclass
class ExploitEntry:
    """A known exploit for a vulnerability."""

    title: str
    source: str  # e.g. "ExploitDB", "GitHub", "Metasploit"
    url: str
    cve_id: str = ""
    platform: str = ""
    exploit_type: str = ""
    date: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "title": self.title,
            "source": self.source,
            "url": self.url,
            "cve_id": self.cve_id,
            "platform": self.platform,
            "type": self.exploit_type,
            "date": self.date,
        }


# ── CVE Lookup Engine ────────────────────────────────────────────────────────

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_SEARCH = "https://exploit-db.com/search"
GITHUB_EXPLOIT_SEARCH = "https://api.github.com/search/repositories"

# Rate limit: NVD allows ~5 req/30s without API key, ~50 req/30s with key
_last_nvd_request: float = 0.0
_NVD_RATE_LIMIT = 6.5  # seconds between requests without API key


class CVELookup:
    """CVE and exploit intelligence engine."""

    def __init__(self, nvd_api_key: str = "", timeout: int = 20):
        """
        Args:
            nvd_api_key: Optional NVD API key for higher rate limits.
            timeout: Request timeout in seconds.
        """
        self.nvd_api_key = nvd_api_key
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "HackBot/1.0 CVE-Lookup",
            "Accept": "application/json",
        })
        if nvd_api_key:
            self._session.headers["apiKey"] = nvd_api_key

    # ── NVD Queries ──────────────────────────────────────────────────────

    def _nvd_rate_limit(self) -> None:
        """Enforce NVD rate limiting."""
        global _last_nvd_request
        if not self.nvd_api_key:
            elapsed = time.time() - _last_nvd_request
            if elapsed < _NVD_RATE_LIMIT:
                time.sleep(_NVD_RATE_LIMIT - elapsed)
        _last_nvd_request = time.time()

    def _parse_nvd_item(self, item: Dict[str, Any]) -> CVEEntry:
        """Parse a single NVD CVE item into a CVEEntry."""
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")

        # Description
        descriptions = cve_data.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc and descriptions:
            desc = descriptions[0].get("value", "")

        # CVSS score
        metrics = cve_data.get("metrics", {})
        cvss_score = 0.0
        cvss_vector = ""
        severity = "Unknown"

        # Try CVSS v3.1 first, then v3.0, then v2.0
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version, [])
            if metric_list:
                primary = metric_list[0]
                cvss_data = primary.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity = primary.get("baseSeverity", cvss_data.get("baseSeverity", "Unknown"))
                break

        # Published / Modified
        published = cve_data.get("published", "")[:10]
        modified = cve_data.get("lastModified", "")[:10]

        # References
        refs = []
        for ref in cve_data.get("references", []):
            url = ref.get("url", "")
            if url:
                refs.append(url)

        # CPE matches
        cpe_matches = []
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    if criteria:
                        cpe_matches.append(criteria)

        # Weaknesses (CWE)
        weaknesses = []
        for w in cve_data.get("weaknesses", []):
            for wd in w.get("description", []):
                val = wd.get("value", "")
                if val and val != "NVD-CWE-Other" and val != "NVD-CWE-noinfo":
                    weaknesses.append(val)

        return CVEEntry(
            cve_id=cve_id,
            description=desc,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            published=published,
            modified=modified,
            references=refs[:10],
            cpe_matches=cpe_matches[:20],
            weaknesses=weaknesses,
        )

    def lookup_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """
        Look up a specific CVE by its ID (e.g., CVE-2021-44228).

        Returns:
            CVEEntry or None if not found.
        """
        cve_id = cve_id.strip().upper()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
            return None

        self._nvd_rate_limit()

        try:
            resp = self._session.get(
                NVD_API_BASE,
                params={"cveId": cve_id},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None

            entry = self._parse_nvd_item(vulnerabilities[0])

            # Try to find exploits
            entry.exploits = self._search_exploits_for_cve(cve_id)

            return entry

        except requests.RequestException:
            return None

    def search_cve(
        self,
        keyword: str,
        max_results: int = 20,
        severity: str = "",
    ) -> List[CVEEntry]:
        """
        Search NVD for CVEs matching a keyword.

        Args:
            keyword: Search term (e.g., "Apache 2.4.49", "Log4j", "WordPress")
            max_results: Maximum results to return (capped at 50)
            severity: Filter by severity: CRITICAL, HIGH, MEDIUM, LOW
        """
        keyword = keyword.strip()
        if not keyword:
            return []

        max_results = min(max_results, 50)

        self._nvd_rate_limit()

        params: Dict[str, Any] = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
        }

        if severity:
            severity_upper = severity.upper()
            if severity_upper in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                params["cvssV3Severity"] = severity_upper

        try:
            resp = self._session.get(
                NVD_API_BASE,
                params=params,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()

            results = []
            for item in data.get("vulnerabilities", []):
                entry = self._parse_nvd_item(item)
                results.append(entry)

            # Sort by CVSS score descending
            results.sort(key=lambda e: e.cvss_score, reverse=True)

            return results

        except requests.RequestException:
            return []

    def map_service_to_cves(
        self,
        service: str,
        version: str = "",
        max_results: int = 15,
    ) -> List[CVEEntry]:
        """
        Map a service name + version to known CVEs.
        Useful for auto-mapping nmap results to vulnerabilities.

        Args:
            service: Service name (e.g., "Apache httpd", "OpenSSH", "nginx")
            version: Version string (e.g., "2.4.49", "8.2p1")
            max_results: Max CVEs to return
        """
        query = f"{service} {version}".strip()
        return self.search_cve(query, max_results=max_results)

    def parse_nmap_and_lookup(self, nmap_output: str, max_per_service: int = 5) -> Dict[str, List[CVEEntry]]:
        """
        Parse nmap output and look up CVEs for discovered services.

        Args:
            nmap_output: Raw nmap text output
            max_per_service: Max CVEs per service

        Returns:
            Dict mapping "port/service" to list of CVEs
        """
        results: Dict[str, List[CVEEntry]] = {}

        # Parse nmap output lines for open ports with service info
        # Typical format: 80/tcp   open  http    Apache httpd 2.4.49
        port_pattern = re.compile(
            r"(\d+)/(\w+)\s+open\s+(\S+)\s+(.*)",
            re.IGNORECASE,
        )

        seen_services = set()

        for line in nmap_output.splitlines():
            match = port_pattern.search(line)
            if not match:
                continue

            port = match.group(1)
            proto = match.group(2)
            service = match.group(3)
            banner = match.group(4).strip()

            # Build search query from banner
            query = banner if banner else service
            if query in seen_services:
                continue
            seen_services.add(query)

            key = f"{port}/{proto} {service}"
            if banner:
                key += f" ({banner[:50]})"

            cves = self.search_cve(query, max_results=max_per_service)
            if cves:
                results[key] = cves

        return results

    # ── Exploit Search ───────────────────────────────────────────────────

    def _search_exploits_for_cve(self, cve_id: str) -> List[Dict[str, str]]:
        """Search for known exploits for a CVE from multiple sources."""
        exploits: List[Dict[str, str]] = []

        # GitHub search for PoC repositories
        try:
            resp = self._session.get(
                GITHUB_EXPLOIT_SEARCH,
                params={
                    "q": f"{cve_id} exploit OR poc OR vulnerability",
                    "sort": "stars",
                    "order": "desc",
                    "per_page": 5,
                },
                timeout=self.timeout,
            )
            if resp.ok:
                data = resp.json()
                for repo in data.get("items", [])[:5]:
                    exploits.append({
                        "title": repo.get("full_name", ""),
                        "source": "GitHub",
                        "url": repo.get("html_url", ""),
                        "description": (repo.get("description") or "")[:200],
                        "stars": str(repo.get("stargazers_count", 0)),
                    })
        except requests.RequestException:
            pass

        # ExploitDB reference check via NVD references
        # (ExploitDB API isn't public, but NVD often links to it)

        return exploits

    def search_exploits(self, query: str, max_results: int = 10) -> List[Dict[str, str]]:
        """
        Search for exploits/PoCs on GitHub.

        Args:
            query: Search term (CVE ID, service name, etc.)
            max_results: Max results to return
        """
        exploits: List[Dict[str, str]] = []

        try:
            resp = self._session.get(
                GITHUB_EXPLOIT_SEARCH,
                params={
                    "q": f"{query} exploit OR poc OR vulnerability",
                    "sort": "stars",
                    "order": "desc",
                    "per_page": min(max_results, 20),
                },
                timeout=self.timeout,
            )
            if resp.ok:
                data = resp.json()
                for repo in data.get("items", [])[:max_results]:
                    exploits.append({
                        "title": repo.get("full_name", ""),
                        "source": "GitHub",
                        "url": repo.get("html_url", ""),
                        "description": (repo.get("description") or "")[:200],
                        "stars": str(repo.get("stargazers_count", 0)),
                        "language": repo.get("language") or "",
                    })
        except requests.RequestException:
            pass

        return exploits

    # ── Formatting ───────────────────────────────────────────────────────

    @staticmethod
    def format_cve_report(cves: List[CVEEntry], title: str = "CVE Results") -> str:
        """Format CVEs as a rich markdown report."""
        if not cves:
            return f"## {title}\n\nNo CVEs found."

        lines = [f"## {title}\n", f"**{len(cves)} vulnerabilities found**\n"]
        lines.append("| CVE ID | CVSS | Severity | Description |")
        lines.append("|--------|------|----------|-------------|")

        for cve in cves:
            desc = cve.description[:100] + "..." if len(cve.description) > 100 else cve.description
            desc = desc.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {cve.cve_id} | {cve.cvss_score} | {cve.severity_color} | {desc} |")

        lines.append("")

        # Detailed entries for top findings
        for cve in cves[:5]:
            lines.append(f"### {cve.cve_id} — CVSS {cve.cvss_score} ({cve.severity_color})")
            lines.append(f"\n{cve.description}\n")

            if cve.weaknesses:
                lines.append(f"**Weaknesses:** {', '.join(cve.weaknesses)}")
            if cve.published:
                lines.append(f"**Published:** {cve.published}")
            if cve.references:
                lines.append("\n**References:**")
                for ref in cve.references[:5]:
                    lines.append(f"- {ref}")
            if cve.exploits:
                lines.append("\n**Known Exploits:**")
                for exp in cve.exploits:
                    stars = f" ⭐ {exp['stars']}" if exp.get("stars") else ""
                    lines.append(f"- [{exp['title']}]({exp['url']}){stars}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def format_nmap_cve_report(
        results: Dict[str, List[CVEEntry]],
    ) -> str:
        """Format nmap→CVE mapping as markdown."""
        if not results:
            return "## Nmap CVE Mapping\n\nNo vulnerabilities found for discovered services."

        lines = ["## Nmap Service → CVE Mapping\n"]

        total = sum(len(cves) for cves in results.values())
        lines.append(f"**{total} vulnerabilities** across **{len(results)} services**\n")

        for service, cves in results.items():
            lines.append(f"### 🔓 {service}\n")
            for cve in cves:
                emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}.get(
                    cve.severity_color, "⚪"
                )
                lines.append(
                    f"- {emoji} **{cve.cve_id}** (CVSS {cve.cvss_score}) — "
                    f"{cve.description[:120]}..."
                )
            lines.append("")

        return "\n".join(lines)
