"""Bounded lookups against official public vulnerability advisory sources."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

_USER_AGENT = "ZeroForge/0.1"
_GITHUB_ECOSYSTEMS = {
    "actions": "actions",
    "composer": "composer",
    "crates.io": "rust",
    "erlang": "erlang",
    "go": "go",
    "hex": "erlang",
    "maven": "maven",
    "npm": "npm",
    "nuget": "nuget",
    "other": "other",
    "pip": "pip",
    "pub": "pub",
    "pypi": "pip",
    "rubygems": "rubygems",
    "rust": "rust",
    "swift": "swift",
}


def _bounded_limit(max_results: int) -> int:
    if not 1 <= max_results <= 100:
        raise ValueError("max_results must be between 1 and 100")
    return max_results


def _bounded_timeout(timeout: int) -> int:
    if not 1 <= timeout <= 60:
        raise ValueError("timeout must be between 1 and 60 seconds")
    return timeout


def _request_json(
    url: str,
    *,
    timeout: int,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> Any:
    request_headers = {
        "Accept": "application/json",
        "User-Agent": _USER_AGENT,
        **(headers or {}),
    }
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=request_headers)
    with urllib.request.urlopen(request, timeout=_bounded_timeout(timeout)) as response:
        return json.loads(response.read().decode("utf-8"))


def _string_list(value: Any, *, limit: int = 100) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value[:limit] if isinstance(item, (str, int, float))]


def _osv_record(vulnerability: dict[str, Any]) -> dict[str, Any]:
    affected_packages: list[dict[str, Any]] = []
    for affected in vulnerability.get("affected", [])[:20]:
        if not isinstance(affected, dict):
            continue
        package_value = affected.get("package")
        package: dict[str, Any] = package_value if isinstance(package_value, dict) else {}
        affected_packages.append(
            {
                "ecosystem": str(package.get("ecosystem", "")),
                "name": str(package.get("name", "")),
                "purl": str(package.get("purl", "")),
                "ranges": affected.get("ranges", [])[:20]
                if isinstance(affected.get("ranges"), list)
                else [],
                "versions": _string_list(affected.get("versions"), limit=100),
            }
        )

    database_specific = vulnerability.get("database_specific")
    if not isinstance(database_specific, dict):
        database_specific = {}
    references = vulnerability.get("references")
    if not isinstance(references, list):
        references = []

    advisory_id = str(vulnerability.get("id", ""))
    return {
        "source": "osv",
        "advisory_id": advisory_id,
        "aliases": _string_list(vulnerability.get("aliases")),
        "summary": str(vulnerability.get("summary", "")),
        "details": str(vulnerability.get("details", "")),
        "severity": "",
        "cwes": _string_list(database_specific.get("cwe_ids")),
        "affected_packages": affected_packages,
        "vulnerable_functions": [],
        "references": [
            str(item.get("url", ""))
            for item in references[:100]
            if isinstance(item, dict) and item.get("url")
        ],
        "published": str(vulnerability.get("published", "")),
        "modified": str(vulnerability.get("modified", "")),
        "source_url": f"https://osv.dev/vulnerability/{advisory_id}" if advisory_id else "",
        "exploited_in_wild": None,
    }


def osv_query(
    package_name: str,
    ecosystem: str,
    version: str = "",
    max_results: int = 10,
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """Query OSV for known vulnerabilities affecting one package or package version."""

    package_name = package_name.strip()
    ecosystem = ecosystem.strip()
    if not package_name or not ecosystem:
        raise ValueError("package_name and ecosystem are required")

    payload: dict[str, Any] = {
        "package": {"name": package_name, "ecosystem": ecosystem},
    }
    if version.strip():
        payload["version"] = version.strip()

    data = _request_json(OSV_QUERY_URL, timeout=timeout, payload=payload)
    vulnerabilities = data.get("vulns", []) if isinstance(data, dict) else []
    if not isinstance(vulnerabilities, list):
        return []
    limit = _bounded_limit(max_results)
    return [
        _osv_record(item)
        for item in vulnerabilities[:limit]
        if isinstance(item, dict)
    ]


def _github_record(advisory: dict[str, Any]) -> dict[str, Any]:
    identifiers = advisory.get("identifiers")
    if not isinstance(identifiers, list):
        identifiers = []
    vulnerabilities = advisory.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        vulnerabilities = []
    cwes = advisory.get("cwes")
    if not isinstance(cwes, list):
        cwes = []

    affected_packages: list[dict[str, Any]] = []
    vulnerable_functions: list[str] = []
    for vulnerability in vulnerabilities[:50]:
        if not isinstance(vulnerability, dict):
            continue
        package_value = vulnerability.get("package")
        package: dict[str, Any] = package_value if isinstance(package_value, dict) else {}
        affected_packages.append(
            {
                "ecosystem": str(package.get("ecosystem", "")),
                "name": str(package.get("name", "")),
                "vulnerable_version_range": str(
                    vulnerability.get("vulnerable_version_range", "")
                ),
                "first_patched_version": str(
                    vulnerability.get("first_patched_version", "") or ""
                ),
            }
        )
        vulnerable_functions.extend(
            _string_list(vulnerability.get("vulnerable_functions"), limit=100)
        )

    advisory_id = str(advisory.get("ghsa_id", ""))
    aliases = [
        str(identifier.get("value", ""))
        for identifier in identifiers[:100]
        if isinstance(identifier, dict)
        and identifier.get("value")
        and identifier.get("value") != advisory_id
    ]
    return {
        "source": "github_advisory",
        "advisory_id": advisory_id,
        "aliases": aliases,
        "summary": str(advisory.get("summary", "")),
        "details": str(advisory.get("description", "")),
        "severity": str(advisory.get("severity", "")),
        "cwes": [
            str(item.get("cwe_id", ""))
            for item in cwes[:50]
            if isinstance(item, dict) and item.get("cwe_id")
        ],
        "affected_packages": affected_packages,
        "vulnerable_functions": list(dict.fromkeys(vulnerable_functions)),
        "references": _string_list(advisory.get("references"), limit=100),
        "published": str(advisory.get("published_at", "")),
        "modified": str(advisory.get("updated_at", "")),
        "source_url": str(advisory.get("html_url", "")),
        "exploited_in_wild": None,
    }


def github_advisory_search(
    cve_ids: list[str],
    ghsa_ids: list[str],
    package_name: str = "",
    ecosystem: str = "",
    version: str = "",
    max_results: int = 10,
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """Search GitHub's public global advisory database using explicit seed filters."""

    queries: list[dict[str, str]] = []
    queries.extend({"cve_id": value.strip().upper()} for value in cve_ids if value.strip())
    queries.extend({"ghsa_id": value.strip().upper()} for value in ghsa_ids if value.strip())

    package_name = package_name.strip()
    github_ecosystem = _GITHUB_ECOSYSTEMS.get(ecosystem.strip().lower(), "")
    version = version.strip()
    if package_name:
        package_query = package_name if not version else f"{package_name}@{version}"
        query = {"affects": package_query}
        if github_ecosystem:
            query["ecosystem"] = github_ecosystem
        queries.append(query)

    if not queries:
        raise ValueError("at least one CVE, GHSA, or package filter is required")

    limit = _bounded_limit(max_results)
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    for query in queries:
        params = urllib.parse.urlencode({**query, "per_page": limit})
        data = _request_json(
            f"{GITHUB_ADVISORIES_URL}?{params}",
            timeout=timeout,
            headers=headers,
        )
        advisories = data if isinstance(data, list) else []
        for advisory in advisories:
            if not isinstance(advisory, dict):
                continue
            record = _github_record(advisory)
            key = record["advisory_id"] or "|".join(record["aliases"])
            if not key or key in seen:
                continue
            seen.add(key)
            records.append(record)
            if len(records) >= limit:
                return records
    return records


def cisa_kev_lookup(
    cve_ids: list[str],
    max_results: int = 50,
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """Return CISA KEV entries for the supplied CVE identifiers."""

    normalized = {value.strip().upper() for value in cve_ids if value.strip()}
    if not normalized:
        return []

    data = _request_json(CISA_KEV_URL, timeout=timeout)
    vulnerabilities = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    if not isinstance(vulnerabilities, list):
        return []

    results: list[dict[str, Any]] = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        cve_id = str(vulnerability.get("cveID", "")).upper()
        if cve_id not in normalized:
            continue
        results.append(
            {
                "cve_id": cve_id,
                "vendor_project": str(vulnerability.get("vendorProject", "")),
                "product": str(vulnerability.get("product", "")),
                "vulnerability_name": str(
                    vulnerability.get("vulnerabilityName", "")
                ),
                "date_added": str(vulnerability.get("dateAdded", "")),
                "short_description": str(
                    vulnerability.get("shortDescription", "")
                ),
                "required_action": str(vulnerability.get("requiredAction", "")),
                "known_ransomware_campaign_use": str(
                    vulnerability.get("knownRansomwareCampaignUse", "")
                ),
                "notes": str(vulnerability.get("notes", "")),
            }
        )
        if len(results) >= _bounded_limit(max_results):
            break
    return results
