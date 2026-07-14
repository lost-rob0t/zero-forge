"""CVE lookup tool using the public NVD API."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"


def cve_lookup(cve_id: str, timeout: int = 15) -> dict[str, Any]:
    """Fetch CVE details from the NVD API.

    Returns a dict with keys: cve_id, description, references, cvss, published.
    Falls back gracefully with empty values on network failure.
    """
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    result: dict[str, Any] = {
        "cve_id": cve_id,
        "description": "",
        "references": [],
        "cvss": "",
        "published": "",
    }

    url = NVD_API_URL.format(cve_id=cve_id)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ZeroForge/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return result
        cve_item = vulns[0].get("cve", {})
        descs = cve_item.get("descriptions", [])
        for d in descs:
            if d.get("lang") == "en":
                result["description"] = d.get("value", "")
                break
        result["references"] = [r.get("url", "") for r in cve_item.get("references", [])]
        metrics = cve_item.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics and metrics[key]:
                result["cvss"] = str(metrics[key][0].get("cvssData", {}).get("baseScore", ""))
                break
        result["published"] = cve_item.get("published", "")
    except Exception:
        pass

    return result
