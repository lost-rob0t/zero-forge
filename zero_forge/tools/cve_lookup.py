"""CVE lookup tool using the public NVD API."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from ..schemas import CveLookupResult, CveLookupStatus

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

_MAX_RETRIES = 3
_RETRY_BACKOFF_BASE = 1.0  # seconds


def _normalize_cve_id(cve_id: str) -> str:
    """Normalize a CVE ID to canonical uppercase format."""
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"
    return cve_id


def _parse_nvd_response(data: dict[str, Any], cve_id: str) -> CveLookupResult:
    """Parse the NVD API JSON response into a CveLookupResult."""
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return CveLookupResult(
            cve_id=cve_id,
            status=CveLookupStatus.NOT_FOUND,
        )
    cve_item = vulns[0].get("cve", {})
    result = CveLookupResult(cve_id=cve_id, status=CveLookupStatus.SUCCESS)

    descs = cve_item.get("descriptions", [])
    for d in descs:
        if d.get("lang") == "en":
            result.description = d.get("value", "")
            break

    result.references = [
        r.get("url", "") for r in cve_item.get("references", [])
    ]

    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            result.cvss = str(
                metrics[key][0].get("cvssData", {}).get("baseScore", "")
            )
            break

    result.published = cve_item.get("published", "")
    return result


def _classify_error(exc: Exception) -> tuple[CveLookupStatus, str, str]:
    """Classify an exception into a status, category, and message."""
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 404:
            return (
                CveLookupStatus.NOT_FOUND,
                "http_404",
                "NVD returned 404 for CVE lookup",
            )
        if exc.code == 429:
            return (
                CveLookupStatus.RETRYABLE_FAILURE,
                "http_429_rate_limit",
                "NVD rate-limited the request",
            )
        if 500 <= exc.code < 600:
            return (
                CveLookupStatus.RETRYABLE_FAILURE,
                f"http_{exc.code}_server_error",
                f"NVD returned HTTP {exc.code}",
            )
        return (
            CveLookupStatus.PERMANENT_FAILURE,
            f"http_{exc.code}",
            f"NVD returned HTTP {exc.code}",
        )
    if isinstance(exc, urllib.error.URLError):
        return (
            CveLookupStatus.RETRYABLE_FAILURE,
            "network_error",
            f"Network error: {exc.reason}",
        )
    if isinstance(exc, TimeoutError):
        return (
            CveLookupStatus.RETRYABLE_FAILURE,
            "timeout",
            "NVD request timed out",
        )
    if isinstance(exc, json.JSONDecodeError):
        return (
            CveLookupStatus.PERMANENT_FAILURE,
            "malformed_json",
            f"NVD returned malformed JSON: {exc}",
        )
    return (
        CveLookupStatus.PERMANENT_FAILURE,
        type(exc).__name__.lower(),
        f"Unexpected error: {exc}",
    )


def _attempt_lookup(cve_id: str, timeout: int) -> CveLookupResult:
    """Make a single NVD API request and return a typed result."""
    url = NVD_API_URL.format(cve_id=cve_id)
    req = urllib.request.Request(
        url, headers={"User-Agent": "ZeroForge/0.1"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return _parse_nvd_response(data, cve_id)
    except Exception as exc:
        status, category, message = _classify_error(exc)
        return CveLookupResult(
            cve_id=cve_id,
            status=status,
            error_category=category,
            error_message=message,
        )


def cve_lookup(cve_id: str, timeout: int = 15) -> dict[str, Any]:
    """Fetch CVE details from the NVD API with bounded retry and backoff.

    Returns a dict with keys: cve_id, description, references, cvss,
    published, status, error_category, error_message.

    Status values: success, not_found, retryable_failure, permanent_failure.
    Retryable failures (network errors, rate limits, server errors) are
    retried up to _MAX_RETRIES times with exponential backoff.
    """
    cve_id = _normalize_cve_id(cve_id)

    for attempt in range(1, _MAX_RETRIES + 1):
        result = _attempt_lookup(cve_id, timeout)
        if result.status in (
            CveLookupStatus.SUCCESS,
            CveLookupStatus.NOT_FOUND,
            CveLookupStatus.PERMANENT_FAILURE,
        ):
            return result.to_dict()

        # Retryable failure
        if attempt < _MAX_RETRIES:
            backoff = _RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
            time.sleep(backoff)
        else:
            # Exhausted retries
            result.status = CveLookupStatus.PERMANENT_FAILURE
            result.error_message = (
                f"{result.error_message}"
                f" (exhausted {_MAX_RETRIES} retries)"
            )
            return result.to_dict()

    return CveLookupResult(
        cve_id=cve_id,
        status=CveLookupStatus.PERMANENT_FAILURE,
        error_category="unexpected",
        error_message="Lookup loop exited unexpectedly",
    ).to_dict()
