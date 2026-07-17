"""Tests for official advisory lookup tools."""

import json
from unittest.mock import MagicMock, patch

import pytest

from zero_forge.tools.advisory_lookup import (
    cisa_kev_lookup,
    github_advisory_search,
    osv_query,
)
from zero_forge.tools.registry import create_default_registry


def _response(payload):
    response = MagicMock()
    response.read.return_value = json.dumps(payload).encode("utf-8")
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)
    return response


def test_osv_query_normalizes_package_advisory():
    payload = {
        "vulns": [
            {
                "id": "GHSA-test-1234-5678",
                "aliases": ["CVE-2026-12345"],
                "summary": "Parser length mismatch",
                "details": "A declared length can exceed the available buffer.",
                "published": "2026-01-01T00:00:00Z",
                "modified": "2026-01-02T00:00:00Z",
                "affected": [
                    {
                        "package": {
                            "ecosystem": "PyPI",
                            "name": "demo-parser",
                        },
                        "versions": ["1.0.0"],
                        "ranges": [{"type": "ECOSYSTEM", "events": []}],
                    }
                ],
                "references": [{"url": "https://example.com/advisory"}],
                "database_specific": {"cwe_ids": ["CWE-125"]},
            }
        ]
    }
    with patch(
        "zero_forge.tools.advisory_lookup.urllib.request.urlopen",
        return_value=_response(payload),
    ) as mock_urlopen:
        records = osv_query("demo-parser", "PyPI", version="1.0.0")

    request = mock_urlopen.call_args.args[0]
    assert json.loads(request.data.decode("utf-8")) == {
        "package": {"name": "demo-parser", "ecosystem": "PyPI"},
        "version": "1.0.0",
    }
    assert records[0]["source"] == "osv"
    assert records[0]["aliases"] == ["CVE-2026-12345"]
    assert records[0]["cwes"] == ["CWE-125"]
    assert records[0]["affected_packages"][0]["name"] == "demo-parser"


def test_github_advisory_search_normalizes_vulnerable_functions():
    payload = [
        {
            "ghsa_id": "GHSA-test-1234-5678",
            "summary": "Unsafe parser state transition",
            "description": "A crafted record reaches an invalid state.",
            "severity": "high",
            "html_url": "https://github.com/advisories/GHSA-test-1234-5678",
            "identifiers": [
                {"type": "GHSA", "value": "GHSA-test-1234-5678"},
                {"type": "CVE", "value": "CVE-2026-12345"},
            ],
            "cwes": [{"cwe_id": "CWE-20"}],
            "references": ["https://example.com/fix"],
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "pip", "name": "demo-parser"},
                    "vulnerable_version_range": "< 1.0.1",
                    "first_patched_version": "1.0.1",
                    "vulnerable_functions": ["parse_record"],
                }
            ],
        }
    ]
    with patch(
        "zero_forge.tools.advisory_lookup.urllib.request.urlopen",
        return_value=_response(payload),
    ) as mock_urlopen:
        records = github_advisory_search(
            cve_ids=["CVE-2026-12345"],
            ghsa_ids=[],
        )

    request = mock_urlopen.call_args.args[0]
    assert "cve_id=CVE-2026-12345" in request.full_url
    assert records[0]["advisory_id"] == "GHSA-test-1234-5678"
    assert records[0]["aliases"] == ["CVE-2026-12345"]
    assert records[0]["vulnerable_functions"] == ["parse_record"]


def test_github_advisory_search_maps_pypi_to_pip():
    with patch(
        "zero_forge.tools.advisory_lookup.urllib.request.urlopen",
        return_value=_response([]),
    ) as mock_urlopen:
        github_advisory_search(
            cve_ids=[],
            ghsa_ids=[],
            package_name="demo-parser",
            ecosystem="PyPI",
            version="1.0.0",
        )

    request = mock_urlopen.call_args.args[0]
    assert "affects=demo-parser%401.0.0" in request.full_url
    assert "ecosystem=pip" in request.full_url


def test_cisa_kev_lookup_filters_requested_cves():
    payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-12345",
                "vendorProject": "Example",
                "product": "Parser",
                "vulnerabilityName": "Parser Bounds Vulnerability",
                "dateAdded": "2026-02-01",
                "shortDescription": "The parser can read outside the intended buffer.",
                "requiredAction": "Apply the vendor update.",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "",
            },
            {"cveID": "CVE-2026-99999"},
        ]
    }
    with patch(
        "zero_forge.tools.advisory_lookup.urllib.request.urlopen",
        return_value=_response(payload),
    ):
        records = cisa_kev_lookup(["cve-2026-12345"])

    assert len(records) == 1
    assert records[0]["cve_id"] == "CVE-2026-12345"
    assert records[0]["product"] == "Parser"


def test_advisory_tools_enforce_bounds():
    with pytest.raises(ValueError, match="max_results"):
        osv_query("demo", "PyPI", max_results=101)


def test_default_registry_contains_advisory_tools():
    names = create_default_registry().names()

    assert "osv_query" in names
    assert "github_advisory_search" in names
    assert "cisa_kev_lookup" in names
