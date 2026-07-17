"""Tests for bounded web search and page retrieval tools."""

import json
import urllib.error
from email.message import Message
from unittest.mock import MagicMock, patch

import pytest

from zero_forge.tools.web_research import fetch_web_page, web_search


def _json_response(payload):
    response = MagicMock()
    response.read.return_value = json.dumps(payload).encode("utf-8")
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)
    return response


def test_web_search_auto_uses_brave_without_exposing_key(monkeypatch):
    monkeypatch.setenv("BRAVE_SEARCH_API_KEY", "secret-token")
    payload = {
        "web": {
            "results": [
                {
                    "title": "Vendor advisory",
                    "url": "https://vendor.example/advisory",
                    "description": "A parser fix and affected versions.",
                    "page_age": "2026-07-01",
                }
            ]
        }
    }
    with patch(
        "zero_forge.tools.web_research.urllib.request.urlopen",
        return_value=_json_response(payload),
    ) as mock_urlopen:
        results = web_search(
            "CVE-2026-12345 vendor fix",
            include_domains=["vendor.example"],
            max_results=3,
        )

    request = mock_urlopen.call_args.args[0]
    assert request.headers["X-subscription-token"] == "secret-token"
    assert "secret-token" not in request.full_url
    assert "site%3Avendor.example" in request.full_url
    assert results == [
        {
            "provider": "brave",
            "title": "Vendor advisory",
            "url": "https://vendor.example/advisory",
            "snippet": "A parser fix and affected versions.",
            "published": "2026-07-01",
            "score": None,
        }
    ]


def test_web_search_tavily_normalizes_results(monkeypatch):
    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-secret")
    payload = {
        "results": [
            {
                "title": "Fix commit",
                "url": "https://github.com/example/project/commit/abc",
                "content": "Bounds validation was added before indexing.",
                "score": 0.91,
            }
        ]
    }
    with patch(
        "zero_forge.tools.web_research.urllib.request.urlopen",
        return_value=_json_response(payload),
    ) as mock_urlopen:
        results = web_search("project bounds vulnerability", provider="tavily")

    request = mock_urlopen.call_args.args[0]
    assert request.headers["Authorization"] == "Bearer tvly-secret"
    sent = json.loads(request.data.decode("utf-8"))
    assert sent["search_depth"] == "basic"
    assert sent["include_answer"] is False
    assert results[0]["provider"] == "tavily"
    assert results[0]["score"] == 0.91


def test_web_search_requires_configured_provider(monkeypatch):
    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="requires BRAVE_SEARCH_API_KEY"):
        web_search("known parser bug")


def test_fetch_web_page_rejects_private_resolution():
    with patch(
        "zero_forge.tools.web_research.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("127.0.0.1", 443))],
    ):
        with pytest.raises(ValueError, match="non-public"):
            fetch_web_page("https://example.test/internal")


def test_fetch_web_page_extracts_text_and_hashes_content():
    headers = Message()
    headers["Content-Type"] = "text/html; charset=utf-8"
    response = MagicMock()
    response.geturl.return_value = "https://vendor.example/advisory"
    response.headers = headers
    response.read.return_value = (
        b"<html><head><title>Vendor Fix</title><script>ignore()</script></head>"
        b"<body><h1>Patch available</h1><p>Upgrade to 1.0.1.</p></body></html>"
    )
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)
    public_address = [(2, 1, 6, "", ("93.184.216.34", 443))]

    with (
        patch(
            "zero_forge.tools.web_research.socket.getaddrinfo",
            return_value=public_address,
        ),
        patch(
            "zero_forge.tools.web_research.urllib.request.urlopen",
            return_value=response,
        ),
    ):
        result = fetch_web_page("https://vendor.example/advisory")

    assert result["title"] == "Vendor Fix"
    assert "Patch available" in result["text"]
    assert "ignore()" not in result["text"]
    assert len(result["sha256"]) == 64


def test_fetch_web_page_propagates_bounded_http_failure():
    public_address = [(2, 1, 6, "", ("93.184.216.34", 443))]
    error = urllib.error.HTTPError("", 404, "Not Found", {}, None)
    with (
        patch(
            "zero_forge.tools.web_research.socket.getaddrinfo",
            return_value=public_address,
        ),
        patch(
            "zero_forge.tools.web_research.urllib.request.urlopen",
            side_effect=error,
        ),
    ):
        with pytest.raises(urllib.error.HTTPError):
            fetch_web_page("https://vendor.example/missing")
