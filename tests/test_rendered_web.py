# ruff: noqa: I001
"""Tests for bounded rendered-page Markdown retrieval."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from zero_forge.tools.rendered_web import (
    _browser_request_allowed,
    _chromium_args,
    _chunk_markdown,
    _redirect_depth,
    _resolve_public_addresses,
    _TransferBudget,
    fetch_rendered_web_page,
)


def test_browser_request_rejects_private_and_heavy_resources():
    private_address = [(2, 1, 6, "", ("127.0.0.1", 443))]
    with patch(
        "zero_forge.tools.web_research.socket.getaddrinfo",
        return_value=private_address,
    ):
        assert not _browser_request_allowed("https://internal.example/data", "xhr")
    assert not _browser_request_allowed("https://public.example/image.png", "image")
    assert not _browser_request_allowed("https://public.example/socket", "websocket")
    assert not _browser_request_allowed("http://public.example/plain", "document")
    assert not _browser_request_allowed("data:text/plain,ok", "other")
    assert _browser_request_allowed("about:blank", "other")


def test_proxy_resolution_rejects_non_public_actual_targets():
    private_address = [(2, 1, 6, "", ("169.254.169.254", 443))]
    with patch(
        "zero_forge.tools.rendered_web.socket.getaddrinfo",
        return_value=private_address,
    ):
        with pytest.raises(ValueError, match="non-public"):
            _resolve_public_addresses("metadata.example", 443)


def test_proxy_resolution_pins_public_socket_address():
    public_address = [(2, 1, 6, "", ("93.184.216.34", 443))]
    with patch(
        "zero_forge.tools.rendered_web.socket.getaddrinfo",
        return_value=public_address,
    ):
        resolved = _resolve_public_addresses("vendor.example", 443)

    assert resolved == [(2, 1, 6, ("93.184.216.34", 443))]


def test_transfer_budget_never_forwards_past_limit():
    budget = _TransferBudget(10)

    assert budget.reserve(7) == 7
    assert budget.reserve(5) == 3
    assert budget.total == 10
    assert budget.remaining == 0
    assert budget.exceeded is True


def test_chromium_is_forced_through_public_only_proxy():
    arguments = _chromium_args("http://127.0.0.1:4141", 128)

    assert "--proxy-server=http://127.0.0.1:4141" in arguments
    assert "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1" in arguments
    assert "--disable-quic" in arguments
    assert "--js-flags=--max-old-space-size=128" in arguments


def test_redirect_depth_counts_full_navigation_chain():
    first = SimpleNamespace(redirected_from=None)
    second = SimpleNamespace(redirected_from=first)
    third = SimpleNamespace(redirected_from=second)

    assert _redirect_depth(first) == 0
    assert _redirect_depth(third) == 2


def test_chunk_markdown_preserves_order_and_content():
    markdown = "# One\n\n" + ("alpha " * 1000) + "\n\n# Two\n\n" + ("beta " * 1000)
    chunks = _chunk_markdown(markdown, 2_000)

    assert len(chunks) > 2
    assert chunks[0].startswith("# One")
    assert "# Two" in "\n".join(chunks)
    assert "alpha" in "".join(chunks)
    assert "beta" in "".join(chunks)


def test_fetch_rendered_page_converts_html_to_markdown_and_chunks():
    rendered = {
        "final_url": "https://vendor.example/advisory",
        "title": "Rendered Advisory",
        "html": "<main><h1>Rendered Advisory</h1><p>Full body.</p></main>",
        "fallback_text": "Rendered Advisory Full body.",
        "request_count": 4,
        "transfer_bytes": 1200,
        "request_limited": False,
        "transfer_limited": False,
        "redirect_count": 1,
        "redirect_limited": False,
        "scroll_steps": 3,
        "scroll_limited": False,
        "timeout_limited": False,
    }

    def converter(html, **kwargs):
        del html, kwargs
        return "# Rendered Advisory\n\nFull body.\n\n" + ("x" * 3000)

    public_address = [(2, 1, 6, "", ("93.184.216.34", 443))]

    with (
        patch(
            "zero_forge.tools.web_research.socket.getaddrinfo",
            return_value=public_address,
        ),
        patch(
            "zero_forge.tools.rendered_web._render_public_page",
            return_value=rendered,
        ),
        patch(
            "zero_forge.tools.rendered_web._load_markdown_converter",
            return_value=converter,
        ),
    ):
        result = fetch_rendered_web_page(
            "https://vendor.example/advisory",
            max_markdown_chars=10_000,
            chunk_chars=1_000,
        )

    assert result["rendered"] is True
    assert result["format"] == "markdown"
    assert result["markdown"].startswith("# Rendered Advisory")
    assert result["chunk_count"] >= 3
    assert "Full body." in "\n".join(result["markdown_chunks"])
    assert result["truncated"] is False
    assert result["redirect_count"] == 1
    assert result["scroll_steps"] == 3
    assert result["max_js_heap_mb"] == 128


def test_fetch_rendered_page_marks_content_limit():
    rendered = {
        "final_url": "https://vendor.example/advisory",
        "title": "Large Advisory",
        "html": "<main>large</main>",
        "fallback_text": "large",
        "request_count": 1,
        "transfer_bytes": 100,
        "request_limited": False,
        "transfer_limited": False,
        "redirect_count": 0,
        "redirect_limited": False,
        "scroll_steps": 0,
        "scroll_limited": False,
        "timeout_limited": False,
    }

    def converter(html, **kwargs):
        del html, kwargs
        return "z" * 2_000

    public_address = [(2, 1, 6, "", ("93.184.216.34", 443))]

    with (
        patch(
            "zero_forge.tools.web_research.socket.getaddrinfo",
            return_value=public_address,
        ),
        patch(
            "zero_forge.tools.rendered_web._render_public_page",
            return_value=rendered,
        ),
        patch(
            "zero_forge.tools.rendered_web._load_markdown_converter",
            return_value=converter,
        ),
    ):
        result = fetch_rendered_web_page(
            "https://vendor.example/advisory",
            max_markdown_chars=1_000,
            chunk_chars=1_000,
        )

    assert result["truncated"] is True
    assert result["size_bytes"] == 1_000
    assert result["total_markdown_chars"] == 2_000
