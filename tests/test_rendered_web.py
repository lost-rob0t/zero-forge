"""Tests for rendered-page Markdown retrieval."""

from unittest.mock import patch

import pytest

from zero_forge.tools.rendered_web import _chunk_markdown, fetch_rendered_web_page


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
        "scroll_steps": 3,
        "scroll_limited": False,
        "timeout_limited": False,
    }

    def converter(html, **kwargs):
        del html, kwargs
        return "# Rendered Advisory\n\nFull body.\n\n" + ("x" * 3000)

    with (
        patch(
            "zero_forge.tools.rendered_web._render_page",
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
            max_requests=250,
            max_transfer_bytes=20_000_000,
            max_redirects=5,
            max_js_heap_mb=128,
        )

    assert result["rendered"] is True
    assert result["format"] == "markdown"
    assert result["markdown"].startswith("# Rendered Advisory")
    assert result["chunk_count"] >= 3
    assert "Full body." in "\n".join(result["markdown_chunks"])
    assert result["truncated"] is False
    assert result["scroll_steps"] == 3
    assert "request_count" not in result
    assert "transfer_bytes" not in result
    assert "redirect_count" not in result
    assert "max_js_heap_mb" not in result


def test_fetch_rendered_page_marks_content_limit():
    rendered = {
        "final_url": "https://vendor.example/advisory",
        "title": "Large Advisory",
        "html": "<main>large</main>",
        "fallback_text": "large",
        "scroll_steps": 0,
        "scroll_limited": False,
        "timeout_limited": False,
    }

    def converter(html, **kwargs):
        del html, kwargs
        return "z" * 2_000

    with (
        patch(
            "zero_forge.tools.rendered_web._render_page",
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


def test_fetch_rendered_page_rejects_empty_url():
    with pytest.raises(ValueError, match="must not be empty"):
        fetch_rendered_web_page("   ")
