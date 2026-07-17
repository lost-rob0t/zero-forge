"""Tests for static-to-rendered research fallback and page chunk context."""

from types import SimpleNamespace

from zero_forge.discovery.exploit_loop import _collect_web_context, _page_context
from zero_forge.schemas import ToolRequest, ToolResult


class WebContextRunner:
    def __init__(self) -> None:
        self.names: list[str] = []

    def run(self, request: ToolRequest) -> ToolResult:
        name = request.allowed_tools[0]
        self.names.append(name)
        if name == "web_search":
            return ToolResult(
                name=name,
                output=[
                    {
                        "url": "https://vendor.example/advisory",
                        "title": "Advisory",
                    }
                ],
            )
        if name == "fetch_web_page":
            return ToolResult(
                name=name,
                output={
                    "final_url": "https://vendor.example/advisory",
                    "content_type": "text/html",
                    "title": "Advisory",
                    "text": "You need to enable JavaScript to view this page.",
                    "sha256": "static-hash",
                    "size_bytes": 120,
                    "truncated": False,
                },
            )
        if name == "fetch_rendered_web_page":
            return ToolResult(
                name=name,
                output={
                    "final_url": "https://vendor.example/advisory",
                    "content_type": "text/markdown",
                    "format": "markdown",
                    "rendered": True,
                    "title": "Advisory",
                    "markdown": "# Advisory\n\nFull rendered body.",
                    "markdown_chunks": ["# Advisory", "Full rendered body."],
                    "sha256": "rendered-hash",
                    "size_bytes": 30,
                    "truncated": False,
                },
            )
        raise AssertionError(f"unexpected tool: {name}")


def test_collect_web_context_escalates_javascript_shell_to_browser():
    request = SimpleNamespace(
        web_queries=["vendor advisory"],
        web_provider="auto",
        max_web_results=8,
        web_include_domains=[],
        web_exclude_domains=[],
        max_web_pages=2,
        render_web_pages=True,
        max_rendered_markdown_chars=300_000,
    )
    runner = WebContextRunner()

    results, pages, errors = _collect_web_context(request, runner)

    assert len(results) == 1
    assert errors == []
    assert runner.names == [
        "web_search",
        "fetch_web_page",
        "fetch_rendered_web_page",
    ]
    assert pages[0]["rendered"] is True
    assert pages[0]["markdown_chunks"] == ["# Advisory", "Full rendered body."]
    assert pages[0]["static_fetch"]["sha256"] == "static-hash"


def test_page_context_keeps_ordered_content_beyond_old_eight_kilobyte_limit():
    request = SimpleNamespace(max_web_pages=2, max_web_context_chars=40_000)
    chunks = ["a" * 9_000, "b" * 9_000, "c" * 9_000]

    context = _page_context(
        request,
        [
            {
                "final_url": "https://vendor.example/long",
                "title": "Long page",
                "format": "markdown",
                "rendered": True,
                "truncated": False,
                "markdown_chunks": chunks,
            }
        ],
    )

    page = context[0]
    assert page["chunk_count"] == 3
    assert [chunk["index"] for chunk in page["chunks"]] == [1, 2, 3]
    assert "".join(chunk["content"] for chunk in page["chunks"]) == "".join(chunks)
    assert page["truncated"] is False
