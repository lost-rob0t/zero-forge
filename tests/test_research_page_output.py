"""Tests for standalone Markdown research-page publication."""

from zero_forge.tools.output_bundle import _write_research_pages


def test_write_research_pages_preserves_rendered_markdown(tmp_path):
    summaries, written = _write_research_pages(
        tmp_path,
        [
            {
                "final_url": "https://vendor.example/advisory",
                "title": "Vendor Advisory",
                "rendered": True,
                "truncated": False,
                "markdown": "## Details\n\nComplete rendered content.",
                "markdown_chunks": ["## Details", "Complete rendered content."],
                "sha256": "abc123",
            }
        ],
    )

    destination = tmp_path / "page-01.md"
    assert written == [str(destination)]
    assert destination.exists()
    content = destination.read_text(encoding="utf-8")
    assert content.startswith("# Vendor Advisory")
    assert "Source: https://vendor.example/advisory" in content
    assert "## Details" in content
    assert "Complete rendered content." in content
    assert summaries == [
        {
            "final_url": "https://vendor.example/advisory",
            "title": "Vendor Advisory",
            "rendered": True,
            "truncated": False,
            "sha256": "abc123",
            "markdown_path": "pages/page-01.md",
        }
    ]
