from __future__ import annotations

from pathlib import Path

from zero_forge.tools.poc_context import normalize_poc_context

FIXTURE = (Path(__file__).parent / "fixtures" / "langflow_poc_bundle.txt").read_text(
    encoding="utf-8"
)
TARGET = """project = "langflow"
version = "1.2.0"
@router.post("/code")
def validate_code(code):
    return code
"""


def test_langflow_bundle_selects_one_coherent_cve_group():
    result = normalize_poc_context(
        FIXTURE,
        target_text=TARGET,
        max_chars=3900,
        max_sections=2,
    )

    assert "exploitdb:52364" in result["text"]
    assert "exploitdb:52262" not in result["text"]
    assert "exploitdb:52597" not in result["text"]
    assert "CVE-2026-0770" not in result["text"]
    assert result["selected_cve_ids"] == ["CVE-2025-3248"]

    records = {record["id"]: record for record in result["records"]}
    assert records["exploitdb:52364"]["selected"] is True
    assert "duplicate" in records["exploitdb:52262"]["reason"]
    assert "conflicting CVE" in records["exploitdb:52597"]["reason"]


def test_requested_cve_excludes_conflicting_sections():
    result = normalize_poc_context(
        FIXTURE,
        requested_cve="CVE-2025-3248",
        target_text=TARGET,
        max_chars=3900,
    )

    assert result["selected_cve_ids"] == ["CVE-2025-3248"]
    assert "CVE-2026-0770" not in result["text"]


def test_single_unstructured_poc_remains_supported():
    result = normalize_poc_context("print('single poc')")

    assert "print('single poc')" in result["text"]
    assert result["records"][0]["id"] == "inline:1"
    assert result["records"][0]["selected"] is True


def test_long_section_is_truncated_at_an_explicit_boundary():
    body = "\n".join(f"line-{index:04d}" for index in range(2000))
    result = normalize_poc_context(body, max_chars=1000)

    assert "PoC section truncated at a line boundary" in result["text"]
    assert not result["text"].endswith("line-1999")
    assert "truncated within per-section budget" in result["records"][0]["reason"]
