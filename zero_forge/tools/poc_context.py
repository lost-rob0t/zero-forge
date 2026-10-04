"""Structured selection of bounded proof-of-concept context for model prompts."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

_BUNDLE_HEADER = re.compile(r"(?m)^===== Exploit-DB (?P<id>\d+) =====\s*$")
_CVE_PATTERN = re.compile(r"\bCVE-[0-9]{4}-[0-9]{4,}\b", re.IGNORECASE)
_ENDPOINT_PATTERN = re.compile(r"/api/[A-Za-z0-9_./{}:-]+")
_METADATA_PATTERN = re.compile(r"(?mi)^(Query|Title|Source|CVE):\s*(.+?)\s*$")
_VERSION_PATTERN = re.compile(r"\b[0-9]+\.[0-9]+(?:\.[0-9]+)?\b")
_WORD_PATTERN = re.compile(r"[a-z0-9]{4,}")


@dataclass(frozen=True, slots=True)
class _PocSection:
    identifier: str
    title: str
    source: str
    content: str
    cve_ids: tuple[str, ...]
    endpoints: tuple[str, ...]
    index: int


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_sections(text: str) -> list[_PocSection]:
    matches = list(_BUNDLE_HEADER.finditer(text))
    if not matches:
        return [
            _PocSection(
                identifier="inline:1",
                title="",
                source="",
                content=text.strip(),
                cve_ids=tuple(sorted({value.upper() for value in _CVE_PATTERN.findall(text)})),
                endpoints=tuple(sorted(set(_ENDPOINT_PATTERN.findall(text)))),
                index=0,
            )
        ]

    sections: list[_PocSection] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        content = text[match.end() : end].strip()
        metadata = {key.lower(): value.strip() for key, value in _METADATA_PATTERN.findall(content)}
        sections.append(
            _PocSection(
                identifier=f"exploitdb:{match.group('id')}",
                title=metadata.get("title", ""),
                source=metadata.get("source", ""),
                content=content,
                cve_ids=tuple(sorted({value.upper() for value in _CVE_PATTERN.findall(content)})),
                endpoints=tuple(sorted(set(_ENDPOINT_PATTERN.findall(content)))),
                index=index,
            )
        )
    return sections


def _score(section: _PocSection, target_text: str) -> int:
    target = target_text.lower()[:200_000]
    if not target:
        return 0
    score = 0
    for endpoint in section.endpoints:
        if endpoint.lower() in target:
            score += 30
    for version in set(_VERSION_PATTERN.findall(f"{section.title}\n{section.content[:2000]}")):
        if version in target:
            score += 20
    for word in set(_WORD_PATTERN.findall(section.title.lower())):
        if word in target:
            score += 1
    return score


def _equivalence_key(section: _PocSection) -> tuple[Any, ...]:
    if section.cve_ids and section.endpoints:
        return ("vulnerability", section.cve_ids, section.endpoints)
    if section.cve_ids:
        return ("cve", section.cve_ids)
    normalized = re.sub(r"\s+", " ", section.content).strip().lower()
    return ("content", _sha256(normalized))


def _truncate_section(text: str, budget: int) -> tuple[str, bool]:
    if len(text) <= budget:
        return text, False
    marker = "\n[ZeroForge: PoC section truncated at a line boundary]\n"
    cutoff = max(0, budget - len(marker))
    boundary = text.rfind("\n", 0, cutoff)
    if boundary <= 0:
        boundary = cutoff
    return text[:boundary].rstrip() + marker, True


def normalize_poc_context(
    poc_text: str,
    requested_cve: str = "",
    target_text: str = "",
    max_chars: int = 6000,
    max_sections: int = 3,
) -> dict[str, Any]:
    """Select coherent PoC sections without opaque concatenation or global slicing."""
    if not isinstance(poc_text, str):
        raise ValueError("poc_text must be a string")
    if not 1000 <= max_chars <= 50_000:
        raise ValueError("max_chars must be between 1000 and 50000")
    if not 1 <= max_sections <= 10:
        raise ValueError("max_sections must be between 1 and 10")
    if not poc_text.strip():
        return {"text": "", "records": [], "selected_cve_ids": []}

    requested = requested_cve.strip().upper()
    sections = _parse_sections(poc_text)
    ranked = sorted(sections, key=lambda item: (-_score(item, target_text), item.index))

    chosen_cves: tuple[str, ...] = ()
    if requested:
        chosen_cves = (requested,)
    else:
        chosen = next((item for item in ranked if item.cve_ids), None)
        if chosen is not None:
            chosen_cves = chosen.cve_ids

    selected: list[_PocSection] = []
    seen_keys: set[tuple[Any, ...]] = set()
    records_by_id: dict[str, dict[str, Any]] = {}

    for section in ranked:
        record: dict[str, Any] = {
            "id": section.identifier,
            "title": section.title,
            "source": section.source,
            "cve_ids": list(section.cve_ids),
            "sha256": _sha256(section.content),
            "characters": len(section.content),
            "selected": False,
            "reason": "",
        }
        if chosen_cves and section.cve_ids and set(section.cve_ids).isdisjoint(chosen_cves):
            record["reason"] = "excluded conflicting CVE group; selected " + ", ".join(chosen_cves)
        else:
            key = _equivalence_key(section)
            if key in seen_keys:
                record["reason"] = "excluded duplicate vulnerability evidence"
            elif len(selected) >= max_sections:
                record["reason"] = "excluded by section limit"
            else:
                seen_keys.add(key)
                selected.append(section)
                record["selected"] = True
                record["reason"] = "selected coherent PoC evidence"
        records_by_id[section.identifier] = record

    records = [records_by_id[section.identifier] for section in sections]
    selected.sort(key=lambda item: item.index)
    if not selected:
        return {
            "text": "",
            "records": records,
            "selected_cve_ids": list(chosen_cves),
        }

    per_section = max(1000, max_chars // len(selected))
    rendered: list[str] = []
    for section in selected:
        body, truncated = _truncate_section(section.content, per_section)
        record = records_by_id[section.identifier]
        if truncated:
            record["reason"] = (
                str(record.get("reason", "")) + "; truncated within per-section budget"
            )
        provenance = [f"ID: {section.identifier}"]
        if section.title:
            provenance.append(f"Title: {section.title}")
        if section.source:
            provenance.append(f"Source: {section.source}")
        if section.cve_ids:
            provenance.append("CVE: " + ", ".join(section.cve_ids))
        rendered.append("\n".join(provenance) + "\n\n" + body)

    return {
        "text": "\n\n--- selected PoC section ---\n\n".join(rendered),
        "records": records,
        "selected_cve_ids": list(chosen_cves),
    }
