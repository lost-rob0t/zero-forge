"""Nuclei artifact profile registration for the Smart Agent."""

from __future__ import annotations

from types import ModuleType

from ..schemas import ArtifactType


def register_nuclei_profile(smart_agent: ModuleType) -> None:
    """Register the Nuclei prompt contract on the shared Smart Agent module."""
    profiles = smart_agent._PROFILES
    if ArtifactType.NUCLEI in profiles:
        return
    profiles[ArtifactType.NUCLEI] = smart_agent.ArtifactProfile(
        label="Nuclei detection template",
        language="yaml",
        fence_aliases=("yaml", "yml"),
        filename_suffix="_nuclei.yaml",
        system_instructions="""\
Write one Nuclei v3 YAML detection template. Use only supplied vulnerability evidence.
Keep requests bounded and non-destructive, target the exact affected endpoint and
parameters, and require vulnerability-specific response, timing, or protocol evidence
before a match is reported.
""",
        contract="""\
- Emit exactly one YAML document with a unique slug-style id.
- Define info.name, info.author, info.severity, info.description, authoritative
  info.reference entries, and relevant tags.
- Define at least one supported protocol request such as http, dns, network, ssl,
  websocket, headless, file, code, or javascript.
- For HTTP templates, use {{BaseURL}}, the evidence-backed method, endpoint, headers,
  parameters, and body. Keep probe values deterministic and non-destructive.
- Include matchers or extractors that require vulnerability-specific evidence. For
  differential or timing checks, compare a baseline and probe rather than matching a
  generic status code alone.
- Do not embed another template, workflow, Markdown explanation, or target unrelated
  to the supplied evidence.
- Output one complete Nuclei template in a yaml code fence.
""",
    )
