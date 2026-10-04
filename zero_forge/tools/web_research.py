"""Bounded web search and page retrieval for vulnerability research."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import Any, Literal

BRAVE_SEARCH_URL = "https://api.search.brave.com/res/v1/web/search"
TAVILY_SEARCH_URL = "https://api.tavily.com/search"
_USER_AGENT = "ZeroForge/0.1"
_ALLOWED_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
)


class _TextExtractor(HTMLParser):
    """Extract readable text while ignoring script and style content."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._ignored_depth = 0
        self.title = ""
        self._in_title = False
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        normalized = tag.lower()
        if normalized in {"script", "style", "noscript", "svg"}:
            self._ignored_depth += 1
        if normalized == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        normalized = tag.lower()
        if normalized in {"script", "style", "noscript", "svg"} and self._ignored_depth:
            self._ignored_depth -= 1
        if normalized == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        text = " ".join(data.split())
        if not text:
            return
        if self._in_title:
            self.title = f"{self.title} {text}".strip()
        self._parts.append(text)

    def text(self) -> str:
        return "\n".join(self._parts)


def _bounded_timeout(timeout: int) -> int:
    if not 1 <= timeout <= 60:
        raise ValueError("timeout must be between 1 and 60 seconds")
    return timeout


def _bounded_results(max_results: int) -> int:
    if not 1 <= max_results <= 20:
        raise ValueError("max_results must be between 1 and 20")
    return max_results


def _normalized_domains(domains: list[str]) -> list[str]:
    output: list[str] = []
    for domain in domains[:100]:
        value = domain.strip().lower().removeprefix("www.")
        if not value or "/" in value or ":" in value:
            raise ValueError(f"invalid domain filter: {domain}")
        output.append(value)
    return list(dict.fromkeys(output))


def _validate_query(query: str) -> str:
    normalized = " ".join(query.split())
    if not normalized:
        raise ValueError("query is required")
    if len(normalized) > 400 or len(normalized.split()) > 50:
        raise ValueError("query exceeds the provider limit")
    return normalized


def _request_json(
    url: str,
    *,
    timeout: int,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> Any:
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
            **(headers or {}),
        },
    )
    with urllib.request.urlopen(request, timeout=_bounded_timeout(timeout)) as response:
        return json.loads(response.read().decode("utf-8"))


def _brave_search(
    query: str,
    *,
    max_results: int,
    include_domains: list[str],
    exclude_domains: list[str],
    timeout: int,
) -> list[dict[str, Any]]:
    api_key = os.environ.get("BRAVE_SEARCH_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("BRAVE_SEARCH_API_KEY is not configured")

    terms = [query]
    terms.extend(f"site:{domain}" for domain in include_domains)
    terms.extend(f"-site:{domain}" for domain in exclude_domains)
    params = urllib.parse.urlencode(
        {
            "q": " ".join(terms),
            "count": max_results,
            "safesearch": "moderate",
        }
    )
    data = _request_json(
        f"{BRAVE_SEARCH_URL}?{params}",
        timeout=timeout,
        headers={"X-Subscription-Token": api_key},
    )
    web = data.get("web") if isinstance(data, dict) else None
    raw_results = web.get("results", []) if isinstance(web, dict) else []
    if not isinstance(raw_results, list):
        return []

    output: list[dict[str, Any]] = []
    for item in raw_results[:max_results]:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url", ""))
        if not url:
            continue
        output.append(
            {
                "provider": "brave",
                "title": str(item.get("title", "")),
                "url": url,
                "snippet": str(item.get("description", "")),
                "published": str(item.get("page_age", item.get("age", ""))),
                "score": None,
            }
        )
    return output


def _tavily_search(
    query: str,
    *,
    max_results: int,
    include_domains: list[str],
    exclude_domains: list[str],
    timeout: int,
) -> list[dict[str, Any]]:
    api_key = os.environ.get("TAVILY_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("TAVILY_API_KEY is not configured")

    payload = {
        "query": query,
        "search_depth": "basic",
        "include_answer": False,
        "include_raw_content": False,
        "max_results": max_results,
        "include_domains": include_domains,
        "exclude_domains": exclude_domains,
    }
    data = _request_json(
        TAVILY_SEARCH_URL,
        timeout=timeout,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    raw_results = data.get("results", []) if isinstance(data, dict) else []
    if not isinstance(raw_results, list):
        return []

    output: list[dict[str, Any]] = []
    for item in raw_results[:max_results]:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url", ""))
        if not url:
            continue
        score = item.get("score")
        output.append(
            {
                "provider": "tavily",
                "title": str(item.get("title", "")),
                "url": url,
                "snippet": str(item.get("content", "")),
                "published": str(item.get("published_date", "")),
                "score": float(score) if isinstance(score, (int, float)) else None,
            }
        )
    return output


def web_search(
    query: str,
    provider: Literal["auto", "brave", "tavily"] = "auto",
    max_results: int = 8,
    include_domains: list[str] | None = None,
    exclude_domains: list[str] | None = None,
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """Search the public web through a configured bounded provider.

    API keys are read directly from ``BRAVE_SEARCH_API_KEY`` or ``TAVILY_API_KEY``;
    they are never included in Tool Agent arguments or model prompts.
    """

    normalized_query = _validate_query(query)
    limit = _bounded_results(max_results)
    included = _normalized_domains(include_domains or [])
    excluded = _normalized_domains(exclude_domains or [])
    if set(included).intersection(excluded):
        raise ValueError("a domain cannot be both included and excluded")

    selected = provider
    if selected == "auto":
        if os.environ.get("BRAVE_SEARCH_API_KEY", "").strip():
            selected = "brave"
        elif os.environ.get("TAVILY_API_KEY", "").strip():
            selected = "tavily"
        else:
            raise RuntimeError("web search requires BRAVE_SEARCH_API_KEY or TAVILY_API_KEY")

    if selected == "brave":
        return _brave_search(
            normalized_query,
            max_results=limit,
            include_domains=included,
            exclude_domains=excluded,
            timeout=timeout,
        )
    return _tavily_search(
        normalized_query,
        max_results=limit,
        include_domains=included,
        exclude_domains=excluded,
        timeout=timeout,
    )


def _validate_public_https_url(url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("only absolute HTTPS URLs are allowed")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed")

    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"could not resolve URL host: {exc}") from exc
    if not addresses:
        raise ValueError("URL host did not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise ValueError("URL resolves to a non-public address")
    return parsed


def fetch_web_page(
    url: str,
    max_bytes: int = 200_000,
    timeout: int = 15,
) -> dict[str, Any]:
    """Fetch one public HTTPS page with SSRF and response-size controls."""

    if not 1 <= max_bytes <= 1_000_000:
        raise ValueError("max_bytes must be between 1 and 1000000")
    _validate_public_https_url(url)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/html,text/plain,application/json,application/xml;q=0.9",
            "User-Agent": _USER_AGENT,
        },
    )
    with urllib.request.urlopen(request, timeout=_bounded_timeout(timeout)) as response:
        final_url = response.geturl()
        _validate_public_https_url(final_url)
        content_type = response.headers.get_content_type().lower()
        if not any(content_type.startswith(value) for value in _ALLOWED_CONTENT_TYPES):
            raise ValueError(f"unsupported response content type: {content_type}")
        raw = response.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError("web response exceeded max_bytes")
        charset = response.headers.get_content_charset() or "utf-8"

    decoded = raw.decode(charset, errors="replace")
    title = ""
    text = decoded
    if content_type in {"text/html", "application/xhtml+xml"}:
        parser = _TextExtractor()
        parser.feed(decoded)
        parser.close()
        title = parser.title
        text = parser.text()

    return {
        "url": url,
        "final_url": final_url,
        "content_type": content_type,
        "title": title,
        "text": text,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "retrieved_at": datetime.now(UTC).isoformat(),
        "size_bytes": len(raw),
    }
