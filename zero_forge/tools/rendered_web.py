"""JavaScript rendering and HTML-to-Markdown extraction."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from datetime import UTC, datetime
from time import monotonic
from typing import Any, cast

from .web_research import _USER_AGENT, _bounded_timeout


class RenderedWebDependencyError(RuntimeError):
    """Raised when optional rendered-web dependencies are unavailable."""


class RenderedWebError(RuntimeError):
    """Raised when browser rendering fails."""


def _load_markdown_converter() -> Callable[..., str]:
    try:
        from markdownify import markdownify
    except ImportError as exc:
        raise RenderedWebDependencyError(
            "rendered web research requires markdownify; install requirements-browser.txt"
        ) from exc
    return cast(Callable[..., str], markdownify)


def _load_playwright() -> Callable[..., Any]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RenderedWebDependencyError(
            "rendered web research requires Playwright; install requirements-browser.txt "
            "and run 'playwright install chromium'"
        ) from exc
    return cast(Callable[..., Any], sync_playwright)


def _normalize_markdown(value: str) -> str:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    normalized = re.sub(r"[ \t]+\n", "\n", normalized)
    normalized = re.sub(r"\n{3,}", "\n\n", normalized)
    return normalized.strip()


def _html_to_markdown(html: str) -> str:
    converter = _load_markdown_converter()
    return _normalize_markdown(
        converter(
            html,
            heading_style="ATX",
            bullets="-",
            strip=["script", "style", "noscript", "svg", "canvas", "template"],
        )
    )


def _chunk_markdown(markdown: str, chunk_chars: int) -> list[str]:
    if not markdown:
        return []
    chunks: list[str] = []
    current: list[str] = []
    current_size = 0
    in_fence = False

    for line in markdown.splitlines(keepends=True):
        stripped = line.lstrip()
        starts_fence = stripped.startswith("```") or stripped.startswith("~~~")
        if current and current_size + len(line) > chunk_chars and not in_fence:
            chunks.append("".join(current).strip())
            current = []
            current_size = 0
        if not current and len(line) > chunk_chars and not in_fence:
            for offset in range(0, len(line), chunk_chars):
                piece = line[offset : offset + chunk_chars].strip()
                if piece:
                    chunks.append(piece)
            continue
        current.append(line)
        current_size += len(line)
        if starts_fence:
            in_fence = not in_fence

    if current:
        chunks.append("".join(current).strip())
    return [chunk for chunk in chunks if chunk]


def _close_safely(resource: Any) -> None:
    if resource is None:
        return
    try:
        resource.close()
    except Exception:
        return


def _remaining_milliseconds(deadline: float, *, cap: int | None = None) -> int:
    remaining = int((deadline - monotonic()) * 1000)
    if remaining <= 0:
        raise RenderedWebError("browser rendering timed out")
    return min(remaining, cap) if cap is not None else remaining


def _render_page(
    url: str,
    *,
    max_scrolls: int,
    scroll_wait_ms: int,
    timeout: int,
) -> dict[str, Any]:
    sync_playwright = _load_playwright()
    scroll_steps = 0
    scroll_limited = False
    timeout_limited = False
    final_url = url
    title = ""
    html = ""
    fallback_text = ""
    deadline = monotonic() + timeout

    try:
        with sync_playwright() as playwright:
            browser: Any = None
            context: Any = None
            try:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context(
                    java_script_enabled=True,
                    user_agent=_USER_AGENT,
                )
                context.set_default_timeout(timeout * 1000)
                context.set_default_navigation_timeout(timeout * 1000)
                page = context.new_page()

                response = page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=_remaining_milliseconds(deadline),
                )
                if response is None:
                    raise RenderedWebError("browser navigation returned no response")
                final_url = page.url

                try:
                    page.wait_for_load_state(
                        "networkidle",
                        timeout=_remaining_milliseconds(deadline, cap=5_000),
                    )
                except RenderedWebError:
                    raise
                except Exception:
                    pass

                stable_rounds = 0
                previous_height = -1
                for _ in range(max_scrolls):
                    if monotonic() >= deadline:
                        timeout_limited = True
                        break
                    metrics = page.evaluate(
                        """() => ({
                            height: Math.max(
                                document.body ? document.body.scrollHeight : 0,
                                document.documentElement.scrollHeight
                            ),
                            viewport: window.innerHeight,
                            y: window.scrollY
                        })"""
                    )
                    height = int(metrics.get("height", 0))
                    viewport = int(metrics.get("viewport", 0))
                    y = int(metrics.get("y", 0))
                    at_bottom = y + viewport >= height - 4
                    if height == previous_height and at_bottom:
                        stable_rounds += 1
                        if stable_rounds >= 2:
                            break
                    else:
                        stable_rounds = 0
                    previous_height = height
                    page.evaluate(
                        "() => window.scrollTo(0, document.documentElement.scrollHeight)"
                    )
                    page.wait_for_timeout(
                        _remaining_milliseconds(deadline, cap=scroll_wait_ms)
                    )
                    scroll_steps += 1
                else:
                    scroll_limited = max_scrolls > 0

                extracted = page.evaluate(
                    """() => {
                        const selectors = ["main", "article", "[role='main']", "body"];
                        const candidates = selectors
                            .flatMap((selector) => Array.from(
                                document.querySelectorAll(selector)
                            ))
                            .filter((node) =>
                                node && node.innerText && node.innerText.trim()
                            );
                        candidates.sort((left, right) =>
                            right.innerText.trim().length
                            - left.innerText.trim().length
                        );
                        const source = candidates[0]
                            || document.body
                            || document.documentElement;
                        const clone = source.cloneNode(true);
                        clone.querySelectorAll(
                            "script,style,noscript,svg,canvas,template,iframe,object,embed"
                        ).forEach((node) => node.remove());
                        clone.querySelectorAll("[hidden],[aria-hidden='true']")
                            .forEach((node) => node.remove());
                        return {
                            html: clone.outerHTML || clone.innerHTML || "",
                            text: clone.innerText || source.innerText || ""
                        };
                    }"""
                )
                title = page.title()
                html = str(extracted.get("html", ""))
                fallback_text = str(extracted.get("text", ""))
            finally:
                _close_safely(context)
                _close_safely(browser)
    except RenderedWebDependencyError:
        raise
    except RenderedWebError:
        raise
    except Exception as exc:
        raise RenderedWebError(f"browser rendering failed: {exc}") from exc

    return {
        "final_url": final_url,
        "title": title,
        "html": html,
        "fallback_text": fallback_text,
        "scroll_steps": scroll_steps,
        "scroll_limited": scroll_limited,
        "timeout_limited": timeout_limited,
    }


def fetch_rendered_web_page(
    url: str,
    max_markdown_chars: int = 300_000,
    chunk_chars: int = 12_000,
    max_scrolls: int = 20,
    scroll_wait_ms: int = 300,
    timeout: int = 30,
) -> dict[str, Any]:
    """Render one page, scroll boundedly, and return Markdown chunks."""

    if not url.strip():
        raise ValueError("url must not be empty")
    if not 1_000 <= max_markdown_chars <= 1_000_000:
        raise ValueError("max_markdown_chars must be between 1000 and 1000000")
    if not 1_000 <= chunk_chars <= 50_000:
        raise ValueError("chunk_chars must be between 1000 and 50000")
    if not 0 <= max_scrolls <= 50:
        raise ValueError("max_scrolls must be between 0 and 50")
    if not 50 <= scroll_wait_ms <= 2_000:
        raise ValueError("scroll_wait_ms must be between 50 and 2000")
    bounded_timeout = _bounded_timeout(timeout)

    rendered = _render_page(
        url,
        max_scrolls=max_scrolls,
        scroll_wait_ms=scroll_wait_ms,
        timeout=bounded_timeout,
    )
    markdown = _html_to_markdown(str(rendered.get("html", "")))
    if not markdown:
        markdown = _normalize_markdown(str(rendered.get("fallback_text", "")))
    original_markdown_chars = len(markdown)
    markdown_limited = original_markdown_chars > max_markdown_chars
    if markdown_limited:
        markdown = markdown[:max_markdown_chars].rstrip()
    chunks = _chunk_markdown(markdown, chunk_chars)
    raw = markdown.encode("utf-8")
    truncated = bool(
        markdown_limited
        or rendered.get("scroll_limited", False)
        or rendered.get("timeout_limited", False)
    )

    return {
        "url": url,
        "final_url": str(rendered.get("final_url", url)),
        "content_type": "text/markdown",
        "format": "markdown",
        "rendered": True,
        "renderer": "playwright-chromium",
        "title": str(rendered.get("title", "")),
        "text": markdown,
        "markdown": markdown,
        "markdown_chunks": chunks,
        "chunk_count": len(chunks),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "retrieved_at": datetime.now(UTC).isoformat(),
        "size_bytes": len(raw),
        "total_markdown_chars": original_markdown_chars,
        "scroll_steps": int(rendered.get("scroll_steps", 0)),
        "truncated": truncated,
    }
