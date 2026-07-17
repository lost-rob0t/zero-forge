"""Bounded JavaScript rendering and HTML-to-Markdown extraction."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import select
import socket
import socketserver
import threading
import urllib.parse
from collections.abc import Callable
from datetime import UTC, datetime
from time import monotonic
from typing import Any, cast

from .web_research import _USER_AGENT, _bounded_timeout, _validate_public_https_url

_BLOCKED_RESOURCE_TYPES = {
    "eventsource",
    "font",
    "image",
    "manifest",
    "media",
    "texttrack",
    "websocket",
    "worker",
}
_LOCAL_RESOURCE_SCHEMES = {"about", "blob"}
_PROXY_HEADER_LIMIT = 16_384
_PROXY_BUFFER_SIZE = 16_384
_DISABLE_WEBSOCKETS = """
Object.defineProperty(window, "WebSocket", {
    configurable: false,
    value: class DisabledWebSocket {
        constructor() {
            throw new Error("WebSocket disabled by ZeroForge rendered research");
        }
    }
});
"""


class RenderedWebDependencyError(RuntimeError):
    """Raised when optional rendered-web dependencies are unavailable."""


class RenderedWebError(RuntimeError):
    """Raised when bounded browser rendering fails."""


class _TransferBudget:
    """Thread-safe transfer counter shared by every browser proxy tunnel."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._total = 0
        self._exceeded = False
        self._lock = threading.Lock()

    @property
    def total(self) -> int:
        with self._lock:
            return self._total

    @property
    def exceeded(self) -> bool:
        with self._lock:
            return self._exceeded

    @property
    def remaining(self) -> int:
        with self._lock:
            return max(0, self.limit - self._total)

    def reserve(self, size: int) -> int:
        """Reserve at most the remaining transfer budget and return bytes allowed."""

        if size <= 0:
            return 0
        with self._lock:
            remaining = max(0, self.limit - self._total)
            allowed = min(size, remaining)
            self._total += allowed
            if allowed < size:
                self._exceeded = True
            return allowed


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


def _browser_request_allowed(url: str, resource_type: str) -> bool:
    if resource_type in _BLOCKED_RESOURCE_TYPES:
        return False
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme in _LOCAL_RESOURCE_SCHEMES:
        return True
    if parsed.scheme.lower() != "https":
        return False
    try:
        _validate_public_https_url(url)
    except ValueError:
        return False
    return True


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


def _resolve_public_addresses(
    host: str,
    port: int,
) -> list[tuple[int, int, int, tuple[Any, ...]]]:
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"could not resolve proxy target: {exc}") from exc
    if not addresses:
        raise ValueError("proxy target did not resolve")

    output: list[tuple[int, int, int, tuple[Any, ...]]] = []
    for family, socktype, proto, _canonical, sockaddr in addresses:
        raw_ip = str(sockaddr[0]).split("%", 1)[0]
        if not ipaddress.ip_address(raw_ip).is_global:
            raise ValueError("proxy target resolves to a non-public address")
        output.append((family, socktype, proto, cast(tuple[Any, ...], sockaddr)))
    return output


def _parse_connect_target(target: str) -> tuple[str, int]:
    parsed = urllib.parse.urlsplit(f"//{target}")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("invalid CONNECT target")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError("invalid CONNECT target port") from exc
    if not 1 <= port <= 65_535:
        raise ValueError("invalid CONNECT target port")
    return parsed.hostname, port


def _read_proxy_headers(client: socket.socket) -> bytes:
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        chunk = client.recv(min(4096, _PROXY_HEADER_LIMIT + 1 - len(buffer)))
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > _PROXY_HEADER_LIMIT:
            raise ValueError("proxy request headers exceeded the limit")
    if b"\r\n\r\n" not in buffer:
        raise ValueError("incomplete proxy request")
    return bytes(buffer)


def _connect_public_target(host: str, port: int, timeout: float) -> socket.socket:
    last_error: OSError | None = None
    for family, socktype, proto, sockaddr in _resolve_public_addresses(host, port):
        upstream = socket.socket(family, socktype, proto)
        upstream.settimeout(timeout)
        try:
            upstream.connect(sockaddr)
            return upstream
        except OSError as exc:
            last_error = exc
            upstream.close()
    raise OSError(f"could not connect to public proxy target: {last_error}")


class _ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, budget: _TransferBudget, io_timeout: float) -> None:
        self.budget = budget
        self.io_timeout = io_timeout
        self._policy_error = ""
        self._error_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _ConnectProxyHandler)

    @property
    def policy_error(self) -> str:
        with self._error_lock:
            return self._policy_error

    def record_policy_error(self, message: str) -> None:
        with self._error_lock:
            if not self._policy_error:
                self._policy_error = message

    def handle_error(
        self,
        request: Any,
        client_address: tuple[str, int],
    ) -> None:
        del request, client_address


class _ConnectProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast(_ProxyServer, self.server)
        client = cast(socket.socket, self.request)
        upstream: socket.socket | None = None
        tunnel_established = False
        client.settimeout(server.io_timeout)

        try:
            headers = _read_proxy_headers(client)
            first_line = headers.split(b"\r\n", 1)[0].decode(
                "ascii",
                errors="replace",
            )
            parts = first_line.split()
            if len(parts) != 3 or parts[0].upper() != "CONNECT":
                client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return

            host, port = _parse_connect_target(parts[1])
            upstream = _connect_public_target(host, port, server.io_timeout)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            tunnel_established = True

            sockets = [client, upstream]
            while True:
                readable, _, _ = select.select(
                    sockets,
                    [],
                    [],
                    server.io_timeout,
                )
                if not readable:
                    return
                for source in readable:
                    destination = upstream if source is client else client
                    read_size = min(
                        _PROXY_BUFFER_SIZE,
                        max(1, server.budget.remaining + 1),
                    )
                    data = source.recv(read_size)
                    if not data:
                        return
                    allowed = server.budget.reserve(len(data))
                    if allowed:
                        destination.sendall(data[:allowed])
                    if allowed < len(data):
                        server.record_policy_error("browser transfer budget exceeded")
                        return
        except ValueError as exc:
            server.record_policy_error(str(exc))
            if not tunnel_established:
                try:
                    client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                except OSError:
                    pass
        except OSError:
            if not tunnel_established:
                try:
                    client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                except OSError:
                    pass
        finally:
            if upstream is not None:
                upstream.close()


class _PublicHttpsProxy:
    def __init__(self, max_transfer_bytes: int, timeout: int) -> None:
        self.budget = _TransferBudget(max_transfer_bytes)
        self._timeout = max(1.0, min(float(timeout), 10.0))
        self._server: _ProxyServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("browser proxy is not running")
        host, port = cast(tuple[str, int], self._server.server_address)
        return f"http://{host}:{port}"

    @property
    def policy_error(self) -> str:
        return self._server.policy_error if self._server is not None else ""

    def __enter__(self) -> _PublicHttpsProxy:
        self._server = _ProxyServer(self.budget, self._timeout)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: Any,
    ) -> None:
        del exc_type, exc, traceback
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def _chromium_args(proxy_url: str, max_js_heap_mb: int) -> list[str]:
    return [
        f"--proxy-server={proxy_url}",
        "--proxy-bypass-list=<-loopback>",
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-quic",
        "--disable-sync",
        "--disable-translate",
        "--metrics-recording-only",
        "--no-first-run",
        "--renderer-process-limit=2",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        f"--js-flags=--max-old-space-size={max_js_heap_mb}",
    ]


def _redirect_depth(request: Any) -> int:
    depth = 0
    current = getattr(request, "redirected_from", None)
    while current is not None:
        depth += 1
        current = getattr(current, "redirected_from", None)
    return depth


def _remaining_milliseconds(deadline: float, *, cap: int | None = None) -> int:
    remaining = int((deadline - monotonic()) * 1000)
    if remaining <= 0:
        raise RenderedWebError("browser rendering timed out")
    return min(remaining, cap) if cap is not None else remaining


def _render_public_page(
    url: str,
    *,
    max_scrolls: int,
    scroll_wait_ms: int,
    max_requests: int,
    max_transfer_bytes: int,
    max_redirects: int,
    max_js_heap_mb: int,
    timeout: int,
) -> dict[str, Any]:
    sync_playwright = _load_playwright()
    request_count = 0
    request_limited = False
    redirect_count = 0
    redirect_limited = False
    scroll_steps = 0
    scroll_limited = False
    timeout_limited = False
    final_url = url
    title = ""
    html = ""
    fallback_text = ""
    deadline = monotonic() + timeout
    proxy: _PublicHttpsProxy | None = None

    try:
        with _PublicHttpsProxy(max_transfer_bytes, timeout) as proxy:
            with sync_playwright() as playwright:
                browser: Any = None
                context: Any = None
                try:
                    browser = playwright.chromium.launch(
                        headless=True,
                        args=_chromium_args(proxy.url, max_js_heap_mb),
                    )
                    context = browser.new_context(
                        accept_downloads=False,
                        java_script_enabled=True,
                        service_workers="block",
                        user_agent=_USER_AGENT,
                    )
                    context.add_init_script(_DISABLE_WEBSOCKETS)
                    context.set_default_timeout(timeout * 1000)
                    context.set_default_navigation_timeout(timeout * 1000)

                    def handle_route(route: Any, request: Any) -> None:
                        nonlocal request_count, request_limited
                        nonlocal redirect_count, redirect_limited
                        request_count += 1
                        redirect_count = max(redirect_count, _redirect_depth(request))
                        if request_count > max_requests:
                            request_limited = True
                            route.abort("blockedbyclient")
                            return
                        if redirect_count > max_redirects:
                            redirect_limited = True
                            route.abort("blockedbyclient")
                            return
                        if not _browser_request_allowed(
                            request.url,
                            request.resource_type,
                        ):
                            route.abort("blockedbyclient")
                            return
                        route.continue_()

                    context.route("**/*", handle_route)
                    page = context.new_page()
                    page.on("popup", lambda popup: popup.close())
                    page.on("download", lambda download: download.cancel())

                    response = page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=_remaining_milliseconds(deadline),
                    )
                    if response is None:
                        raise RenderedWebError("browser navigation returned no response")
                    if proxy.budget.exceeded:
                        raise RenderedWebError("browser transfer budget exceeded")
                    if redirect_limited:
                        raise RenderedWebError("browser redirect budget exceeded")
                    final_url = page.url
                    _validate_public_https_url(final_url)

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
                        if proxy.budget.exceeded or request_limited or redirect_limited:
                            break
                        page.evaluate(
                            "() => window.scrollTo(0, document.documentElement.scrollHeight)"
                        )
                        page.wait_for_timeout(
                            _remaining_milliseconds(deadline, cap=scroll_wait_ms)
                        )
                        scroll_steps += 1
                    else:
                        scroll_limited = max_scrolls > 0

                    if proxy.budget.exceeded:
                        raise RenderedWebError("browser transfer budget exceeded")
                    if redirect_limited:
                        raise RenderedWebError("browser redirect budget exceeded")
                    if timeout_limited:
                        raise RenderedWebError("browser rendering timed out")

                    _remaining_milliseconds(deadline)
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
        if proxy is not None:
            if proxy.budget.exceeded:
                raise RenderedWebError("browser transfer budget exceeded") from exc
            if proxy.policy_error:
                raise RenderedWebError(
                    f"browser proxy blocked request: {proxy.policy_error}"
                ) from exc
        raise RenderedWebError(f"browser rendering failed: {exc}") from exc

    if proxy is None:
        raise RenderedWebError("browser proxy did not initialize")
    return {
        "final_url": final_url,
        "title": title,
        "html": html,
        "fallback_text": fallback_text,
        "request_count": request_count,
        "transfer_bytes": proxy.budget.total,
        "request_limited": request_limited,
        "transfer_limited": proxy.budget.exceeded,
        "redirect_count": redirect_count,
        "redirect_limited": redirect_limited,
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
    max_requests: int = 250,
    max_transfer_bytes: int = 20_000_000,
    max_redirects: int = 5,
    max_js_heap_mb: int = 128,
    timeout: int = 30,
) -> dict[str, Any]:
    """Render one public page, scroll boundedly, and return standard Markdown chunks."""

    if not 1_000 <= max_markdown_chars <= 1_000_000:
        raise ValueError("max_markdown_chars must be between 1000 and 1000000")
    if not 1_000 <= chunk_chars <= 50_000:
        raise ValueError("chunk_chars must be between 1000 and 50000")
    if not 0 <= max_scrolls <= 50:
        raise ValueError("max_scrolls must be between 0 and 50")
    if not 50 <= scroll_wait_ms <= 2_000:
        raise ValueError("scroll_wait_ms must be between 50 and 2000")
    if not 1 <= max_requests <= 500:
        raise ValueError("max_requests must be between 1 and 500")
    if not 100_000 <= max_transfer_bytes <= 50_000_000:
        raise ValueError("max_transfer_bytes must be between 100000 and 50000000")
    if not 0 <= max_redirects <= 10:
        raise ValueError("max_redirects must be between 0 and 10")
    if not 64 <= max_js_heap_mb <= 512:
        raise ValueError("max_js_heap_mb must be between 64 and 512")
    bounded_timeout = _bounded_timeout(timeout)
    _validate_public_https_url(url)

    rendered = _render_public_page(
        url,
        max_scrolls=max_scrolls,
        scroll_wait_ms=scroll_wait_ms,
        max_requests=max_requests,
        max_transfer_bytes=max_transfer_bytes,
        max_redirects=max_redirects,
        max_js_heap_mb=max_js_heap_mb,
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
        or rendered.get("request_limited", False)
        or rendered.get("transfer_limited", False)
        or rendered.get("redirect_limited", False)
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
        "request_count": int(rendered.get("request_count", 0)),
        "transfer_bytes": int(rendered.get("transfer_bytes", 0)),
        "redirect_count": int(rendered.get("redirect_count", 0)),
        "scroll_steps": int(rendered.get("scroll_steps", 0)),
        "max_js_heap_mb": max_js_heap_mb,
        "truncated": truncated,
    }
