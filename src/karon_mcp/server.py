#!/usr/bin/env python3
"""Karon API MCP Server."""
from karon_mcp import __version__
from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent
import httpx
import os
import json
import asyncio
import logging
import ipaddress
import math
import re
import socket
import unicodedata
from urllib.parse import urlparse, urldefrag

logger = logging.getLogger("karon-mcp")
logging.getLogger("mcp").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

mcp = FastMCP("karon-mcp")
mcp._mcp_server.version = __version__

_API_BASE = "https://api.karonlabs.net"
_ALLOWED_EXTRACTS = {"markdown", "text", "html"}
_ALLOWED_AGENT_EXTRACTS = {"markdown", "text", "html", "json", "pruned"}
_MAX_URL_LEN = 8192
_MAX_CONTENT_LEN = 200_000
_MAX_CONCURRENCY = 5
_MAX_URLS = 20
_MAX_BATCH_URLS = 50
_TIMEOUT_LOCAL = 70.0
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
_MAX_META_LEN = 2048
_MAX_REJECTED = 100

_global_sem = asyncio.Semaphore(_MAX_CONCURRENCY)
_client: httpx.AsyncClient | None = None

# --- Network access validation ---
_BLOCKED_NETS = [
    # IPv4
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),  # broadcast
    # IPv6
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fec0::/10"),
    ipaddress.ip_network("2001:db8::/32"),      # documentation
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped
    ipaddress.ip_network("64:ff9b::/96"),       # NAT64
]

# --- Control character translation table (built once) ---
_CONTROL_TRANSLATION: dict[int, str] = {}
for _i in range(32):
    if _i not in (9, 10, 13):
        _CONTROL_TRANSLATION[_i] = f"\\x{_i:02x}"
_CONTROL_TRANSLATION[0x7F] = "\\x7f"
for _i in range(0x80, 0xA0):
    _CONTROL_TRANSLATION[_i] = f"\\x{_i:02x}"
for _cp in (0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
            0x2066, 0x2067, 0x2068, 0x2069):
    _CONTROL_TRANSLATION[_cp] = ""

_SENSITIVE_RE = re.compile(
    r"(Bearer\s+\S+|api[_-]?key[=:]\S+|password[=:]\S+)", re.IGNORECASE
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _get_api_key() -> str:
    return os.environ.get("KARON_API_KEY", "")


def _debug_errors_enabled() -> bool:
    return (
        os.environ.get("KARON_MCP_ENV") == "development"
        and os.environ.get("KARON_MCP_DEBUG_ERRORS") == "1"
    )


def _log_failure(message: str, *args: object, exc: BaseException | None = None) -> None:
    if exc is not None and _debug_errors_enabled():
        logger.error(message, *args, exc_info=(type(exc), exc, exc.__traceback__))
        return
    logger.error(message, *args)


def _log_upstream_error(tool: str, upstream_error: str, status_code: int | None) -> None:
    if _debug_errors_enabled():
        detail = _redact_sensitive(_safe_str(upstream_error, max_len=512))
        logger.error("%s upstream error detail: %s (HTTP %s)", tool, detail, status_code)
        return
    logger.error("%s upstream error (HTTP %s)", tool, status_code)


async def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=_TIMEOUT_LOCAL,
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=_MAX_CONCURRENCY),
            cookies=httpx.Cookies(),
        )
    return _client


def _is_blocked_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check address (and any embedded IPv4) against blocked networks."""
    check_addrs: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [addr]
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:                 # ::ffff:x.x.x.x
            check_addrs.append(addr.ipv4_mapped)
        packed = addr.packed
        if packed[:12] == b"\x00" * 12 and packed[12:] not in (b"\x00\x00\x00\x00", b"\x00\x00\x00\x01"):
            check_addrs.append(ipaddress.IPv4Address(packed[12:]))
        if packed[:2] == b"\x20\x02":
            check_addrs.append(ipaddress.IPv4Address(packed[2:6]))
        if packed[:4] == b"\x20\x01\x00\x00":
            client_bits = int.from_bytes(packed[12:16], "big") ^ 0xFFFFFFFF
            check_addrs.append(ipaddress.IPv4Address(client_bits))
    for a in check_addrs:
        for net in _BLOCKED_NETS:
            if isinstance(a, type(net.network_address)) and a in net:
                return True
    return False


async def _validate_url(url: str) -> str | None:
    """Returns error message if invalid, None if OK."""
    if not isinstance(url, str) or not url.strip():
        return "url must be a non-empty string"

    url = url.strip()

    if "\x00" in url:
        return "url contains null byte"

    if len(url) > _MAX_URL_LEN:
        return f"url exceeds {_MAX_URL_LEN} chars"

    try:
        parsed = urlparse(url)
    except ValueError:
        return "url is malformed"

    if parsed.scheme not in ("http", "https"):
        return "url must use http or https scheme"

    hostname = parsed.hostname
    if not hostname:
        return "url has no hostname"
    try:
        port = parsed.port
        if port is not None and not (1 <= port <= 65535):
            return "url has invalid port number"
    except ValueError:
        return "url has invalid port number"
    if parsed.username or parsed.password:
        return "url must not contain credentials"
    try:
        hostname_lower = unicodedata.normalize("NFKC", hostname.lower())
    except (UnicodeError, ValueError):
        return "url hostname contains invalid characters"

    if hostname_lower in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        return "url target is not allowed"
    addr_str = hostname_lower
    if "%" in addr_str:
        addr_str = addr_str.split("%")[0]

    try:
        addr = ipaddress.ip_address(addr_str)
        if _is_blocked_ip(addr):
            return "url target is not allowed"
    except ValueError:
        pass  # Not an IP literal — proceed to DNS check
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP),
        )
        for info in infos:
            resolved_ip = info[4][0]
            try:
                addr = ipaddress.ip_address(resolved_ip)
                if _is_blocked_ip(addr):
                    return "url target is not allowed"
            except ValueError:
                continue
    except socket.gaierror:
        return "url hostname could not be resolved"

    return None


def _safe_str(val: object, *, max_len: int = 0) -> str:
    """Sanitize value for safe output. max_len=0 means no limit."""
    if isinstance(val, (dict, list)):
        try:
            s = json.dumps(val, ensure_ascii=False, allow_nan=False)
        except (ValueError, TypeError):
            s = repr(val)
    elif isinstance(val, str):
        s = val
    elif val is None:
        return ""
    else:
        s = str(val)
    s = s.translate(_CONTROL_TRANSLATION)
    if max_len and len(s) > max_len:
        s = s[:max_len] + "\n[truncated]"
    return s


def _sanitize_exception(exc: BaseException) -> str:
    """Return a stable public error message for unexpected failures."""
    return "request failed"


def _redact_sensitive(text: str) -> str:
    """Redact credentials from error text only."""
    redacted = _SENSITIVE_RE.sub("[REDACTED]", text)
    api_key = os.environ.get("KARON_API_KEY", "")
    if api_key and len(api_key) >= 4:
        redacted = redacted.replace(api_key, "[REDACTED]")
    return redacted


def _parse_response(data: object) -> dict | None:
    """Validate API response is a dict. Returns None if not."""
    if not isinstance(data, dict):
        return None
    return data


def _tool_text(text: str, *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        isError=is_error,
    )


def _build_error(msg: str, status_code: int | None = None, cost: object = None) -> CallToolResult:
    parts = [f"Error: {_redact_sensitive(_safe_str(msg, max_len=1024))}"]
    if status_code is not None:
        parts.append(f"(HTTP {status_code})")
    if cost is not None:
        parts.append(f"[credits_used: {cost}]")
    return _tool_text(" ".join(parts), is_error=True)


def _sanitize_cost(cost: object) -> object:
    """Replace NaN/Inf floats with None."""
    if isinstance(cost, float) and not math.isfinite(cost):
        return None
    return cost


def _sanitize_meta(val: object, fallback: str = "") -> str:
    """Sanitize a metadata field: safe_str + CRLF strip + size limit."""
    s = _safe_str(val, max_len=_MAX_META_LEN) if val is not None else fallback
    return s.replace("\n", " ").replace("\r", " ")[:_MAX_META_LEN]


def _validate_resolved_url(raw: object, original: str) -> str:
    """Validate resolved URL and keep only supported schemes."""
    if raw and isinstance(raw, str):
        try:
            rp = urlparse(raw)
            if rp.scheme in ("http", "https"):
                return _sanitize_meta(raw, fallback=original)
        except ValueError:
            pass
    return _sanitize_meta(original)


async def _stream_body(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    headers: dict,
    json_body: dict | None = None,
) -> tuple[bytes, int]:
    """Stream response body with a size guard."""
    stream_kwargs = {"headers": headers}
    if json_body is not None:
        stream_kwargs["json"] = json_body
    async with client.stream(method, url, **stream_kwargs) as r:
        status_code = r.status_code
        chunks: list[bytes] = []
        total = 0
        async for chunk in r.aiter_bytes(chunk_size=65536):
            total += len(chunk)
            if total > _MAX_RESPONSE_BYTES:
                raise ValueError("response too large")
            chunks.append(chunk)
    return b"".join(chunks), status_code


async def _parse_json(raw: bytes) -> object:
    """Parse response JSON, offloading large payloads."""
    if len(raw) > 1_000_000:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, json.loads, raw)
    return json.loads(raw)


def _json_dumps(data: object) -> str:
    try:
        return json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False)
    except (TypeError, ValueError):
        return _build_error("unexpected response format")


def _api_error_message(data: dict, status_code: int | None = None) -> str:
    status = data.get("status") or status_code
    if status in (400, 422):
        return "invalid request"
    if status == 401:
        return "authentication required"
    if status == 403:
        return "request not allowed"
    if status == 404:
        return "resource not found"
    if status == 408:
        return "request timeout"
    if status == 409:
        return "request conflict"
    if status == 429:
        return "rate limit exceeded"
    if isinstance(status, int) and status >= 500:
        return "service unavailable"
    if data.get("success") is False:
        return "request failed"
    return "request failed"


def _format_api_response(data: object, status_code: int | None = None) -> str:
    parsed = _parse_response(data)
    if parsed is None:
        return _build_error("unexpected response format", status_code=status_code)

    cost = _sanitize_cost(parsed.get("cost_credits"))
    if parsed.get("success") is False:
        return _build_error(_api_error_message(parsed, status_code), status_code=status_code, cost=cost)
    if status_code is not None and status_code >= 400:
        return _build_error(_api_error_message(parsed, status_code), status_code=status_code, cost=cost)
    return _json_dumps(parsed)


async def _api_json_request(
    method: str,
    path: str,
    *,
    api_key: str | None = None,
    json_body: dict | None = None,
) -> tuple[object | None, str | None, int | None]:
    status_code: int | None = None
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        client = await _get_client()
        raw, status_code = await _stream_body(
            client,
            method,
            f"{_API_BASE}{path}",
            headers=headers,
            json_body=json_body,
        )
        client.cookies.clear()
    except httpx.HTTPError as e:
        _log_failure("API request failed for %s %s", method, path, exc=e)
        return None, _build_error(_sanitize_exception(e), status_code=status_code), status_code
    except ValueError as e:
        return None, _build_error(str(e), status_code=status_code), status_code
    except Exception as e:
        _log_failure("API request failed for %s %s", method, path, exc=e)
        return None, _build_error(_sanitize_exception(e), status_code=status_code), status_code

    try:
        return await _parse_json(raw), None, status_code
    except Exception:
        logger.error("API JSON parse failed for %s %s (HTTP %s)", method, path, status_code)
        return None, _build_error("JSON parse failed", status_code=status_code), status_code


def _require_api_key() -> str | None:
    api_key = _get_api_key()
    return api_key or None


def _validate_extract(extract: str) -> str | None:
    if not isinstance(extract, str):
        return "extract must be a string"
    if extract not in _ALLOWED_EXTRACTS:
        return f"extract must be one of {sorted(_ALLOWED_EXTRACTS)}"
    return None


def _normalize_formats(formats: list[str] | None) -> tuple[list[str] | None, str | None]:
    if formats is None:
        return ["markdown"], None
    if not isinstance(formats, list) or not formats:
        return None, "formats must be a non-empty list of strings"
    normalized: list[str] = []
    for item in formats:
        if not isinstance(item, str):
            return None, "formats must be a list of strings"
        fmt = item.strip().lower()
        if fmt not in _ALLOWED_EXTRACTS:
            return None, f"formats must contain only {sorted(_ALLOWED_EXTRACTS)}"
        normalized.append(fmt)
    return normalized, None


def _validate_common_options(
    *,
    readability: bool | None = None,
    wait_timeout_ms: int | None = None,
    concurrency: int | None = None,
    ttl_days: int | None = None,
) -> str | None:
    if readability is not None and not isinstance(readability, bool):
        return "readability must be a boolean"
    if wait_timeout_ms is not None:
        if not isinstance(wait_timeout_ms, int) or isinstance(wait_timeout_ms, bool):
            return "wait_timeout_ms must be an integer"
        if not (1000 <= wait_timeout_ms <= 30000):
            return "wait_timeout_ms must be between 1000 and 30000"
    if concurrency is not None:
        if not isinstance(concurrency, int) or isinstance(concurrency, bool):
            return "concurrency must be an integer"
        if not (1 <= concurrency <= 10):
            return "concurrency must be between 1 and 10"
    if ttl_days is not None:
        if not isinstance(ttl_days, int) or isinstance(ttl_days, bool):
            return "ttl_days must be an integer"
        if not (1 <= ttl_days <= 30):
            return "ttl_days must be between 1 and 30"
    return None


def _add_optional(payload: dict, **values: object) -> dict:
    for key, value in values.items():
        if value is not None:
            payload[key] = value
    return payload


# ── MCP tools ────────────────────────────────────────────────────────────────

@mcp.tool(structured_output=False)
async def browse(
    url: str,
    extract: str = "markdown",
    readability: bool = True,
):
    """
    Fetch a single URL through the Karon API.
    Returns clean text or markdown. Costs 1 credit (cache) or 10 credits (fresh retrieval).

    Args:
        url: Target URL (must start with http/https)
        extract: Output format — "markdown" | "text" | "html"
        readability: True = main content only (default). False = full page.
    """
    api_key = _get_api_key()
    if not api_key:
        return _build_error("KARON_API_KEY environment variable not set")

    url_err = await _validate_url(url)  # async
    if url_err:
        return _build_error(url_err)

    if not isinstance(extract, str):
        return _build_error("extract must be a string")
    if extract not in _ALLOWED_EXTRACTS:
        return _build_error(f"extract must be one of {sorted(_ALLOWED_EXTRACTS)}")

    if not isinstance(readability, bool):
        return _build_error("readability must be a boolean")

    status_code: int | None = None
    async with _global_sem:
        try:
            client = await _get_client()
            raw, status_code = await _stream_body(
                client, "POST", f"{_API_BASE}/v1/agent/browse",
                headers={"Authorization": f"Bearer {api_key}"},
                json_body={"url": url, "extract": extract, "readability": readability},
            )
            client.cookies.clear()
        except httpx.HTTPError as e:
            _log_failure("browse network request failed", exc=e)
            return _build_error(_sanitize_exception(e))
        except ValueError as e:
            # "response too large" from _stream_body
            return _build_error(str(e), status_code=status_code)
        except Exception as e:
            _log_failure("browse request failed", exc=e)
            return _build_error(_sanitize_exception(e))

    try:
        data = await _parse_json(raw)
    except Exception:
        logger.error("browse JSON parse failed (HTTP %s)", status_code)
        return _build_error("JSON parse failed", status_code=status_code)

    data = _parse_response(data)
    if data is None:
        return _build_error("unexpected response format", status_code=status_code)

    success = data.get("success")
    cost = _sanitize_cost(data.get("cost_credits"))

    if success is not True:
        upstream_error = _safe_str(data.get("error", "unknown"), max_len=512)
        _log_upstream_error("browse", upstream_error, status_code)
        return _build_error(
            _api_error_message(data, status_code),
            status_code=status_code,
            cost=cost,
        )

    if status_code is not None and status_code >= 400:
        return _build_error("HTTP error with success flag", status_code=status_code, cost=cost)

    raw_content = data.get("content")
    content = _safe_str(raw_content, max_len=_MAX_CONTENT_LEN) if raw_content is not None else ""

    resolved_url = _validate_resolved_url(data.get("url"), url)
    timing = data.get("timing")
    cache_hit = timing.get("cache_hit", "?") if isinstance(timing, dict) else "?"

    if extract == "html":
        return json.dumps({
            "source": resolved_url,
            "credits_used": cost,
            "cache_hit": cache_hit,
            "content": content,
        }, ensure_ascii=False, allow_nan=False)

    lines = [
        f"[source]: {resolved_url}",
        f"[credits_used]: {cost if cost is not None else '?'}",
        f"[cache_hit]: {cache_hit}",
        "---",
        content,
    ]
    return "\n".join(lines)


@mcp.tool(structured_output=False)
async def crawl(
    urls: list[str],
    extract: str = "markdown",
    readability: bool = True,
    concurrency: int = 3,
):
    """
    Fetch multiple URLs concurrently. Returns JSON array of results.

    Args:
        urls: List of URLs (max 20)
        extract: Output format — "markdown" | "text"
        readability: True = main content only (default). False = full page.
        concurrency: Parallel requests (1-5, default 3)
    """
    api_key = _get_api_key()
    if not api_key:
        return _build_error("KARON_API_KEY environment variable not set")

    if not isinstance(urls, list):
        return _build_error("urls must be a list of strings")
    if not isinstance(concurrency, int) or isinstance(concurrency, bool):
        return _build_error("concurrency must be an integer")

    if not isinstance(extract, str):
        return _build_error("extract must be a string")
    if extract not in _ALLOWED_EXTRACTS:
        return _build_error(f"extract must be one of {sorted(_ALLOWED_EXTRACTS)}")

    if not isinstance(readability, bool):
        return _build_error("readability must be a boolean")
    if len(urls) > _MAX_URLS:
        return _build_error(f"too many URLs: {len(urls)} (max {_MAX_URLS})")

    concurrency = max(1, min(_MAX_CONCURRENCY, concurrency))

    # --- URL validation and deduplication ---
    validated: list[str] = []
    rejected: list[dict] = []
    seen: set[str] = set()

    for u in urls:
        if not isinstance(u, str) or not u.strip():
            if len(rejected) < _MAX_REJECTED:
                rejected.append({"url": _safe_str(u, max_len=256), "error": "invalid url type or empty"})
            continue

        u = u.strip()
        u_defrag, _ = urldefrag(u)
        try:
            p = urlparse(u_defrag)
            dedup_key = f"{p.scheme}://{(p.hostname or '').lower()}{p.path}{'?' + p.query if p.query else ''}"
        except ValueError:
            dedup_key = u_defrag.lower()
        if dedup_key in seen:
            if len(rejected) < _MAX_REJECTED:
                rejected.append({"url": u, "success": False, "content": "", "error": "duplicate URL (skipped)"})
            continue
        seen.add(dedup_key)

        url_err = await _validate_url(u_defrag)  # async
        if url_err:
            if len(rejected) < _MAX_REJECTED:
                rejected.append({"url": u, "error": url_err})
            continue

        validated.append(u_defrag)

    # --- fetch logic ---
    local_sem = asyncio.Semaphore(concurrency)

    async def fetch_one(target_url: str) -> dict:
        try:
            async with asyncio.timeout(_TIMEOUT_LOCAL + 5):
                async with local_sem:
                    async with _global_sem:
                        try:
                            client = await _get_client()
                            raw, status_code = await _stream_body(
                                client, "POST", f"{_API_BASE}/v1/agent/browse",
                                headers={"Authorization": f"Bearer {api_key}"},
                                json_body={"url": target_url, "extract": extract, "readability": readability},
                            )
                            client.cookies.clear()
                        except httpx.HTTPError as e:
                            _log_failure("crawl network failed for %s", target_url, exc=e)
                            return {"url": target_url, "success": False, "content": "", "error": _sanitize_exception(e)}
                        except ValueError as e:
                            return {"url": target_url, "success": False, "content": "", "error": str(e)}
                        except Exception as e:
                            _log_failure("crawl fetch failed for %s", target_url, exc=e)
                            return {"url": target_url, "success": False, "content": "", "error": _sanitize_exception(e)}

                        status_code_val = status_code
                        try:
                            data = await _parse_json(raw)
                        except Exception:
                            logger.error("crawl JSON parse failed for %s (HTTP %d)", target_url, status_code_val)
                            return {"url": target_url, "success": False, "content": "", "error": "JSON parse failed", "status_code": status_code_val}

                        if not isinstance(data, dict):
                            return {"url": target_url, "success": False, "content": "", "error": "unexpected response format", "status_code": status_code_val}

                        success = data.get("success") is True
                        if success and status_code_val >= 400:
                            success = False

                        cost = _sanitize_cost(data.get("cost_credits"))

                        if success:
                            raw_content = data.get("content")
                            content = _safe_str(raw_content, max_len=_MAX_CONTENT_LEN) if raw_content is not None else ""
                            error = None
                        else:
                            content = ""
                            upstream_error = _safe_str(data.get("error", "unknown"), max_len=512)
                            _log_upstream_error("crawl", upstream_error, status_code_val)
                            error = _api_error_message(data, status_code_val)

                        return {
                            "url": target_url,
                            "resolved_url": _validate_resolved_url(data.get("url"), target_url),
                            "success": success,
                            "content": content,
                            "error": error,
                            "cost_credits": cost,
                            "status_code": status_code_val,
                        }
        except TimeoutError:
            return {"url": target_url, "success": False, "content": "", "error": "per-URL timeout exceeded"}

    # --- task execution ---
    task_pairs: list[tuple[str, asyncio.Task]] = []
    for u in validated:
        t = asyncio.create_task(fetch_one(u))
        task_pairs.append((u, t))

    all_tasks = [t for _, t in task_pairs]
    batch_timeout = _TIMEOUT_LOCAL * len(validated) / max(concurrency, 1) + 30

    if all_tasks:
        done, pending = await asyncio.wait(all_tasks, timeout=batch_timeout)
        for t in pending:
            t.cancel()
    else:
        done, pending = set(), set()
    final: list[dict] = []
    for url_str, t in task_pairs:
        if t in done:
            exc = t.exception()
            if exc:
                final.append({"url": url_str, "success": False, "content": "", "error": _sanitize_exception(exc)})
            else:
                final.append(t.result())
        else:
            final.append({"url": url_str, "success": False, "content": "", "error": "batch timeout exceeded"})

    if rejected:
        for rej in rejected:
            rej.setdefault("success", False)
            rej.setdefault("content", "")
            final.append(rej)

    has_success = any(item.get("success") is True for item in final)
    return _tool_text(
        json.dumps(final, ensure_ascii=False, indent=2, allow_nan=False),
        is_error=not has_success,
    )


@mcp.tool(structured_output=False)
async def scrape(
    url: str,
    formats: list[str] | None = None,
    readability: bool = True,
    wait_selector: str | None = None,
    wait_timeout_ms: int = 10000,
):
    """
    Retrieve one URL and return the requested content format.

    Args:
        url: Target URL (must start with http/https)
        formats: Output formats. Defaults to ["markdown"].
        readability: True = main content only. False = full page.
        wait_selector: Optional CSS selector to wait for.
        wait_timeout_ms: Selector wait timeout in milliseconds.
    """
    api_key = _require_api_key()
    if not api_key:
        return _build_error("KARON_API_KEY environment variable not set")

    url_err = await _validate_url(url)
    if url_err:
        return _build_error(url_err)
    opt_err = _validate_common_options(
        readability=readability,
        wait_timeout_ms=wait_timeout_ms,
    )
    if opt_err:
        return _build_error(opt_err)
    normalized_formats, formats_err = _normalize_formats(formats)
    if formats_err:
        return _build_error(formats_err)

    payload = {
        "url": url.strip(),
        "extract": normalized_formats[0],
        "readability": readability,
    }
    _add_optional(payload, wait_selector=wait_selector, wait_timeout_ms=wait_timeout_ms)

    data, err, status_code = await _api_json_request(
        "POST",
        "/v1/agent/browse",
        api_key=api_key,
        json_body=payload,
    )
    return err or _format_api_response(data, status_code=status_code)


@mcp.tool(structured_output=False)
async def fetch(
    url: str,
    wait_selector: str | None = None,
    wait_timeout_ms: int = 10000,
    session_id: str | None = None,
):
    """
    Retrieve raw page data for one URL.

    Args:
        url: Target URL (must start with http/https)
        wait_selector: Optional CSS selector to wait for.
        wait_timeout_ms: Selector wait timeout in milliseconds.
        session_id: Optional session identifier.
    """
    api_key = _require_api_key()
    if not api_key:
        return _build_error("KARON_API_KEY environment variable not set")

    url_err = await _validate_url(url)
    if url_err:
        return _build_error(url_err)
    opt_err = _validate_common_options(wait_timeout_ms=wait_timeout_ms)
    if opt_err:
        return _build_error(opt_err)
    if session_id is not None and not isinstance(session_id, str):
        return _build_error("session_id must be a string")
    if wait_selector is not None and not isinstance(wait_selector, str):
        return _build_error("wait_selector must be a string")

    payload = {
        "url": url.strip(),
        "wait_timeout_ms": wait_timeout_ms,
    }
    _add_optional(payload, wait_selector=wait_selector, session_id=session_id)

    data, err, status_code = await _api_json_request(
        "POST",
        "/v1/fetch",
        api_key=api_key,
        json_body=payload,
    )
    return err or _format_api_response(data, status_code=status_code)


@mcp.tool(structured_output=False)
async def extract(
    url: str,
    json_schema: dict | None = None,
    prompt: str | None = None,
    readability: bool = True,
):
    """
    Retrieve one URL and return structured JSON data.

    Args:
        url: Target URL (must start with http/https)
        json_schema: Optional JSON schema for the extraction result.
        prompt: Optional extraction instruction.
        readability: True = main content only. False = full page.
    """
    api_key = _require_api_key()
    if not api_key:
        return _build_error("KARON_API_KEY environment variable not set")

    url_err = await _validate_url(url)
    if url_err:
        return _build_error(url_err)
    opt_err = _validate_common_options(readability=readability)
    if opt_err:
        return _build_error(opt_err)
    if json_schema is not None and not isinstance(json_schema, dict):
        return _build_error("json_schema must be an object")
    if prompt is not None and not isinstance(prompt, str):
        return _build_error("prompt must be a string")

    payload = {
        "url": url.strip(),
        "extract": "json",
        "readability": readability,
    }
    _add_optional(payload, json_schema=json_schema, json_prompt=prompt)

    data, err, status_code = await _api_json_request(
        "POST",
        "/v1/agent/browse",
        api_key=api_key,
        json_body=payload,
    )
    return err or _format_api_response(data, status_code=status_code)


@mcp.tool(structured_output=False)
async def batch_scrape(
    urls: list[str],
    formats: list[str] | None = None,
    readability: bool = True,
    concurrency: int = 3,
):
    """
    Retrieve multiple URLs in one request.

    Args:
        urls: List of URLs (max 50)
        formats: Output formats. Defaults to ["markdown"].
        readability: True = main content only. False = full page.
        concurrency: Parallel requests (1-10, default 3)
    """
    api_key = _require_api_key()
    if not api_key:
        return _build_error("KARON_API_KEY environment variable not set")

    if not isinstance(urls, list):
        return _build_error("urls must be a list of strings")
    if not urls:
        return _build_error("urls must not be empty")
    if len(urls) > _MAX_BATCH_URLS:
        return _build_error(f"too many URLs: {len(urls)} (max {_MAX_BATCH_URLS})")
    opt_err = _validate_common_options(
        readability=readability,
        concurrency=concurrency,
    )
    if opt_err:
        return _build_error(opt_err)
    normalized_formats, formats_err = _normalize_formats(formats)
    if formats_err:
        return _build_error(formats_err)

    cleaned_urls: list[str] = []
    for item in urls:
        if not isinstance(item, str) or not item.strip():
            return _build_error("urls must be a list of non-empty strings")
        cleaned = item.strip()
        url_err = await _validate_url(cleaned)
        if url_err:
            return _build_error(url_err)
        cleaned_urls.append(cleaned)

    payload = {
        "urls": cleaned_urls,
        "extract": normalized_formats[0],
        "readability": readability,
        "concurrency": concurrency,
    }

    data, err, status_code = await _api_json_request(
        "POST",
        "/v1/agent/crawl",
        api_key=api_key,
        json_body=payload,
    )
    return err or _format_api_response(data, status_code=status_code)


@mcp.tool(structured_output=False)
async def watch_snapshot(
    url: str,
    extract: str = "markdown",
    readability: bool = True,
    ttl_days: int = 7,
    json_schema: dict | None = None,
    prompt: str | None = None,
):
    """
    Save a snapshot for one URL and return snapshot metadata.

    Args:
        url: Target URL (must start with http/https)
        extract: Output mode: "markdown", "text", "html", "json", or "pruned".
        readability: True = main content only. False = full page.
        ttl_days: Snapshot retention in days (1-30).
        json_schema: Optional JSON schema when extract is "json".
        prompt: Optional extraction instruction when extract is "json".
    """
    api_key = _require_api_key()
    if not api_key:
        return _build_error("KARON_API_KEY environment variable not set")

    url_err = await _validate_url(url)
    if url_err:
        return _build_error(url_err)
    opt_err = _validate_common_options(
        readability=readability,
        ttl_days=ttl_days,
    )
    if opt_err:
        return _build_error(opt_err)
    if not isinstance(extract, str) or extract not in _ALLOWED_AGENT_EXTRACTS:
        return _build_error(f"extract must be one of {sorted(_ALLOWED_AGENT_EXTRACTS)}")
    if json_schema is not None and not isinstance(json_schema, dict):
        return _build_error("json_schema must be an object")
    if prompt is not None and not isinstance(prompt, str):
        return _build_error("prompt must be a string")

    payload = {
        "url": url.strip(),
        "extract": extract,
        "readability": readability,
        "ttl_days": ttl_days,
    }
    _add_optional(payload, json_schema=json_schema, json_prompt=prompt)

    data, err, status_code = await _api_json_request(
        "POST",
        "/v1/watch/snapshot",
        api_key=api_key,
        json_body=payload,
    )
    return err or _format_api_response(data, status_code=status_code)


@mcp.tool(structured_output=False)
async def watch_diff(
    url: str,
    extract: str = "markdown",
    readability: bool = True,
    json_schema: dict | None = None,
    prompt: str | None = None,
):
    """
    Compare the current URL snapshot with the previous saved snapshot.

    Args:
        url: Target URL (must start with http/https)
        extract: Output mode: "markdown", "text", "html", "json", or "pruned".
        readability: True = main content only. False = full page.
        json_schema: Optional JSON schema when extract is "json".
        prompt: Optional extraction instruction when extract is "json".
    """
    api_key = _require_api_key()
    if not api_key:
        return _build_error("KARON_API_KEY environment variable not set")

    url_err = await _validate_url(url)
    if url_err:
        return _build_error(url_err)
    opt_err = _validate_common_options(readability=readability)
    if opt_err:
        return _build_error(opt_err)
    if not isinstance(extract, str) or extract not in _ALLOWED_AGENT_EXTRACTS:
        return _build_error(f"extract must be one of {sorted(_ALLOWED_AGENT_EXTRACTS)}")
    if json_schema is not None and not isinstance(json_schema, dict):
        return _build_error("json_schema must be an object")
    if prompt is not None and not isinstance(prompt, str):
        return _build_error("prompt must be a string")

    payload = {
        "url": url.strip(),
        "extract": extract,
        "readability": readability,
    }
    _add_optional(payload, json_schema=json_schema, json_prompt=prompt)

    data, err, status_code = await _api_json_request(
        "POST",
        "/v1/watch/diff",
        api_key=api_key,
        json_body=payload,
    )
    return err or _format_api_response(data, status_code=status_code)


@mcp.tool(structured_output=False)
async def watch_list():
    """
    List saved watch targets for the configured API key.
    """
    api_key = _require_api_key()
    if not api_key:
        return _build_error("KARON_API_KEY environment variable not set")

    data, err, status_code = await _api_json_request(
        "GET",
        "/v1/watch/list",
        api_key=api_key,
    )
    return err or _format_api_response(data, status_code=status_code)


@mcp.tool(structured_output=False)
async def credits():
    """
    Return account credit and tier information for the configured API key.
    """
    api_key = _require_api_key()
    if not api_key:
        return _build_error("KARON_API_KEY environment variable not set")

    data, err, status_code = await _api_json_request(
        "GET",
        "/v1/credits",
        api_key=api_key,
    )
    return err or _format_api_response(data, status_code=status_code)


@mcp.tool(structured_output=False)
async def pricing():
    """
    Return public pricing information.
    """
    data, err, status_code = await _api_json_request("GET", "/v1/pricing")
    return err or _format_api_response(data, status_code=status_code)


if __name__ == "__main__":
    mcp.run()
