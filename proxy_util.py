# -*- coding: utf-8 -*-
"""Normalize proxy strings into URL / Playwright forms.

Accepted input examples:
    host:port
    user:pass@host:port
    host:port:user:pass
    user:pass:host:port
    http://user:pass@host:port
    socks5://host:port:user:pass
"""
from __future__ import annotations

import re
from urllib.parse import quote, unquote
from typing import Optional

_SCHEMES = {"http", "https", "socks4", "socks5", "socks5h"}
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_IPV6_BRACKET_RE = re.compile(r"^(\[[0-9A-Fa-f:.]+])(?::(\d{1,5}))(?::(.*))?$")
_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://(.+)$")


def _valid_port(value: str) -> bool:
    if not value or not value.isdigit():
        return False
    return 1 <= int(value) <= 65535


def _valid_host(host: str) -> bool:
    if not host:
        return False
    if host.startswith("[") and host.endswith("]") and len(host) > 2:
        return True
    return bool(_IPV4_RE.match(host) or _HOST_RE.match(host))


def _split_userinfo(userinfo: str) -> tuple[str, str]:
    if ":" in userinfo:
        user, password = userinfo.split(":", 1)
        return user, password
    return userinfo, ""


def _split_hostport(hostport: str) -> tuple[str, str]:
    hostport = (hostport or "").strip()
    if not hostport:
        return "", ""
    if hostport.startswith("["):
        match = re.match(r"^(\[[^\]]+])(?::(\d{1,5}))?$", hostport)
        if not match:
            return "", ""
        return match.group(1), match.group(2) or ""
    if ":" in hostport:
        host, port = hostport.rsplit(":", 1)
        return host, port
    return hostport, ""


def parse_proxy(raw: str) -> Optional[dict[str, object]]:
    """Return {scheme, host, port, username, password} or None if unusable."""
    text = (raw or "").strip()
    if not text or text.startswith("#"):
        return None

    scheme = "http"
    rest = text
    match = _SCHEME_RE.match(text)
    if match:
        scheme = match.group(1).lower()
        rest = match.group(2)
        if scheme not in _SCHEMES:
            return None
    rest = rest.split("/", 1)[0].strip()
    if not rest:
        return None

    username = ""
    password = ""
    host = ""
    port = ""

    if rest.startswith("["):
        v6 = _IPV6_BRACKET_RE.match(rest)
        if not v6:
            return None
        host, port, extra = v6.group(1), v6.group(2), v6.group(3)
        if extra is not None:
            username, password = _split_userinfo(extra)
    elif "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
        username, password = _split_userinfo(userinfo)
        host, port = _split_hostport(hostport)
    else:
        parts = rest.split(":")
        if len(parts) == 2 and _valid_port(parts[1]) and _valid_host(parts[0]):
            host, port = parts[0], parts[1]
        elif len(parts) >= 4 and _valid_host(parts[0]) and _valid_port(parts[1]):
            host, port, username = parts[0], parts[1], parts[2]
            password = ":".join(parts[3:])
        elif (
            len(parts) >= 4
            and _valid_host(parts[-2])
            and _valid_port(parts[-1])
            and not _valid_port(parts[1])
        ):
            username = parts[0]
            password = ":".join(parts[1:-2])
            host, port = parts[-2], parts[-1]
        elif len(parts) == 3 and _valid_host(parts[0]) and _valid_port(parts[1]):
            host, port, username = parts[0], parts[1], parts[2]
        else:
            return None

    host = (host or "").strip()
    port = (port or "").strip()
    if not _valid_host(host) or not _valid_port(port):
        return None
    return {
        "scheme": scheme,
        "host": host,
        "port": int(port),
        "username": unquote(username) if username else "",
        "password": unquote(password) if password else "",
    }


def normalize_proxy_url(raw: str) -> str:
    """Canonical `scheme://[user:pass@]host:port`, or empty if invalid."""
    parsed = parse_proxy(raw)
    if not parsed:
        return ""
    auth = ""
    if parsed["username"] or parsed["password"]:
        user = quote(str(parsed["username"]), safe="")
        pwd = quote(str(parsed["password"]), safe="")
        auth = f"{user}:{pwd}@"
    return f"{parsed['scheme']}://{auth}{parsed['host']}:{parsed['port']}"


def playwright_proxy(raw: str, *, bypass: str = "") -> Optional[dict[str, str]]:
    """Playwright/Camoufox launch proxy dict, credentials split out of server."""
    parsed = parse_proxy(raw)
    if not parsed:
        return None
    scheme = str(parsed["scheme"])
    if scheme == "socks5h":
        scheme = "socks5"
    cfg: dict[str, str] = {"server": f"{scheme}://{parsed['host']}:{parsed['port']}"}
    if parsed["username"]:
        cfg["username"] = str(parsed["username"])
    if parsed["password"]:
        cfg["password"] = str(parsed["password"])
    if bypass:
        cfg["bypass"] = bypass
    return cfg
