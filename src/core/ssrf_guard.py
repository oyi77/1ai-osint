"""SSRF protection — validate scan targets before any outbound request.

The deep-scan engine interpolates user-supplied targets (domains, IPs)
into outbound HTTP/HTTPS fetches (``https://{target}``,
``https://ipinfo.io/{ip}/json``, ...). Without validation an operator
could point the scanner at loopback, link-local, or cloud-metadata
addresses (``169.254.169.254``, ``127.0.0.1``, ...), turning the scanner
into an SSRF proxy.

:func:`validate_scan_target` is the single entry point. It blocks
private/internal/reserved hosts while still allowing:

* public IP literals (``8.8.8.8``),
* unresolvable hostnames (test fixtures, TLD-only fake domains) —
  a DNS failure is treated as "cannot prove it is private" and allowed,
* non-network targets (usernames, emails, phone numbers, crypto
  addresses) that have no host-like component.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket

logger = logging.getLogger(__name__)

# Hostnames that are never valid scan targets, regardless of DNS.
_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "localhost6",
        "localhost6.localdomain6",
        "metadata",
        "metadata.google.internal",
    }
)

_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_USERINFO_RE = re.compile(r"^(?:[^@/?#]*@)")
_PORT_RE = re.compile(r":(\d{1,5})$")


def validate_scan_target(target: object) -> bool:
    """Return True when *target* is safe to scan, False when it is private.

    Private/internal/reserved hosts (loopback, RFC1918, link-local,
    metadata, multicast, ...) are rejected. Anything else — public IPs,
    unresolvable hostnames, and non-network identifiers — is allowed so
    legitimate username/email/phone/crypto scans keep working.
    """
    if not isinstance(target, str) or not target.strip():
        return True  # nothing to check; empty targets are rejected upstream
    host = _extract_host(target.strip())
    if host is None:
        return True  # not a network target (username, email, phone, ...)
    return _host_is_safe(host)


def _extract_host(target: str) -> str | None:
    """Return the host part of *target*, or None when it is not host-like.

    Handles bare hosts (``example.com``, ``8.8.8.8``, ``::1``), URLs
    (``https://example.com/path``, ``http://[::1]:8080/x``), userinfo
    (``user:pass@host``) and emails (``user@example.com`` → the domain).
    """
    value = target
    if _SCHEME_RE.match(value):
        value = _SCHEME_RE.sub("", value)
    elif "://" in value:
        return None  # malformed scheme — not a URL, treat as non-network
    else:
        # Non-URL form. An email ("user@example.com") contributes its
        # domain; a bare userinfo form is treated the same way. Anything
        # after '@' that is not host-like means the target is a plain
        # identifier (e.g. a phone number with a suffix) — allow it.
        at = value.rfind("@")
        if at != -1:
            domain = value[at + 1 :]
            if not _looks_like_host(domain):
                return None
            value = domain

    # user:pass@host
    if _USERINFO_RE.match(value):
        value = _USERINFO_RE.sub("", value)
    # Path / query / fragment — strip before the port so "host:8080/path"
    # still loses its port (the port regex is end-anchored).
    for sep in ("/", "?", "#"):
        idx = value.find(sep)
        if idx != -1:
            value = value[:idx]
    # [::1]:8080 → [::1]  |  host:8080 → host
    value = _strip_port(value)
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    value = value.strip().rstrip(".")
    return value or None


def _looks_like_host(value: str) -> bool:
    """Heuristic: a dotted hostname or an IPv6 literal looks like a host."""
    return "." in value or ":" in value


def _strip_port(value: str) -> str:
    if value.startswith("["):
        closing = value.find("]")
        return value[: closing + 1] if closing != -1 else value
    match = _PORT_RE.search(value)
    if match and ":" not in value[: match.start()]:
        return value[: match.start()]
    return value


def _host_is_safe(host: str) -> bool:
    lower = host.lower()
    if lower in _BLOCKED_HOSTNAMES:
        logger.warning("SSRF guard: blocked hostname %r", host)
        return False

    # IP literal — check directly, no DNS round trip.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return not _is_blocked_ip(ip)

    # Numeric-literal IP forms (decimal "2130706433", hex "0x7f000001",
    # octal "017700000001") are accepted by inet_aton and can alias
    # loopback/private addresses — treat them like their dotted forms.
    if len(host) >= 7 and (
        host.isdigit()
        or (lower.startswith("0x") and len(host) > 2)
        or (len(host) > 1 and host[0] == "0" and all(c in "01234567" for c in host))
    ):
        base = 16 if lower.startswith("0x") else (8 if len(host) > 1 and host[0] == "0" else 10)
        try:
            numeric = ipaddress.IPv4Address(int(host, base))
        except ValueError:
            numeric = None
        if numeric is not None:
            return not _is_blocked_ip(numeric)

    # Hostname — only resolve when it looks like one; plain usernames
    # (no dot, no colon) are never sent to a resolver.
    if not _looks_like_host(host):
        return True
    ips = _resolve(host)
    if ips is None:
        return True  # unresolvable — allow (fixtures, fake domains)
    for ip in ips:
        if _is_blocked_ip(ip):
            logger.warning("SSRF guard: blocked %r -> %s", host, ip)
            return False
    return True


def _resolve(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address] | None:
    """Resolve *host* to unique IPs; None on resolution failure."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return None
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True when *ip* is loopback / private / link-local / multicast / reserved."""
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if ip.is_private:
        return True
    if ip.version == 6 and ip.is_site_local:
        return True
    if not ip.is_global:
        return True  # shared space, documentation, other non-global ranges
    return False
