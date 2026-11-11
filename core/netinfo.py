"""Local IPv4 discovery for the GUI bind dropdown (v2.8).

Why this module exists: the bind choice used to be a binary — 127.0.0.1
(no network at all) or 0.0.0.0 (every interface). Operators who wanted
"this machine's LAN address only" had no entry to pick. This module
finds the machine's real IPv4 addresses so the dropdown can offer them.

Design constraints (both hold):

* **Zero packets.** The primary-route address comes from the UDP-connect
  trick: connect() a datagram socket to a TEST-NET-1 address
  (192.0.2.1, RFC 5737 — reserved, never routed). The kernel picks the
  outgoing interface and fills in the local address without sending
  anything. connect() on a UDP socket is a local routing-table lookup.
* **Stdlib only, no subprocess.** No `ip`/`ipconfig` parsing, no Qt —
  so this stays unit-testable headless and platform-independent.

Dropped from results: 127.* loopback (already a dropdown entry) and
169.254.* APIPA (link-local; DHCP failure or modern VPN ranges — not
something to bind to deliberately).
"""
from __future__ import annotations

import socket

# RFC 5737 TEST-NET-1: guaranteed unroutable, so connect() performs only
# a routing-table lookup. Port 9 (discard) — no service is contacted.
_PROBE_ADDR = ("192.0.2.1", 9)


def _primary_route_ipv4() -> "str | None":
    """The IPv4 of the interface the kernel would use to reach the
    internet. Sends no packets; returns None when there is no route."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(_PROBE_ADDR)
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _hostname_ipv4s() -> list:
    """Every IPv4 the resolver maps this machine's hostname to
    (catches secondary interfaces: wired + VPN, multi-homed hosts)."""
    try:
        name = socket.gethostname()
        infos = socket.getaddrinfo(name, None, socket.AF_INET)
    except (OSError, socket.gaierror):
        return []
    out = []
    for _fam, _typ, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip and ip not in out:
            out.append(ip)
    return out


def _bindable(ip: str) -> bool:
    """True if the address makes sense as a deliberate bind target."""
    return not (ip.startswith("127.") or ip.startswith("169.254."))


def local_ipv4s() -> list:
    """This machine's real IPv4 addresses, primary route first.
    Sends no packets and never raises."""
    primary = _primary_route_ipv4()
    ordered = ([primary] if primary and _bindable(primary) else [])
    for ip in _hostname_ipv4s():
        if _bindable(ip) and ip not in ordered:
            ordered.append(ip)
    return ordered


def bind_scope(host: str) -> str:
    """Classify a bind address: "loopback", "wildcard" or "specific".

    "specific" is the v2.8 middle ground — one real interface, so the
    server is reachable on the LAN but not on every interface the
    machine owns. The GUI's exposure warning and the agent prompt's
    Host line both branch on this."""
    h = (host or "").strip()
    if h in ("0.0.0.0", "::", ""):
        return "wildcard"
    if h in ("127.0.0.1", "localhost", "::1"):
        return "loopback"
    return "specific"
