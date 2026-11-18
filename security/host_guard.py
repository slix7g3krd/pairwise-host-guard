"""Host-header validation for a multi-domain reverse-proxy deployment.

The ``Host`` header (and ``X-Forwarded-Host``) are attacker-controlled input.
Every helper here is fail-closed: anything that cannot be parsed as a plain,
unambiguous DNS hostname is rejected rather than guessed at.
"""

import ipaddress
import re

__all__ = [
    "parse_host",
    "host_allowed",
    "is_ip_literal",
    "validate_forwarded",
    "dns_rebind_ok",
]

# A single DNS label: 1-63 chars, alphanumeric and hyphen, no leading/trailing
# hyphen.  The full name is capped at 253 octets (255 with the root dot).
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
_MAX_HOST_LEN = 253

# Names that always resolve to the local machine and must never be served,
# regardless of what the allow-list happens to contain.
_LOCAL_NAMES = frozenset({"localhost", "localhost.localdomain"})


def _valid_port(value: str) -> bool:
    return bool(value) and value.isascii() and value.isdigit() and 0 < int(value) <= 65535


def _is_ipv6_literal(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


def _normalize_hostname(value: str) -> str:
    """Lower-case, drop one trailing root dot and validate DNS syntax."""
    host = value.lower()
    if host.endswith("."):
        # A single trailing dot is the DNS root; anything more is malformed.
        host = host[:-1]
        if not host or host.endswith("."):
            return ""
    if len(host) > _MAX_HOST_LEN:
        return ""
    if not _HOSTNAME_RE.match(host):
        return ""
    return host


def parse_host(value) -> str:
    """Return the canonical hostname in *value*, or ``''`` if it is invalid.

    Handles the spellings that show up in real ``Host`` headers:

    * ``app.example:443``   -> ``app.example`` (port stripped)
    * ``APP.EXAMPLE``       -> ``app.example`` (case folded)
    * ``app.example.``      -> ``app.example`` (trailing root dot removed)
    * ``[::1]:8443``        -> ``::1``        (IPv6 brackets removed)
    * ``app.example@evil``  -> ``''``         (userinfo is never a host)

    Per RFC 3986 the authority is parsed as ``[userinfo "@"] host [":" port]``;
    a userinfo component can only make the value ambiguous, so it is rejected
    outright instead of being treated as part of the host.
    """
    if not isinstance(value, str) or not value or len(value) > 255:
        return ""

    # Control characters, whitespace and other header-injection tricks are
    # never valid in a host.  Checked before any normalisation.
    for ch in value:
        if ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F:
            return ""

    if "@" in value:
        return ""

    if value.startswith("["):
        # Bracketed IPv6 literal, optionally followed by a port.
        end = value.find("]")
        if end == -1:
            return ""
        inner = value[1:end]
        rest = value[end + 1:]
        if rest:
            if not rest.startswith(":"):
                return ""
            if not _valid_port(rest[1:]):
                return ""
        if "%" in inner or not _is_ipv6_literal(inner):
            return ""
        return ipaddress.IPv6Address(inner).compressed

    if value.count(":") > 1:
        # Unbracketed IPv6 literal (no port possible in this form).
        if "%" in value or not _is_ipv6_literal(value):
            return ""
        return ipaddress.IPv6Address(value).compressed

    host, sep, port = value.partition(":")
    if sep and not _valid_port(port):
        return ""

    return _normalize_hostname(host)


def is_ip_literal(value) -> bool:
    """True when *value* denotes an IP address rather than a DNS name.

    Covers bracketed and bare IPv6, dotted-decimal IPv4, and the legacy IPv4
    spellings (``2130706433``, ``0x7f000001``, ``127.1``) that some HTTP
    clients and resolvers still accept.
    """
    if not isinstance(value, str):
        return False

    candidate = value.strip()
    if not candidate:
        return False

    # A port may be attached to a literal host.
    if candidate.startswith("["):
        end = candidate.find("]")
        if end == -1:
            return False
        rest = candidate[end + 1:]
        if rest and not (rest.startswith(":") and _valid_port(rest[1:])):
            return False
        candidate = candidate[1:end]
    elif candidate.count(":") == 1:
        # host:port form -- only strip a port if the remainder parses as IPv4.
        host, _, port = candidate.partition(":")
        if _valid_port(port):
            candidate = host

    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]

    # Scope identifiers are not part of the address itself.
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]

    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass

    return _is_legacy_ipv4(candidate)


def _is_legacy_ipv4(value: str) -> bool:
    """Detect the non-canonical IPv4 forms ``inet_aton`` still accepts."""
    labels = value.split(".")
    if not 1 <= len(labels) <= 4:
        return False
    for label in labels:
        if label.lower().startswith("0x"):
            if not re.fullmatch(r"0x[0-9a-f]+", label.lower()):
                return False
        elif not label.isascii() or not label.isdigit():
            return False
    return True


def _is_local_host(host: str) -> bool:
    return host in _LOCAL_NAMES or host.endswith(".localhost")


def _normalize_allowlist(allowed) -> set:
    """Normalise an allow-list, discarding entries that can never match.

    Wildcards are rejected rather than expanded: ``*.example`` in an
    allow-list is a configuration bug that would otherwise trust every
    subdomain (including attacker-controlled ones).
    """
    if allowed is None or isinstance(allowed, (str, bytes)):
        return set()

    normalised = set()
    for entry in allowed:
        if not isinstance(entry, str) or "*" in entry:
            continue
        parsed = parse_host(entry)
        if not parsed or is_ip_literal(parsed):
            continue
        normalised.add(parsed)
    return normalised


def host_allowed(host, allowed) -> bool:
    """True only if *host* exactly matches an entry in *allowed*.

    Matching is exact after canonicalisation -- there is deliberately no
    suffix/subdomain matching, so ``app.example.evil.com`` never satisfies
    an ``app.example`` entry.
    """
    if not isinstance(host, str):
        return False

    normalised = parse_host(host)
    if not normalised:
        # Missing, malformed, or carrying userinfo/port junk.
        return False

    # IP literals bypass name-based allow-lists entirely.
    if is_ip_literal(normalised):
        return False

    # localhost is never a legitimate production host, even if allow-listed.
    if _is_local_host(normalised):
        return False

    return normalised in _normalize_allowlist(allowed)


def _ip_in_networks(addr: str, networks) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    for net in networks:
        try:
            if ip in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False


def validate_forwarded(value, allowed, trusted_proxies=None, remote_addr=None) -> bool:
    """Validate an ``X-Forwarded-Host`` chain against the allow-list.

    A forwarded header is only meaningful when it was appended by a proxy we
    control, so:

    * if *remote_addr* is given, the request must have arrived from one of
      *trusted_proxies* (IPs or CIDR ranges); otherwise the whole header is
      ignored;
    * every hop in the comma-separated chain must itself be an allowed,
      exactly-matching host.  An attacker who prepends ``evil.example`` to a
      legitimate value cannot make the chain validate, and a legitimate
      value does not launder a hostile one.

    With no *trusted_proxies*/*remote_addr* the chain is still validated
    strictly, which is the fail-closed default.
    """
    if not isinstance(value, str):
        return False
    if remote_addr is not None:
        if not trusted_proxies or not _ip_in_networks(remote_addr, trusted_proxies):
            return False

    hops = [part.strip() for part in value.split(",")]
    if not hops or any(not hop for hop in hops):
        return False

    return all(host_allowed(hop, allowed) for hop in hops)


def _is_public_ip(ip) -> bool:
    # Unwrap IPv4-mapped IPv6 (``::ffff:10.0.0.1``) so its IPv4 range is used.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or getattr(ip, "is_site_local", False)
    )


def dns_rebind_ok(host, resolved_ip) -> bool:
    """Check that *host* resolves only to public addresses.

    A hostname that passes the allow-list is pair-checked with the address it
    actually resolved to: if DNS points it at loopback, a private range,
    link-local, multicast, or any other non-public space, the request is
    refused.  This closes the rebinding window where a trusted name is
    re-resolved to an internal address.

    *resolved_ip* may be a single address string or an iterable of them; an
    empty resolution fails closed.
    """
    normalised = parse_host(host)
    if not normalised or is_ip_literal(normalised) or _is_local_host(normalised):
        return False

    if isinstance(resolved_ip, str):
        addresses = [resolved_ip]
    else:
        try:
            addresses = list(resolved_ip)
        except TypeError:
            return False

    if not addresses:
        return False

    for address in addresses:
        if not isinstance(address, str):
            return False
        candidate = address.strip()
        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1]
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        if not _is_public_ip(ip):
            return False

    return True
