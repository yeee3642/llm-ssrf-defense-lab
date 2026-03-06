from __future__ import annotations

import ipaddress
from urllib.parse import parse_qsl, urlparse

PRIVATE_PREFIXES = (
    "localhost",
    ".internal",
    ".local",
    ".svc.cluster.local",
    ".corp",
)

BLOCKED_SCHEMES = {"file", "gopher", "dict", "ftp", "ftps", "ldap", "jar"}
METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
}
SUSPICIOUS_PORTS = {22, 2375, 2379, 3306, 5432, 6379, 9200, 11211}


def parse_target(target_url: str):
    return urlparse(target_url)


def is_internal_host(hostname: str) -> bool:
    if not hostname:
        return True

    lowered = hostname.lower()
    if lowered in METADATA_HOSTS:
        return True
    if lowered == "localhost":
        return True
    if lowered.endswith(PRIVATE_PREFIXES[1:]):
        return True

    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        return False

    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast


def is_internal_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast


def extract_nested_urls(target_url: str) -> list[str]:
    parsed = urlparse(target_url)
    nested: list[str] = []
    for _, value in parse_qsl(parsed.query, keep_blank_values=True):
        candidate = value.strip()
        if "://" in candidate:
            nested.append(candidate)
    return nested


def url_risk_indicators(target_url: str, dns_resolution: list[str]) -> list[str]:
    parsed = parse_target(target_url)
    indicators: list[str] = []
    host = parsed.hostname or ""

    if parsed.scheme in BLOCKED_SCHEMES:
        indicators.append("blocked_scheme")

    if is_internal_host(host):
        indicators.append("internal_host")

    if host.lower() in METADATA_HOSTS:
        indicators.append("metadata_host")

    if parsed.port in SUSPICIOUS_PORTS:
        indicators.append("suspicious_port")

    for address in dns_resolution:
        if is_internal_ip(address):
            indicators.append("internal_dns_resolution")
            break

    return indicators


def contains_allowlist_marker(code_excerpt: str) -> bool:
    lowered = code_excerpt.lower()
    markers = (
        "validate_outbound_url",
        "allowed_hosts",
        "allowlisted_hosts",
        "ssrf_guard",
        "trusted_destinations",
    )
    return any(marker in lowered for marker in markers)
