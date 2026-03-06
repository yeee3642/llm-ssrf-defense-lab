from __future__ import annotations

TOKEN_DESCRIPTIONS = {
    "scheme_allowlist": "Restrict outbound fetches to explicit http/https schemes only.",
    "private_range_block": "Reject loopback, RFC1918, link-local, and metadata IP destinations after DNS resolution.",
    "host_allowlist": "Permit only approved partner, CDN, or tenant-scoped hostnames for server-side fetch features.",
    "disable_redirects": "Disable automatic redirects for user-controlled destinations and inspect every hop manually.",
    "dns_rebind_guard": "Resolve the hostname before connect time and pin the verified IP set for the request lifecycle.",
    "egress_acl": "Apply network egress ACLs that block internal control-plane and database segments.",
    "redirect_validation": "Validate redirect targets against the same allowlist and IP policy as the original request.",
    "timeout_body_cap": "Set strict timeout, content-length, and response-size caps for outbound fetchers.",
}


def dedupe_tokens(tokens: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for token in tokens:
        if token in seen:
            continue
        seen.add(token)
        ordered.append(token)
    return ordered


def build_repair_playbook(framework: str, repair_tokens: list[str]) -> list[str]:
    framework_prefix = framework.strip()
    repairs = []
    for token in dedupe_tokens(repair_tokens):
        description = TOKEN_DESCRIPTIONS.get(token, token.replace("_", " ").title())
        repairs.append(f"[{framework_prefix}] {description}")
    return repairs


def build_patch_hint(framework: str, repair_tokens: list[str]) -> str:
    tokens = set(repair_tokens)
    lower_name = framework.lower()

    if "express" in lower_name or "next.js" in lower_name or "nextjs" in lower_name:
        lines = [
            "import dns from \"node:dns/promises\";",
            "import net from \"node:net\";",
            "",
            "const ALLOWED_HOSTS = new Set([\"cdn.example.com\", \"api.partner.example\"]);",
            "",
            "export async function validateOutboundUrl(rawUrl) {",
            "  const url = new URL(rawUrl);",
            "  if (![\"https:\", \"http:\"].includes(url.protocol)) throw new Error(\"bad scheme\");",
            "  if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error(\"host not allowlisted\");",
            "  const { address } = await dns.lookup(url.hostname, { all: false });",
            "  if (net.isIP(address) && [\"127.\", \"10.\", \"169.254.\", \"192.168.\"].some((prefix) => address.startsWith(prefix))) {",
            "    throw new Error(\"internal address blocked\");",
            "  }",
            "  return url;",
            "}",
            "",
            "const safeUrl = await validateOutboundUrl(inputUrl);",
            "const response = await fetch(safeUrl, { redirect: \"manual\", signal: AbortSignal.timeout(3000) });",
        ]
        return "\n".join(lines)

    if "spring" in lower_name:
        lines = [
            "URI uri = URI.create(candidateUrl);",
            "if (!Set.of(\"https\", \"http\").contains(uri.getScheme())) throw new SecurityException(\"bad scheme\");",
            "if (!ALLOWED_HOSTS.contains(uri.getHost())) throw new SecurityException(\"host not allowlisted\");",
            "InetAddress resolved = InetAddress.getByName(uri.getHost());",
            "if (resolved.isAnyLocalAddress() || resolved.isLoopbackAddress() || resolved.isSiteLocalAddress()) {",
            "    throw new SecurityException(\"internal address blocked\");",
            "}",
            "WebClient client = WebClient.builder()",
            "    .defaultHeader(HttpHeaders.USER_AGENT, \"ssrf-guard\")",
            "    .build();",
            "client.get().uri(uri).retrieve();",
        ]
        return "\n".join(lines)

    lines = [
        "from urllib.parse import urlparse",
        "import ipaddress",
        "import socket",
        "",
        "ALLOWED_HOSTS = {\"cdn.example.com\", \"api.partner.example\"}",
        "",
        "def validate_outbound_url(raw_url: str) -> str:",
        "    parsed = urlparse(raw_url)",
        "    if parsed.scheme not in {\"http\", \"https\"}:",
        "        raise ValueError(\"bad scheme\")",
        "    if parsed.hostname not in ALLOWED_HOSTS:",
        "        raise ValueError(\"host not allowlisted\")",
        "    for result in socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM):",
        "        ip = ipaddress.ip_address(result[4][0])",
        "        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:",
        "            raise ValueError(\"internal address blocked\")",
        "    return raw_url",
        "",
        "safe_url = validate_outbound_url(user_supplied_url)",
        "response = requests.get(safe_url, allow_redirects=False, timeout=3)",
    ]

    if "timeout_body_cap" in tokens:
        lines.append("if int(response.headers.get(\"Content-Length\", \"0\")) > 5_000_000: raise ValueError(\"response too large\")")

    return "\n".join(lines)
