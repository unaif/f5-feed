#!/usr/bin/env python3
"""
F5 Distributed Cloud feed parser.

Descarga el archivo público de F5 con IPs y dominios, lo sanitiza y produce
ficheros limpios listos para consumir como External Dynamic List (Palo Alto)
o External Threat Feed (FortiGate).

Uso:
    python3 scripts/parse.py

Salida en docs/:
    f5_ipv4.txt              # IPs + CIDRs IPv4 combinados (uso típico EDL)
    f5_fqdns.txt             # FQDNs + wildcards combinados
    f5_ipv4_hosts.txt        # solo /32
    f5_ipv4_cidrs.txt        # solo redes con prefijo < 32
    f5_fqdns_only.txt        # solo FQDNs sin wildcard
    f5_wildcards.txt         # solo wildcards (*.dominio.tld)
    meta.json                # timestamp y conteos del último sync
"""
from __future__ import annotations

import ipaddress
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

URL = "https://docs.cloud.f5.com/docs-v2/downloads/platform/reference/network-cloud-ref/ips-domains.txt"
OUT = pathlib.Path("docs")
USER_AGENT = "f5-feed-sync/1.0"
TIMEOUT = 30
RETRIES = 3
RETRY_BACKOFF = 5

# Umbrales de sanidad: si el feed cae por debajo, abortamos
# y conservamos la versión publicada anterior.
MIN_BYTES = 2000
MIN_IPV4_ENTRIES = 50
MIN_FQDN_ENTRIES = 20

# Validador de hostname conforme a RFC 1035 (etiquetas de hasta 63 chars).
DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def fetch(url: str) -> str:
    """Descarga el feed con reintentos exponenciales."""
    last_err: Exception | None = None
    for attempt in range(1, RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}")
                return resp.read().decode("utf-8", errors="ignore")
        except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError) as e:
            last_err = e
            if attempt < RETRIES:
                time.sleep(RETRY_BACKOFF * attempt)
    raise RuntimeError(f"Fetch falló tras {RETRIES} intentos: {last_err}")


def parse(text: str) -> dict[str, set[str]]:
    """Clasifica cada token del feed en hosts, CIDRs, FQDNs o wildcards."""
    ipv4_hosts: set[str] = set()
    ipv4_cidrs: set[str] = set()
    ipv6_hosts: set[str] = set()
    ipv6_cidrs: set[str] = set()
    fqdns: set[str] = set()
    wildcards: set[str] = set()

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for token in line.split():
            try:
                net = ipaddress.ip_network(token, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    if net.prefixlen == 32:
                        ipv4_hosts.add(str(net.network_address))
                    else:
                        ipv4_cidrs.add(str(net))
                else:
                    if net.prefixlen == 128:
                        ipv6_hosts.add(str(net.network_address))
                    else:
                        ipv6_cidrs.add(str(net))
                continue
            except ValueError:
                pass
            if token.startswith("*."):
                if DOMAIN_RE.match(token[2:]):
                    wildcards.add(token)
                continue
            if DOMAIN_RE.match(token):
                fqdns.add(token)

    return {
        "ipv4_hosts": ipv4_hosts,
        "ipv4_cidrs": ipv4_cidrs,
        "ipv6_hosts": ipv6_hosts,
        "ipv6_cidrs": ipv6_cidrs,
        "fqdns": fqdns,
        "wildcards": wildcards,
    }


def write_lines(path: pathlib.Path, items: set[str]) -> None:
    """Escribe un set ordenado, una entrada por línea, con LF final."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(sorted(items))
    if content:
        content += "\n"
    path.write_text(content, encoding="utf-8")


def main() -> int:
    text = fetch(URL)

    if len(text) < MIN_BYTES:
        print(f"ERROR: feed sospechosamente pequeño ({len(text)} B)", file=sys.stderr)
        return 2

    parsed = parse(text)
    ipv4_all = parsed["ipv4_hosts"] | parsed["ipv4_cidrs"]
    fqdn_all = parsed["fqdns"] | parsed["wildcards"]

    if len(ipv4_all) < MIN_IPV4_ENTRIES:
        print(
            f"ERROR: solo {len(ipv4_all)} entradas IPv4, esperadas ≥{MIN_IPV4_ENTRIES}",
            file=sys.stderr,
        )
        return 2
    if len(fqdn_all) < MIN_FQDN_ENTRIES:
        print(
            f"ERROR: solo {len(fqdn_all)} entradas FQDN, esperadas ≥{MIN_FQDN_ENTRIES}",
            file=sys.stderr,
        )
        return 2

    write_lines(OUT / "f5_ipv4_hosts.txt", parsed["ipv4_hosts"])
    write_lines(OUT / "f5_ipv4_cidrs.txt", parsed["ipv4_cidrs"])
    write_lines(OUT / "f5_fqdns_only.txt", parsed["fqdns"])
    write_lines(OUT / "f5_wildcards.txt", parsed["wildcards"])
    write_lines(OUT / "f5_ipv4.txt", ipv4_all)
    write_lines(OUT / "f5_fqdns.txt", fqdn_all)

    if parsed["ipv6_hosts"] or parsed["ipv6_cidrs"]:
        write_lines(OUT / "f5_ipv6.txt", parsed["ipv6_hosts"] | parsed["ipv6_cidrs"])

    meta = {
        "source": URL,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "counts": {
            "ipv4_hosts": len(parsed["ipv4_hosts"]),
            "ipv4_cidrs": len(parsed["ipv4_cidrs"]),
            "ipv4_total": len(ipv4_all),
            "ipv6_hosts": len(parsed["ipv6_hosts"]),
            "ipv6_cidrs": len(parsed["ipv6_cidrs"]),
            "fqdns": len(parsed["fqdns"]),
            "wildcards": len(parsed["wildcards"]),
            "fqdn_total": len(fqdn_all),
        },
    }
    (OUT / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    print(f"OK ipv4:{len(ipv4_all)} fqdn:{len(fqdn_all)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
