#!/usr/bin/env python3
"""
Tests básicos del parser. Ejecutar con:
    python3 scripts/test_parse.py

No requiere red ni dependencias externas.
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from parse import parse  # noqa: E402


SAMPLE = """\
## F5 Distributed Cloud SaaS Services

### Public IPv4 Subnet Ranges
5.182.215.0/25
1.2.3.4
84.54.61.0/25

## Bot Defense
ibd-webus.fastcache.net
*.volterra.io

## Línea con varios tokens
*.gcr.io gcr.io storage.googleapis.com

# Comentario con almohadilla
54.173.72.228

### Caso inválido
foo_bar_invalid

### IPv6 hipotético
2001:db8::/32
2001:db8::1
"""


def run() -> None:
    r = parse(SAMPLE)

    # IPv4
    assert "1.2.3.4" in r["ipv4_hosts"], "IPv4 plano no detectado"
    assert "54.173.72.228" in r["ipv4_hosts"], "espacios al final no manejados"
    assert "5.182.215.0/25" in r["ipv4_cidrs"], "CIDR no detectado"
    assert "84.54.61.0/25" in r["ipv4_cidrs"], "CIDR repetido no detectado"

    # IPv6
    assert "2001:db8::1" in r["ipv6_hosts"], "IPv6 host no detectado"
    assert "2001:db8::/32" in r["ipv6_cidrs"], "IPv6 CIDR no detectado"

    # Wildcards
    assert "*.volterra.io" in r["wildcards"]
    assert "*.gcr.io" in r["wildcards"], "wildcard en línea multi-token"

    # FQDNs
    assert "ibd-webus.fastcache.net" in r["fqdns"]
    assert "gcr.io" in r["fqdns"], "FQDN en línea multi-token"
    assert "storage.googleapis.com" in r["fqdns"], "FQDN en línea multi-token"

    # Inválidos
    assert "foo_bar_invalid" not in r["fqdns"], "underscore aceptado por error"

    print(
        f"OK | ipv4_hosts:{len(r['ipv4_hosts'])} "
        f"ipv4_cidrs:{len(r['ipv4_cidrs'])} "
        f"ipv6_hosts:{len(r['ipv6_hosts'])} "
        f"ipv6_cidrs:{len(r['ipv6_cidrs'])} "
        f"fqdns:{len(r['fqdns'])} "
        f"wildcards:{len(r['wildcards'])}"
    )


if __name__ == "__main__":
    run()
