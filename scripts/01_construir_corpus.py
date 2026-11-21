#!/usr/bin/env python3
"""Fase 1 (paso 1): consulta la API publica del Terraform Registry y evalua candidatos.

Genera `corpus/candidatos.json` con los tipos exactos de recurso declarados en raiz,
conteos por servicio y conteo estricto de recursos evaluables en R_m (Cap4).
"""

from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import requests

REGISTRY_BASE = "https://registry.terraform.io/v1/modules"

QUERIES_POR_SERVICIO: dict[str, list[str]] = {
    "IAM": ["iam", "iam-role", "iam-policy", "iam-user", "oidc"],
    "S3": ["s3", "s3-bucket"],
    "VPC_SG": ["security-group", "security-group-rule", "network-acl", "nacl", "vpc"],
}

TOP_DETALLES_POR_SERVICIO: dict[str, int] = {
    "IAM": 90,
    "S3": 90,
    "VPC_SG": 130,
}

LIMIT_PER_PAGE = 50
PAGES_PER_QUERY = 3

# Recursos evaluables en R_m (Cap4 §4.5.2 alineado a Cap2 §2.4)
VPC_SG_EVALUABLES = {
    "aws_security_group",
    "aws_security_group_rule",
    "aws_default_security_group",
    "aws_vpc_security_group_ingress_rule",
    "aws_vpc_security_group_egress_rule",
    "aws_network_acl",
    "aws_network_acl_rule",
    "aws_default_network_acl",
}

# Recursos de red VPC de soporte (sin colisionar con aws_route53_* ni aws_vpclattice_*)
VPC_NETWORK_SUPPORT = {
    "aws_vpc",
    "aws_default_vpc",
    "aws_subnet",
    "aws_route",
    "aws_route_table",
    "aws_route_table_association",
    "aws_default_route_table",
    "aws_internet_gateway",
    "aws_nat_gateway",
    "aws_egress_only_internet_gateway",
    "aws_vpc_endpoint",
    "aws_vpc_endpoint_route_table_association",
    "aws_vpc_endpoint_subnet_association",
    "aws_vpc_peering_connection",
    "aws_vpc_peering_connection_accepter",
    "aws_vpc_peering_connection_options",
    "aws_flow_log",
}


def get_json(session: requests.Session, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    for intento in range(3):
        try:
            resp = session.get(url, params=params, timeout=20)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            if intento == 2:
                raise RuntimeError(f"Error consultando {url}: {exc}") from exc
            time.sleep(1.5 * (intento + 1))
    return {}


def clasificar_recurso_servicio(rtype: str) -> str:
    if rtype.startswith("aws_iam_"):
        return "IAM"
    if rtype == "aws_s3_bucket" or rtype.startswith("aws_s3_bucket_"):
        return "S3"
    if rtype in VPC_SG_EVALUABLES or rtype in VPC_NETWORK_SUPPORT:
        return "VPC_SG"
    return "OTHER"


def clasificar_recurso_rm(rtype: str) -> str | None:
    if rtype.startswith("aws_iam_"):
        return "IAM"
    if rtype == "aws_s3_bucket" or rtype.startswith("aws_s3_bucket_"):
        return "S3"
    if rtype in VPC_SG_EVALUABLES:
        return "VPC_SG"
    return None


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    corpus_dir = root / "corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.headers.update({"User-Agent": "terraform-sast-corpus-builder/1.1"})

    candidatos_raw: dict[str, dict[str, Any]] = {}

    for servicio_busqueda, queries in QUERIES_POR_SERVICIO.items():
        for q in queries:
            for page in range(PAGES_PER_QUERY):
                offset = page * LIMIT_PER_PAGE
                data = get_json(
                    session,
                    f"{REGISTRY_BASE}/search",
                    params={"q": q, "provider": "aws", "limit": LIMIT_PER_PAGE, "offset": offset},
                )
                mods = data.get("modules", [])
                if not mods:
                    break
                for m in mods:
                    key = f"{m['namespace']}/{m['name']}"
                    tag_q = f"{servicio_busqueda}:{q}"
                    if key not in candidatos_raw:
                        candidatos_raw[key] = {
                            "namespace": m["namespace"],
                            "name": m["name"],
                            "downloads": int(m.get("downloads", 0)),
                            "verified": bool(m.get("verified", False)),
                            "consultas_origen": [tag_q],
                        }
                    elif tag_q not in candidatos_raw[key]["consultas_origen"]:
                        candidatos_raw[key]["consultas_origen"].append(tag_q)

    ordenados = sorted(candidatos_raw.values(), key=lambda x: x["downloads"], reverse=True)
    print(f"Candidatos unicos recolectados en busqueda: {len(ordenados)}")

    seleccion_api: dict[str, dict[str, Any]] = {}
    for svc, limite in TOP_DETALLES_POR_SERVICIO.items():
        del_svc = [c for c in ordenados if any(q.startswith(f"{svc}:") for q in c["consultas_origen"])]
        for c in del_svc[:limite]:
            seleccion_api[f"{c['namespace']}/{c['name']}"] = c

    a_consultar = sorted(seleccion_api.values(), key=lambda x: x["downloads"], reverse=True)
    top_n = len(a_consultar)
    print(f"Consultando detalles de {top_n} candidatos estratificados...")
    detalles: list[dict[str, Any]] = []

    for idx, cand in enumerate(a_consultar, start=1):
        ns = cand["namespace"]
        name = cand["name"]
        try:
            d = get_json(session, f"{REGISTRY_BASE}/{ns}/{name}/aws")
        except Exception as exc:
            print(f"  [WARN] No se pudo obtener detalle de {ns}/{name}: {exc}", file=sys.stderr)
            continue

        root_meta = d.get("root") or {}
        resources = [r.get("type", "") for r in root_meta.get("resources", []) if r.get("type")]
        conteo_svc: dict[str, int] = {"IAM": 0, "S3": 0, "VPC_SG": 0, "OTHER": 0}
        conteo_rm: dict[str, int] = {"IAM": 0, "S3": 0, "VPC_SG": 0}
        for rt in resources:
            conteo_svc[clasificar_recurso_servicio(rt)] += 1
            rm_svc = clasificar_recurso_rm(rt)
            if rm_svc is not None:
                conteo_rm[rm_svc] += 1

        provs = [
            p.get("source") or f"{p.get('namespace')}/{p.get('name')}"
            for p in root_meta.get("provider_dependencies", [])
        ]

        detalles.append({
            "namespace": ns,
            "name": name,
            "version": d.get("version", ""),
            "tag": d.get("tag", "") or d.get("version", ""),
            "published_at": d.get("published_at", ""),
            "downloads": int(d.get("downloads", cand["downloads"])),
            "verified": bool(d.get("verified", cand["verified"])),
            "source": d.get("source", ""),
            "deprecation": d.get("deprecation"),
            "provider": d.get("provider", ""),
            "provider_dependencies": provs,
            "root_resources_total": len(resources),
            "root_resource_types": dict(sorted(Counter(resources).items())),
            "conteo_servicios": conteo_svc,
            "conteo_rm": conteo_rm,
            "submodules_count": len(d.get("submodules", [])),
            "consultas_origen": cand["consultas_origen"],
        })

        if idx % 40 == 0:
            print(f"  Consultados {idx}/{top_n} modulos...")

    out_path = corpus_dir / "candidatos.json"
    out_path.write_text(json.dumps(detalles, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Guardado {out_path} con {len(detalles)} modulos detallados.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
