#!/usr/bin/env python3
"""Fase 1 (paso 2): aplica criterios del Cap4, clona tags exactos, verifica HCL2
y genera `corpus/modulos.csv` y `corpus/excluidos.csv`.
"""

from __future__ import annotations

import csv
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import hcl2

OBJETIVO_POR_SERVICIO = 15
CUOTA_DEFAULT = 3
SERVICIOS = ("IAM", "S3", "VPC_SG")

PRERELEASE_RE = re.compile(r"-(?:rc|beta|alpha|dev|canary|pre)\b", re.I)


def servicio_dominante(conteo: dict[str, int]) -> tuple[str | None, str]:
    objetivos = {s: conteo.get(s, 0) for s in SERVICIOS}
    otros = conteo.get("OTHER", 0)
    total_obj = sum(objetivos.values())
    if total_obj == 0:
        return None, "sin recursos de IAM, S3 o VPC_SG en raiz"
    mejor_svc = max(SERVICIOS, key=lambda s: (objetivos[s], s == "IAM"))
    if otros >= objetivos[mejor_svc]:
        return None, f"no predomina servicio objetivo (OTHER={otros} >= {mejor_svc}={objetivos[mejor_svc]})"
    return mejor_svc, ""


def es_hcl1_por_required_version(req_ver: Any) -> bool:
    if isinstance(req_ver, list):
        req_str = " ".join(str(x) for x in req_ver)
    else:
        req_str = str(req_ver or "")
    if re.search(r"(?:~>|=|<|<=)\s*0\.(?:[0-9]|10|11)\b", req_str) and "0.12" not in req_str and "0.13" not in req_str and "1." not in req_str:
        return True
    if re.search(r"<\s*0\.12\b", req_str):
        return True
    return False


def verificar_modulo_local(repo_dir: Path) -> tuple[bool, str, int]:
    """Verifica sintaxis HCL2, version >= 0.12 y presencia de bloques resource en raiz."""
    tf_files = sorted(repo_dir.glob("*.tf"))
    if not tf_files:
        return False, "no hay archivos .tf en el directorio raiz", 0

    num_resources = 0
    for tf in tf_files:
        texto = tf.read_text(encoding="utf-8")
        try:
            tree = hcl2.parses(texto)
        except Exception as exc:
            return False, f"error_parseo_hcl2 ({tf.name}: {exc})", 0

        try:
            parsed = hcl2.loads(texto)
            for tf_blk in parsed.get("terraform", []):
                if isinstance(tf_blk, dict) and "required_version" in tf_blk:
                    if es_hcl1_por_required_version(tf_blk["required_version"]):
                        return False, f"hcl1_required_version ({tf_blk['required_version']})", 0
            for res_blk in parsed.get("resource", []):
                if isinstance(res_blk, dict):
                    num_resources += len(res_blk)
        except Exception:
            for child in getattr(tree.body, "children", []):
                labels = getattr(child, "labels", None)
                if labels:
                    btype = str(labels[0].serialize())
                    if btype == "resource":
                        num_resources += 1
                    elif btype == "terraform":
                        try:
                            tb = child.serialize()
                            if isinstance(tb, dict) and "required_version" in tb:
                                if es_hcl1_por_required_version(tb["required_version"]):
                                    return False, f"hcl1_required_version ({tb['required_version']})", 0
                        except Exception:
                            pass

    if num_resources == 0:
        return False, "solo_wrapper_sin_resource_raiz", 0
    return True, "ok", num_resources


def clonar_tag(url: str, tag: str, destino: Path) -> tuple[bool, str]:
    esperados = {tag, f"v{tag}", tag.lstrip("v")}
    if destino.exists():
        res_head = subprocess.run(
            ["git", "-C", str(destino), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
        )
        res_tags = subprocess.run(
            ["git", "-C", str(destino), "tag", "--points-at", "HEAD"],
            capture_output=True,
            text=True,
        )
        tags_actuales = set(res_tags.stdout.split())
        if res_head.returncode == 0 and (tags_actuales & esperados):
            return True, res_head.stdout.strip()
        subprocess.run(["rm", "-rf", str(destino)], check=True)

    tags_a_probar = [tag]
    if tag and not tag.startswith("v"):
        tags_a_probar.append(f"v{tag}")
    elif tag.startswith("v"):
        tags_a_probar.append(tag[1:])

    for t in tags_a_probar:
        res = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", t, url, str(destino)],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0:
            head = subprocess.run(
                ["git", "-C", str(destino), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            )
            return True, head.stdout.strip()
        if destino.exists():
            subprocess.run(["rm", "-rf", str(destino)], check=True)

    return False, res.stderr.strip().splitlines()[-1] if res.stderr else "fallo_clone"


def evaluar_candidato_metadata(c: dict[str, Any]) -> tuple[str | None, str, str]:
    """Devuelve (servicio_asignado, criterio_exclusion, detalle) basado en metadatos."""
    if c.get("deprecation"):
        return None, "obsoleto", f"deprecation={c['deprecation']}"
    if PRERELEASE_RE.search(c.get("version", "")):
        return None, "version_prerelease", f"version={c.get('version')}"
    if c.get("provider") != "aws":
        return None, "proveedor_no_aws", f"provider={c.get('provider')}"
    provs = c.get("provider_dependencies") or []
    if provs and not any(p in ("hashicorp/aws", "aws") for p in provs):
        return None, "proveedor_no_oficial", f"provider_dependencies={provs}"
    if int(c.get("root_resources_total", 0)) == 0:
        return None, "solo_wrapper", "root.resources vacio en Registry"
    svc, motivo = servicio_dominante(c.get("conteo_servicios", {}))
    if svc is None:
        return None, "fuera_de_alcance", motivo
    # Exigir al menos un recurso evaluable del propio servicio dentro de R_m
    rm_svc = int((c.get("conteo_rm") or {}).get(svc, 0))
    if rm_svc == 0:
        return None, "sin_recursos_evaluables_rm", f"0 recursos de {svc} en R_m (conteo_rm={c.get('conteo_rm')})"
    src = c.get("source", "")
    if not src.startswith("https://github.com/"):
        return None, "fuente_no_github", f"source={src}"
    return svc, "", ""


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    corpus_dir = root / "corpus"
    descargados_dir = corpus_dir / "descargados"
    descargados_dir.mkdir(parents=True, exist_ok=True)

    candidatos_path = corpus_dir / "candidatos.json"
    if not candidatos_path.exists():
        print("Error: ejecuta primero scripts/01_construir_corpus.py", file=sys.stderr)
        return 1

    candidatos: list[dict[str, Any]] = json.loads(candidatos_path.read_text(encoding="utf-8"))
    fecha_hoy = dt.date.today().isoformat()

    excluidos: list[dict[str, Any]] = []
    pools: dict[str, list[dict[str, Any]]] = {s: [] for s in SERVICIOS}

    for c in candidatos:
        svc, crit, det = evaluar_candidato_metadata(c)
        if svc is None:
            excluidos.append({
                "namespace": c["namespace"],
                "nombre": c["name"],
                "version": c["version"],
                "descargas": c["downloads"],
                "criterio_exclusion": crit,
                "detalle": det,
            })
        else:
            c_copy = dict(c)
            c_copy["servicio_asignado"] = svc
            pools[svc].append(c_copy)

    for s in SERVICIOS:
        pools[s].sort(key=lambda x: x["downloads"], reverse=True)
        print(f"Pool elegible inicial {s}: {len(pools[s])} modulos")

    seleccionados: list[dict[str, Any]] = []
    conteo_ns: dict[str, int] = {}
    conteo_svc: dict[str, int] = {s: 0 for s in SERVICIOS}
    indices: dict[str, int] = {s: 0 for s in SERVICIOS}

    def seleccionar_siguiente(svc: str, cuota_max: int) -> bool:
        while indices[svc] < len(pools[svc]):
            c = pools[svc][indices[svc]]
            indices[svc] += 1
            ns = c["namespace"]
            if conteo_ns.get(ns, 0) >= cuota_max:
                excluidos.append({
                    "namespace": ns,
                    "nombre": c["name"],
                    "version": c["version"],
                    "descargas": c["downloads"],
                    "criterio_exclusion": "cuota_publicador",
                    "detalle": f"excede maximo de {cuota_max} modulos para namespace {ns}",
                })
                continue

            destino = descargados_dir / f"{ns}__{c['name']}"
            ok_clone, clone_info = clonar_tag(c["source"], c["tag"], destino)
            if not ok_clone:
                excluidos.append({
                    "namespace": ns,
                    "nombre": c["name"],
                    "version": c["version"],
                    "descargas": c["downloads"],
                    "criterio_exclusion": "error_clonado",
                    "detalle": clone_info,
                })
                continue

            ok_hcl, motivo_hcl, n_res_hcl = verificar_modulo_local(destino)
            if not ok_hcl:
                subprocess.run(["rm", "-rf", str(destino)], check=True)
                excluidos.append({
                    "namespace": ns,
                    "nombre": c["name"],
                    "version": c["version"],
                    "descargas": c["downloads"],
                    "criterio_exclusion": "hcl1_o_sin_recursos",
                    "detalle": str(motivo_hcl),
                })
                continue

            conteo_ns[ns] = conteo_ns.get(ns, 0) + 1
            conteo_svc[svc] += 1
            tipo_verif = "Verified" if c["verified"] else "Comunidad"
            rm_n = int((c.get("conteo_rm") or {}).get(svc, 0))
            seleccionados.append({
                "namespace": ns,
                "nombre": c["name"],
                "servicio": svc,
                "version": c["version"],
                "tag": c["tag"],
                "commit": clone_info,
                "fecha_extraccion": fecha_hoy,
                "descargas": c["downloads"],
                "url_fuente": c["source"],
                "recursos_raiz": n_res_hcl,
                "recursos_rm_servicio": rm_n,
                "motivo_inclusion": f"{tipo_verif}; {c['downloads']} descargas; predominio {svc} ({c['conteo_servicios']}; R_m={rm_n})",
            })
            print(f"  + [{svc} {conteo_svc[svc]}/{OBJETIVO_POR_SERVICIO}] {ns}/{c['name']} v{c['version']} (R_m={rm_n}, {clone_info[:8]})")
            return True
        return False

    progreso = True
    while progreso and any(conteo_svc[s] < OBJETIVO_POR_SERVICIO for s in SERVICIOS):
        progreso = False
        for s in SERVICIOS:
            if conteo_svc[s] < OBJETIVO_POR_SERVICIO:
                if seleccionar_siguiente(s, CUOTA_DEFAULT):
                    progreso = True

    print("\nResumen seleccion:", conteo_svc, "Total:", len(seleccionados))
    if conteo_svc["IAM"] < 13:
        print(f"ALERTA: IAM obtuvo {conteo_svc['IAM']} (< 13). Se requiere evaluar contingencia Cap4.", file=sys.stderr)

    nombres_ok = {f"{m['namespace']}__{m['nombre']}" for m in seleccionados}
    for sub in descargados_dir.iterdir():
        if sub.is_dir() and sub.name not in nombres_ok:
            subprocess.run(["rm", "-rf", str(sub)], check=True)

    mod_csv = corpus_dir / "modulos.csv"
    with mod_csv.open("w", newline="", encoding="utf-8") as fh:
        campos = [
            "namespace", "nombre", "servicio", "version", "tag", "commit",
            "fecha_extraccion", "descargas", "url_fuente", "recursos_raiz",
            "recursos_rm_servicio", "motivo_inclusion",
        ]
        w = csv.DictWriter(fh, fieldnames=campos)
        w.writeheader()
        w.writerows(seleccionados)

    exc_csv = corpus_dir / "excluidos.csv"
    with exc_csv.open("w", newline="", encoding="utf-8") as fh:
        campos_exc = ["namespace", "nombre", "version", "descargas", "criterio_exclusion", "detalle"]
        w = csv.DictWriter(fh, fieldnames=campos_exc)
        w.writeheader()
        w.writerows(excluidos)

    print(f"Escritos: {mod_csv} ({len(seleccionados)} filas) y {exc_csv} ({len(excluidos)} filas).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
