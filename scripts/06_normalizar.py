#!/usr/bin/env python3
"""Fases 4 y 5: normaliza salidas JSON crudas de Checkov, Trivy y KICS,
atribuye cada alerta a (recurso, control) y construye `unidades.csv` desde el AST HCL2.

- Reconstruye direccion y prefijo `data.` en Checkov (`resource_address` vacio).
- Recorre todos los bloques `Results` de Trivy y antepone `AVD-` cuando falta.
- Enumera todos los recursos declarados r in R_m con `hcl2.parses()` + `BlockRule`
  antes de superponer alertas, conservando los acuerdos en negativo (0, 0, 0).
- Reporta alertas crudas, atribuidas y excluidas por herramienta.
"""

from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

import hcl2

EXCLUIR_DIRS = {"examples", "example", "tests", "test", ".git", ".terraform"}

VPC_SG_RM = {
    "aws_security_group",
    "aws_security_group_rule",
    "aws_default_security_group",
    "aws_vpc_security_group_ingress_rule",
    "aws_vpc_security_group_egress_rule",
    "aws_network_acl",
    "aws_network_acl_rule",
    "aws_default_network_acl",
}

# Reglas adicionales documentadas en `criterio_semantico` de matriz/equivalencias.csv
# que mapean al mismo control principal sin doble conteo por (recurso, control).
REGLAS_COMPANERAS: dict[str, dict[str, str]] = {
    "checkov": {
        "CKV_AWS_53": "CIS-2.1.4",
        "CKV_AWS_54": "CIS-2.1.4",
        "CKV_AWS_55": "CIS-2.1.4",
        "CKV_AWS_56": "CIS-2.1.4",
        "CKV_AWS_57": "BP-S3-ACL-PUBLIC",
        "CKV_AWS_231": "CIS-5.1",
        "CKV_AWS_9": "BP-IAM-PASSWORD-COMPLEXITY",
        "CKV_AWS_11": "BP-IAM-PASSWORD-COMPLEXITY",
        "CKV_AWS_12": "BP-IAM-PASSWORD-COMPLEXITY",
        "CKV_AWS_15": "BP-IAM-PASSWORD-COMPLEXITY",
        "CKV_AWS_111": "BP-IAM-WILDCARD-RESOURCE",
        "CKV_AWS_290": "BP-IAM-WILDCARD-RESOURCE",
    },
    "trivy": {
        "AVD-AWS-0086": "CIS-2.1.4",
        "AVD-AWS-0087": "CIS-2.1.4",
        "AVD-AWS-0091": "CIS-2.1.4",
        "AVD-AWS-0093": "CIS-2.1.4",
        "AVD-AWS-0124": "BP-SG-DESCRIPTION",
        "AVD-AWS-0058": "BP-IAM-PASSWORD-COMPLEXITY",
        "AVD-AWS-0059": "BP-IAM-PASSWORD-COMPLEXITY",
        "AVD-AWS-0061": "BP-IAM-PASSWORD-COMPLEXITY",
        "AVD-AWS-0062": "BP-IAM-PASSWORD-COMPLEXITY",
    },
    "kics": {
        "d0cc8694-fcad-43ff-ac86-32331d7e867f": "CIS-2.1.4",
        "1a4bc881-9f69-4d44-8c9a-d37d08f54c50": "CIS-2.1.4",
        "4fa66806-0dd9-4f8d-9480-3174d39c7c91": "CIS-2.1.4",
        "68eb4bf3-f9bf-463d-b5cf-e029bb446d2e": "BP-SG-DESCRIPTION",
        "a20be318-cac7-457b-911d-04cc6e812c25": "CIS-5.1",
        "2f37c4a3-58b9-4afe-8a87-d7f1d2286f84": "CIS-1.16",
        "43a41523-386a-4cb1-becb-42af6b414433": "BP-IAM-PRIVILEGE-ESC-POLICY",
    },
}


def es_recurso_rm(tipo: str, es_data: bool = False) -> bool:
    if es_data or tipo == "data.aws_iam_policy_document":
        return tipo in ("aws_iam_policy_document", "data.aws_iam_policy_document")
    return (
        tipo.startswith("aws_iam_")
        or tipo == "aws_s3_bucket"
        or tipo.startswith("aws_s3_bucket_")
        or tipo in VPC_SG_RM
    )


def extraer_bloques_hcl(modulo_dir: Path) -> list[dict[str, Any]]:
    """Extrae bloques resource y data 'aws_iam_policy_document' del modulo raiz (*.tf)."""
    bloques: list[dict[str, Any]] = []
    for tf in sorted(modulo_dir.glob("*.tf")):
        if not tf.is_file():
            continue
        rel = tf.relative_to(modulo_dir)
        texto = tf.read_text(encoding="utf-8", errors="ignore")
        rel_str = rel.as_posix()

        mod_prefix = ""

        # Usar hcl2.parses() + BlockRule para obtener posiciones exactas sin caer en bugs de serialize()
        parsed_ok = False
        try:
            tree = hcl2.parses(texto)
            for child in getattr(tree.body, "children", []):
                labels = getattr(child, "labels", None)
                if not labels or len(labels) < 3:
                    continue
                bkind = str(labels[0].serialize()).strip('"')
                if bkind not in ("resource", "data"):
                    continue
                rtype = str(labels[1].serialize()).strip('"')
                rname = str(labels[2].serialize()).strip('"')
                if bkind == "data" and rtype != "aws_iam_policy_document":
                    continue
                meta = getattr(child, "_meta", None)
                start_l = getattr(meta, "line", 0) or 0
                end_l = getattr(meta, "end_line", start_l) or start_l
                addr = f"{mod_prefix}{'data.' if bkind == 'data' else ''}{rtype}.{rname}"
                bloques.append({
                    "archivo": rel_str,
                    "linea_inicio": start_l,
                    "linea_fin": end_l,
                    "kind": bkind,
                    "tipo_recurso": f"data.{rtype}" if bkind == "data" else rtype,
                    "recurso": addr,
                    "en_rm": es_recurso_rm(rtype, es_data=(bkind == "data")),
                })
            parsed_ok = True
        except Exception:
            parsed_ok = False

        if not parsed_ok:
            for m in re.finditer(r'^\s*(resource|data)\s+"([a-z0-9_]+)"\s+"([^"]+)"', texto, re.M):
                bkind, rtype, rname = m.group(1), m.group(2), m.group(3)
                if bkind == "data" and rtype != "aws_iam_policy_document":
                    continue
                line_no = texto[: m.start()].count("\n") + 1
                addr = f"{mod_prefix}{'data.' if bkind == 'data' else ''}{rtype}.{rname}"
                bloques.append({
                    "archivo": rel_str,
                    "linea_inicio": line_no,
                    "linea_fin": line_no + 200,
                    "kind": bkind,
                    "tipo_recurso": f"data.{rtype}" if bkind == "data" else rtype,
                    "recurso": addr,
                    "en_rm": es_recurso_rm(rtype, es_data=(bkind == "data")),
                })
    return bloques


def ubicar_bloque_por_linea(bloques: list[dict[str, Any]], archivo: str, linea: int) -> dict[str, Any] | None:
    arch_norm = archivo.lstrip("./").lstrip("/")
    for b in bloques:
        if b["archivo"] == arch_norm or b["archivo"].endswith("/" + arch_norm) or arch_norm.endswith("/" + b["archivo"]):
            if b["linea_inicio"] <= linea <= b["linea_fin"]:
                return b
    return None


def normalizar_recurso_str(raw: str) -> tuple[str, str]:
    """Devuelve (direccion_normalizada, tipo_recurso) normalizando prefijo data. en Checkov."""
    r = (raw or "").strip()
    if not r:
        return "", ""
    # Quitar indices [0] o ["k"] si aparecieran
    r_sin_idx = re.sub(r"\[[^\]]+\]", "", r)
    # Normalizar aws_iam_policy_document sin data.
    if r_sin_idx.startswith("aws_iam_policy_document."):
        r_sin_idx = "data." + r_sin_idx
    elif ".aws_iam_policy_document." in r_sin_idx and ".data.aws_iam_policy_document." not in r_sin_idx:
        r_sin_idx = r_sin_idx.replace(".aws_iam_policy_document.", ".data.aws_iam_policy_document.")

    parts = r_sin_idx.split(".")
    if len(parts) >= 3 and parts[-3] == "data":
        return r_sin_idx, f"data.{parts[-2]}"
    if len(parts) >= 2:
        return r_sin_idx, parts[-2]
    return r_sin_idx, ""


def cargar_matriz(root: Path) -> tuple[dict[str, dict[str, list[str]]], dict[str, set[str]], list[dict[str, str]]]:
    eq_rows = list(csv.DictReader((root / "matriz" / "equivalencias.csv").open(encoding="utf-8")))
    cat_rows = list(csv.DictReader((root / "matriz" / "catalogo_controles.csv").open(encoding="utf-8")))

    mapa: dict[str, dict[str, list[str]]] = {t: {} for t in ("checkov", "trivy", "kics")}
    for t in ("checkov", "trivy", "kics"):
        for rid, ctrl in REGLAS_COMPANERAS[t].items():
            mapa[t].setdefault(rid, [])
            if ctrl not in mapa[t][rid]:
                mapa[t][rid].append(ctrl)

    # Mapear cada regla a todos los controles de equivalencias.csv (soporta reglas 1:N como AVD-AWS-0107 o CKV_AWS_24)
    for r in eq_rows:
        ctrl = r["id_control"].strip()
        for t in ("checkov", "trivy", "kics"):
            rid = r[f"regla_{t}"].strip()
            if rid and rid != "NA":
                mapa[t].setdefault(rid, [])
                if ctrl not in mapa[t][rid]:
                    mapa[t][rid].append(ctrl)

    tipos_por_control: dict[str, set[str]] = {}
    for r in cat_rows:
        tipos_por_control[r["id_control"]] = {x.strip() for x in r["tipo_recurso_aplicable"].split("|") if x.strip()}

    return mapa, tipos_por_control, eq_rows


def parsear_checkov(path: Path, bloques: list[dict[str, Any]]) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        checks = []
        for item in data:
            if isinstance(item, dict):
                checks.extend((item.get("results") or {}).get("failed_checks", []))
    else:
        checks = (data.get("results") or {}).get("failed_checks", [])

    out = []
    for c in checks:
        f_path = (c.get("file_path") or "").lstrip("/")
        lrange = c.get("file_line_range") or [0, 0]
        l_ini = int(lrange[0]) if len(lrange) > 0 and lrange[0] else 0
        l_fin = int(lrange[1]) if len(lrange) > 1 and lrange[1] else l_ini

        # Priorizar reconstruccion por AST (resuelve module.M. y prefijo data.)
        blk = ubicar_bloque_por_linea(bloques, f_path, l_ini) if l_ini else None
        if blk:
            recurso, rtype = blk["recurso"], blk["tipo_recurso"]
        else:
            recurso, rtype = normalizar_recurso_str(c.get("resource_address") or c.get("resource") or "")

        out.append({
            "herramienta": "checkov",
            "archivo": f_path,
            "linea_inicio": l_ini,
            "linea_fin": l_fin,
            "recurso": recurso,
            "tipo_recurso": rtype,
            "regla": c.get("check_id", ""),
            "severidad_nativa": str(c.get("severity") or ""),
        })
    return out


def parsear_trivy(path: Path, bloques: list[dict[str, Any]]) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for res in data.get("Results") or []:
        target = (res.get("Target") or "").lstrip("./").lstrip("/")
        for m in res.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            raw_id = m.get("AVDID") or m.get("ID") or ""
            if raw_id and not raw_id.startswith("AVD-"):
                raw_id = f"AVD-{raw_id}"
            cm = m.get("CauseMetadata") or {}
            l_ini = int(cm.get("StartLine") or 0)
            l_fin = int(cm.get("EndLine") or l_ini)
            raw_res = cm.get("Resource") or ""
            blk = ubicar_bloque_por_linea(bloques, target, l_ini) if l_ini else None
            if blk:
                recurso, rtype = blk["recurso"], blk["tipo_recurso"]
            else:
                recurso, rtype = normalizar_recurso_str(raw_res)

            out.append({
                "herramienta": "trivy",
                "archivo": target,
                "linea_inicio": l_ini,
                "linea_fin": l_fin,
                "recurso": recurso,
                "tipo_recurso": rtype,
                "regla": raw_id,
                "severidad_nativa": str(m.get("Severity") or ""),
            })
    return out


def parsear_kics(path: Path, bloques: list[dict[str, Any]]) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for q in data.get("queries") or []:
        qid = q.get("query_id", "")
        sev = str(q.get("severity") or "")
        for f in q.get("files") or []:
            fname = (f.get("file_name") or "").replace("../../src/", "").lstrip("./").lstrip("/")
            line = int(f.get("line") or 0)
            blk = ubicar_bloque_por_linea(bloques, fname, line) if line else None
            if blk:
                recurso, rtype = blk["recurso"], blk["tipo_recurso"]
            else:
                rt = (f.get("resource_type") or "").strip()
                rn = (f.get("resource_name") or "").strip()
                recurso, rtype = normalizar_recurso_str(f"{rt}.{rn}" if rt and rn else "")

            out.append({
                "herramienta": "kics",
                "archivo": fname,
                "linea_inicio": line,
                "linea_fin": line,
                "recurso": recurso,
                "tipo_recurso": rtype,
                "regla": qid,
                "severidad_nativa": sev,
            })
    return out


def resolver_directorio_objetivo(root: Path, oid: str) -> tuple[str, Path]:
    if oid.startswith("corpus__"):
        return "corpus", root / "corpus" / "descargados" / oid[len("corpus__"):]
    if oid.startswith("sembrado__"):
        _, caso, var = oid.split("__", 2)
        return "sembrado", root / "casos_sembrados" / caso / var
    if oid.startswith("iam_vulnerable__"):
        return "iam_vulnerable", root / "iam_vulnerable" / "repo" / "modules" / "free-resources" / "privesc-paths"
    raise ValueError(f"Objetivo desconocido: {oid}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--modo", choices=("piloto", "completo"), default="piloto")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    crudos_base = root / "resultados" / "crudos" / args.modo
    norm_dir = root / "resultados" / "normalizados"
    norm_dir.mkdir(parents=True, exist_ok=True)

    mapa_reglas, tipos_por_control, eq_rows = cargar_matriz(root)
    c_comp = [r["id_control"] for r in eq_rows if r["cobertura"].strip() == "3/3"]

    svc_por_modulo: dict[str, str] = {}
    with (root / "corpus" / "modulos.csv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            svc_por_modulo[f"corpus__{row['namespace']}__{row['nombre']}"] = row["servicio"]

    # Detectar objetivos disponibles en crudos/<modo>/checkov/*.json
    objetivos_ids = sorted(p.stem for p in (crudos_base / "checkov").glob("*.json"))
    if not objetivos_ids:
        print(f"Error: no hay salidas crudas en {crudos_base / 'checkov'}. Ejecuta primero 05_escanear.py --modo {args.modo}")
        return 1

    alertas_all: list[dict[str, Any]] = []
    unidades_all: list[dict[str, Any]] = []
    conteo_crudas = collections.Counter()
    conteo_atrib_rm = collections.Counter()
    conteo_excl_no_recurso = collections.Counter()
    conteo_fuera_catalogo = collections.Counter()

    parsers = {"checkov": parsear_checkov, "trivy": parsear_trivy, "kics": parsear_kics}

    for oid in objetivos_ids:
        grupo, obj_dir = resolver_directorio_objetivo(root, oid)
        bloques = extraer_bloques_hcl(obj_dir)

        # Conjunto de detecciones (herramienta, recurso, control) para construir unidades.csv
        detectadas: set[tuple[str, str, str]] = set()

        for tool in ("checkov", "trivy", "kics"):
            jpath = crudos_base / tool / f"{oid}.json"
            if not jpath.exists():
                continue
            if jpath.stat().st_size == 0:
                print(f"Error: salida cruda vacia en {jpath}. Corrige el escaneo en 05_escanear.py antes de normalizar.")
                return 1
            hallazgos = parsers[tool](jpath, bloques)
            for h in hallazgos:
                conteo_crudas[tool] += 1
                ctrls = mapa_reglas[tool].get(h["regla"], [])
                ctrl_str = "|".join(ctrls)
                en_rm = es_recurso_rm(h["tipo_recurso"], es_data=h["tipo_recurso"].startswith("data."))
                if not h["recurso"] or not en_rm:
                    estado = "excluida_sin_recurso_rm"
                    conteo_excl_no_recurso[tool] += 1
                elif not ctrls:
                    estado = "fuera_catalogo"
                    conteo_fuera_catalogo[tool] += 1
                else:
                    estado = "atribuida"
                    conteo_atrib_rm[tool] += 1
                    for c in ctrls:
                        detectadas.add((tool, h["recurso"], c))

                alertas_all.append({
                    "herramienta": tool,
                    "grupo": grupo,
                    "objetivo": oid,
                    "archivo": h["archivo"],
                    "linea_inicio": h["linea_inicio"],
                    "linea_fin": h["linea_fin"],
                    "recurso": h["recurso"],
                    "tipo_recurso": h["tipo_recurso"],
                    "regla": h["regla"],
                    "control": ctrl_str,
                    "severidad_nativa": h["severidad_nativa"],
                    "estado_atribucion": estado,
                })

        # Construir universo U para modulos del corpus: TODOS los recursos r in R_m x c in C_comp aplicables
        if grupo == "corpus":
            recursos_rm_unicos: dict[str, str] = {}
            for b in bloques:
                if b["en_rm"]:
                    recursos_rm_unicos[b["recurso"]] = b["tipo_recurso"]
            for rec, rtype in sorted(recursos_rm_unicos.items()):
                for ctrl in c_comp:
                    if rtype in tipos_por_control.get(ctrl, set()):
                        unidades_all.append({
                            "modulo": oid[len("corpus__"):],
                            "servicio": svc_por_modulo.get(oid, ""),
                            "recurso": rec,
                            "tipo_recurso": rtype,
                            "control": ctrl,
                            "X_checkov": int(("checkov", rec, ctrl) in detectadas),
                            "X_trivy": int(("trivy", rec, ctrl) in detectadas),
                            "X_kics": int(("kics", rec, ctrl) in detectadas),
                        })

    pref = "piloto_" if args.modo == "piloto" else ""
    alertas_csv = norm_dir / f"{pref}alertas.csv"
    with alertas_csv.open("w", newline="", encoding="utf-8") as fh:
        campos = [
            "herramienta", "grupo", "objetivo", "archivo", "linea_inicio", "linea_fin",
            "recurso", "tipo_recurso", "regla", "control", "severidad_nativa", "estado_atribucion",
        ]
        w = csv.DictWriter(fh, fieldnames=campos)
        w.writeheader()
        w.writerows(alertas_all)

    if args.modo == "completo":
        unidades_dir = root / "analisis"
        unidades_dir.mkdir(parents=True, exist_ok=True)
        unidades_csv = unidades_dir / "unidades.csv"
    else:
        unidades_csv = norm_dir / "piloto_unidades.csv"

    with unidades_csv.open("w", newline="", encoding="utf-8") as fh:
        campos_u = ["modulo", "servicio", "recurso", "tipo_recurso", "control", "X_checkov", "X_trivy", "X_kics"]
        w = csv.DictWriter(fh, fieldnames=campos_u)
        w.writeheader()
        w.writerows(unidades_all)

    ceros = sum(1 for u in unidades_all if u["X_checkov"] == 0 and u["X_trivy"] == 0 and u["X_kics"] == 0)
    lineas = [
        f"Normalizacion modo={args.modo} ({dt.date.today().isoformat()})",
        f"Objetivos procesados: {len(objetivos_ids)}",
        "Conteo de alertas por herramienta (cuadre crudo = atribuida + fuera_catalogo + excluida_sin_recurso_rm):",
    ]
    for t in ("checkov", "trivy", "kics"):
        lineas.append(
            f"  - {t:7}: crudas={conteo_crudas[t]:4} | atribuidas={conteo_atrib_rm[t]:4} | "
            f"fuera_catalogo={conteo_fuera_catalogo[t]:4} | excluidas_sin_rm={conteo_excl_no_recurso[t]:4}"
        )
    lineas.append(f"Unidades (r, c) en U (corpus, C_comp 3/3): {len(unidades_all)} (acuerdos 0/0/0: {ceros})")
    lineas.append(f"Archivos escritos: {alertas_csv} y {unidades_csv}")

    if args.modo == "piloto":
        lineas.append("\n--- Muestra de alertas atribuidas para revision manual (Fase 4) ---")
        for a in alertas_all:
            if a["estado_atribucion"] == "atribuida":
                lineas.append(
                    f"  [{a['herramienta']:7}] {a['objetivo']} | {a['archivo']}:{a['linea_inicio']} | "
                    f"{a['recurso']} | {a['regla']} -> {a['control']}"
                )
        ev_path = root / "evidencia" / f"{dt.date.today().isoformat()}_piloto_revision.txt"
        ev_path.write_text("\n".join(lineas) + "\n", encoding="utf-8")
        print(f"Reporte de revision manual guardado en: {ev_path}")
    else:
        ev_path = root / "evidencia" / f"{dt.date.today().isoformat()}_normalizacion_completa.txt"
        ev_path.write_text("\n".join(lineas) + "\n", encoding="utf-8")
        print(f"Resumen de normalizacion guardado en: {ev_path}")

    print("\n".join(lineas[:12]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
