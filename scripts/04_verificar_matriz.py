#!/usr/bin/env python3
"""Fase 3: verifica la Matriz de Equivalencia contra los repositorios fuente fijados,
calcula cobertura (3/3, 2/3, 1/3, 0/3), J_reglas (H1) y genera la muestra aleatoria del 25%
para la segunda pasada de estabilidad.
"""

from __future__ import annotations

import collections
import csv
import datetime as dt
import json
import random
import sys
from pathlib import Path

SEMILLA_SEGUNDA_PASADA = 20261124

COMMITS_ESPERADOS = {
    "checkov": ("https://github.com/bridgecrewio/checkov/blob/af20f73b3f9ef72c04c8a524ed41f6c5f39a3490/", "/tmp/reglas_fase3/checkov"),
    "trivy": ("https://github.com/aquasecurity/trivy-checks/blob/6ceb33758a0f28d6e37e6cd571dc6816beeadbcc/", "/tmp/reglas_fase3/trivy-checks"),
    "kics": ("https://github.com/Checkmarx/kics/blob/28e01700646273c1a959d5c53eac4b1aa3834477/", "/tmp/reglas_fase3/kics"),
}


def verificar_fuente_local(tool: str, rule_id: str, url: str) -> list[str]:
    errores: list[str] = []
    if bool(rule_id) != bool(url):
        return [f"{tool}: regla='{rule_id}' y fuente='{url}' inconsistentes"]
    if not rule_id:
        return []

    prefix, local_base = COMMITS_ESPERADOS[tool]
    if not url.startswith(prefix):
        errores.append(f"{tool}: URL no coincide con commit fijado ({url})")
        return errores

    rel = url[len(prefix):]
    local_dir = Path(local_base)
    if not local_dir.exists():
        return errores

    local_file = local_dir / rel
    if not local_file.exists():
        errores.append(f"{tool}: archivo no existe en commit fijado ({rel})")
        return errores

    if tool == "kics":
        meta_file = local_file.parent / "metadata.json"
        if not meta_file.exists():
            errores.append(f"kics: falta metadata.json junto a {rel}")
        else:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            if meta.get("id") != rule_id:
                errores.append(f"kics: ID {rule_id} != metadata.json id {meta.get('id')} en {rel}")
    elif tool == "trivy":
        txt = local_file.read_text(encoding="utf-8", errors="ignore")
        short_id = rule_id.replace("AVD-", "")
        if rule_id not in txt and short_id not in txt:
            errores.append(f"trivy: ID {rule_id} no aparece en {rel}")
        if "deprecated: true" in txt:
            errores.append(f"trivy: {rule_id} esta marcada deprecated: true en {rel}")
    elif tool == "checkov":
        txt = local_file.read_text(encoding="utf-8", errors="ignore")
        if rule_id not in txt:
            errores.append(f"checkov: ID {rule_id} no aparece en {rel}")

    return errores


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    matriz_dir = root / "matriz"
    evidencia_dir = root / "evidencia"
    evidencia_dir.mkdir(parents=True, exist_ok=True)

    cat = list(csv.DictReader((matriz_dir / "catalogo_controles.csv").open(encoding="utf-8")))
    eq = list(csv.DictReader((matriz_dir / "equivalencias.csv").open(encoding="utf-8")))

    ids_cat = [r["id_control"] for r in cat]
    ids_eq = [r["id_control"] for r in eq]
    errores: list[str] = []

    if ids_cat != ids_eq:
        errores.append(f"Desajuste entre catalogo ({len(ids_cat)}) y equivalencias ({len(ids_eq)})")

    coberturas = collections.Counter()
    por_servicio: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    por_herramienta = collections.Counter()
    c_comp: list[str] = []

    for row in eq:
        cid = row["id_control"]
        svc = row["servicio"]
        n = 0
        for tool in ("checkov", "trivy", "kics"):
            rid = row[f"regla_{tool}"].strip()
            url = row[f"fuente_{tool}"].strip()
            errs = verificar_fuente_local(tool, rid, url)
            for e in errs:
                errores.append(f"[{cid}] {e}")
            if rid:
                n += 1
                por_herramienta[tool] += 1

        esperada = f"{n}/3"
        if row["cobertura"].strip() != esperada:
            errores.append(f"[{cid}] cobertura declarada '{row['cobertura']}' != calculada '{esperada}'")
        coberturas[esperada] += 1
        por_servicio[svc][esperada] += 1
        if n == 3:
            c_comp.append(cid)

    n_3 = coberturas["3/3"]
    n_alguna = coberturas["3/3"] + coberturas["2/3"] + coberturas["1/3"]
    j_reglas = (n_3 / n_alguna) if n_alguna else 0.0

    # Muestra aleatoria del 25% para segunda pasada (8 de 30 controles)
    rng = random.Random(SEMILLA_SEGUNDA_PASADA)
    k_muestra = max(1, round(len(eq) * 0.25))
    muestra = sorted(rng.sample(eq, k=k_muestra), key=lambda r: ids_eq.index(r["id_control"]))

    muestra_path = matriz_dir / "segunda_pasada_muestra.csv"
    with muestra_path.open("w", newline="", encoding="utf-8") as fh:
        campos = [
            "id_control", "servicio", "regla_checkov_p1", "regla_trivy_p1", "regla_kics_p1",
            "cobertura_p1", "cobertura_p2", "coincide", "observaciones_p2",
        ]
        w = csv.DictWriter(fh, fieldnames=campos)
        w.writeheader()
        for r in muestra:
            w.writerow({
                "id_control": r["id_control"],
                "servicio": r["servicio"],
                "regla_checkov_p1": r["regla_checkov"],
                "regla_trivy_p1": r["regla_trivy"],
                "regla_kics_p1": r["regla_kics"],
                "cobertura_p1": r["cobertura"],
                "cobertura_p2": "",
                "coincide": "",
                "observaciones_p2": f"semilla={SEMILLA_SEGUNDA_PASADA}; pendiente revision independiente",
            })

    lineas = [
        f"Fecha verificacion: {dt.date.today().isoformat()}",
        f"Total controles en catalogo a priori: {len(eq)}",
        f"Cobertura global: 3/3={coberturas['3/3']}, 2/3={coberturas['2/3']}, 1/3={coberturas['1/3']}, 0/3={coberturas['0/3']}",
        f"Cobertura por herramienta: checkov={por_herramienta['checkov']}/{len(eq)}, trivy={por_herramienta['trivy']}/{len(eq)}, kics={por_herramienta['kics']}/{len(eq)}",
        "Desglose por servicio:",
    ]
    for svc in ("IAM", "S3", "VPC_SG"):
        c = por_servicio[svc]
        lineas.append(f"  - {svc}: 3/3={c['3/3']}, 2/3={c['2/3']}, 1/3={c['1/3']}, 0/3={c['0/3']}")
    lineas.append(f"J_reglas = |3/3| / |>=1/3| = {n_3} / {n_alguna} = {j_reglas:.4f} (criterio H1: < 0.50 -> {'SE CUMPLE' if j_reglas < 0.50 else 'NO SE CUMPLE'})")
    lineas.append(f"C_comp ({len(c_comp)} controles): {', '.join(c_comp)}")
    lineas.append(f"Muestra 25% segunda pasada (semilla={SEMILLA_SEGUNDA_PASADA}, k={k_muestra}): {', '.join(r['id_control'] for r in muestra)}")
    lineas.append(f"Errores de verificacion contra codigo fuente: {len(errores)}")
    for e in errores:
        lineas.append(f"  ERROR: {e}")

    report = "\n".join(lineas) + "\n"
    out_ev = evidencia_dir / f"{dt.date.today().isoformat()}_verificacion_matriz.txt"
    out_ev.write_text(report, encoding="utf-8")
    print(report)
    return 0 if not errores else 1


if __name__ == "__main__":
    raise SystemExit(main())
