#!/usr/bin/env python3
"""Fase 5: evalua los dos oraculos de control (IAM Vulnerable y casos sembrados V/S).

Produce:
  1. matriz/iam_vulnerable_reglas.csv  (decision 1 vez por regla activada en privesc*.tf)
  2. analisis/iam_vulnerable.csv       (31 rutas x 3 herramientas: recall permisivo y estricto)
  3. analisis/casos_sembrados.csv      (27 controles x 3 herramientas: deteccion en V y FP de control en S)
  4. evidencia/<fecha>_evaluacion_oraculos.txt
"""

from __future__ import annotations

import collections
import csv
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any


def extraer_permiso_ruta(nombre_archivo: str) -> str:
    """Deriva el identificador de tecnica/permiso de escalamiento desde `privesc*.tf`."""
    stem = Path(nombre_archivo).stem
    return re.sub(r"^privesc\d*-", "", stem)


def cargar_nombres_reglas_iv(root: Path) -> dict[tuple[str, str], str]:
    base = root / "resultados" / "crudos" / "completo"
    nombres: dict[tuple[str, str], str] = {}

    ck = json.loads((base / "checkov" / "iam_vulnerable__todas_31rutas.json").read_text(encoding="utf-8"))
    for c in (ck.get("results") or {}).get("failed_checks", []):
        nombres[("checkov", c.get("check_id", ""))] = c.get("check_name", "")

    tr = json.loads((base / "trivy" / "iam_vulnerable__todas_31rutas.json").read_text(encoding="utf-8"))
    for res in tr.get("Results") or []:
        for m in res.get("Misconfigurations") or []:
            rid = m.get("ID", "")
            if rid and not rid.startswith("AVD-"):
                rid = "AVD-" + rid
            nombres[("trivy", rid)] = m.get("Title", "")

    kc = json.loads((base / "kics" / "iam_vulnerable__todas_31rutas.json").read_text(encoding="utf-8"))
    for q in kc.get("queries") or []:
        nombres[("kics", q.get("query_id", ""))] = q.get("query_name", "")

    return nombres


def clasificar_regla_iv(tool: str, regla: str, nombre: str) -> tuple[int, str, str]:
    """Devuelve (comprueba_escalamiento 0/1, permisos_verificados, justificacion).

    Decision tomada 1 vez por regla sobre el codigo fuente de las versiones fijadas
    (Checkov 3.4.5, Trivy trivy-checks v2.3.0, KICS v2.2.1).
    """
    if tool == "checkov":
        if regla == "CKV_AWS_286":
            return (
                1,
                "policy_sentry:privilege_escalation",
                "IAMPrivilegeEscalation.py evalua combinaciones de acciones de escalamiento de privilegios via policy_sentry",
            )
        if regla == "CKV_AWS_289":
            return (
                0,
                "permissions_management:*",
                "IAMPermissionsManagement.py verifica nivel generico de gestion de permisos sin restricciones, no tecnicas de escalamiento",
            )
        if regla == "CKV_AWS_287":
            return (
                0,
                "credentials_exposure",
                "IAMCredentialsExposure.py detecta exposicion de credenciales, no la tecnica de escalamiento de la ruta",
            )
        if regla == "CKV_AWS_288":
            return (
                0,
                "data_exfiltration",
                "IAMDataExfiltration.py detecta exfiltracion de datos, no escalamiento de privilegios",
            )
        if regla in ("CKV_AWS_290", "CKV_AWS_355"):
            return (
                0,
                "Resource:*",
                "Regla generica de comodin Resource:'*' en acciones de escritura/restringibles, no permiso de escalamiento",
            )
        if regla == "CKV_AWS_40":
            return (
                0,
                "CIS-1.15 (user policy attachment)",
                "Verifica adjuntar politicas a usuarios en vez de grupos/roles, independiente del permiso de escalamiento",
            )
        if regla in ("CKV_AWS_62", "CKV_AWS_63", "CKV2_AWS_40"):
            return (
                0,
                "Action:* / iam:*",
                "Verifica privilegios administrativos globales (*:* o iam:*), no la tecnica especifica de escalamiento",
            )
        if regla == "CKV_AWS_273":
            return (
                0,
                "aws_iam_user (SSO)",
                "Sugiere usar SSO en lugar de usuarios IAM; se activa sobre cualquier aws_iam_user",
            )
        return (0, "generica", "Regla generica de IAM sin verificacion de permiso de escalamiento")

    if tool == "trivy":
        if regla == "AVD-AWS-0342":
            return (
                1,
                "iam:PassRole",
                "filter_iam_pass_role.rego verifica explicitamente 'iam:PassRole' en Allow sin Deny (sin filtrar Resource ni Condition)",
            )
        if regla == "AVD-AWS-0143":
            return (
                0,
                "CIS-1.15 (user policy attachment)",
                "no_user_attached_policies.rego comprueba politicas adjuntas a usuarios, no el permiso de escalamiento",
            )
        if regla == "AVD-AWS-0123":
            return (
                0,
                "MFA en grupo IAM",
                "enforce_group_mfa.rego verifica ausencia de MFA en grupos, no permiso de escalamiento",
            )
        return (0, "generica", "Regla generica de IAM sin verificacion de permiso de escalamiento")

    if tool == "kics":
        m = re.search(r"Privilege Escalation By Actions (.+)$", nombre)
        if m:
            acciones = " + ".join(re.findall(r"'([^']+)'", m.group(1)))
            return (
                1,
                acciones or m.group(1),
                f"Consulta dedicada de KICS para escalamiento de privilegios mediante {acciones or m.group(1)}",
            )
        return (
            0,
            "generica",
            f"Regla generica/higiene ({nombre}); no verifica el permiso de escalamiento de la ruta",
        )

    return (0, "", "")


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    alertas = list(csv.DictReader((root / "resultados" / "normalizados" / "alertas.csv").open(encoding="utf-8")))
    eq_rows = list(csv.DictReader((root / "matriz" / "equivalencias.csv").open(encoding="utf-8")))

    en_matriz: dict[str, set[str]] = {"checkov": set(), "trivy": set(), "kics": set()}
    for r in eq_rows:
        for t in ("checkov", "trivy", "kics"):
            rid = r[f"regla_{t}"].strip()
            if rid and rid != "NA":
                en_matriz[t].add(rid)

    # ------------------------------------------------------------------
    # 1. IAM VULNERABLE: matriz/iam_vulnerable_reglas.csv + analisis/iam_vulnerable.csv
    # ------------------------------------------------------------------
    iv_dir = root / "iam_vulnerable" / "repo" / "modules" / "free-resources" / "privesc-paths"
    rutas_31 = sorted(p.name for p in iv_dir.glob("privesc*.tf"))
    if len(rutas_31) != 31:
        raise RuntimeError(f"Se esperaban 31 rutas privesc*.tf, se encontraron {len(rutas_31)}")

    nombres_iv = cargar_nombres_reglas_iv(root)
    iv_iam = [
        a for a in alertas
        if a["objetivo"] == "iam_vulnerable__todas_31rutas"
        and a["archivo"] in set(rutas_31)
        and (a["tipo_recurso"].startswith("aws_iam_") or a["tipo_recurso"] == "data.aws_iam_policy_document")
    ]

    reglas_distintas: dict[tuple[str, str], set[str]] = collections.defaultdict(set)
    for a in iv_iam:
        reglas_distintas[(a["herramienta"], a["regla"])].add(a["archivo"])

    reglas_rows: list[dict[str, Any]] = []
    es_estricto: dict[tuple[str, str], int] = {}
    for (tool, rid), files in sorted(reglas_distintas.items()):
        nombre = nombres_iv.get((tool, rid), "")
        est, perms, just = clasificar_regla_iv(tool, rid, nombre)
        es_estricto[(tool, rid)] = est
        reglas_rows.append({
            "herramienta": tool,
            "regla": rid,
            "nombre_regla": nombre,
            "en_matriz_equivalencias": int(rid in en_matriz[tool]),
            "rutas_activadas": len(files),
            "comprueba_escalamiento": est,
            "permisos_verificados": perms,
            "justificacion": just,
        })

    iv_reglas_csv = root / "matriz" / "iam_vulnerable_reglas.csv"
    with iv_reglas_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "herramienta", "regla", "nombre_regla", "en_matriz_equivalencias",
                "rutas_activadas", "comprueba_escalamiento", "permisos_verificados", "justificacion",
            ],
        )
        w.writeheader()
        w.writerows(reglas_rows)

    por_ruta_tool: dict[tuple[str, str], set[str]] = collections.defaultdict(set)
    for a in iv_iam:
        por_ruta_tool[(a["archivo"], a["herramienta"])].add(a["regla"])

    iv_rows: list[dict[str, Any]] = []
    resumen_iv: dict[str, dict[str, int]] = {t: {"perm": 0, "est": 0} for t in ("checkov", "trivy", "kics")}
    for ruta in rutas_31:
        perm_ruta = extraer_permiso_ruta(ruta)
        for tool in ("checkov", "trivy", "kics"):
            regs = sorted(por_ruta_tool[(ruta, tool)])
            regs_est = [r for r in regs if es_estricto.get((tool, r), 0) == 1]
            perm = int(len(regs) > 0)
            est = int(len(regs_est) > 0)
            resumen_iv[tool]["perm"] += perm
            resumen_iv[tool]["est"] += est
            iv_rows.append({
                "ruta": ruta,
                "permiso_ruta": perm_ruta,
                "herramienta": tool,
                "permisivo": perm,
                "estricto": est,
                "reglas_permisivas": "|".join(regs),
                "reglas_estrictas": "|".join(regs_est),
            })

    iv_out_csv = root / "analisis" / "iam_vulnerable.csv"
    iv_out_csv.parent.mkdir(parents=True, exist_ok=True)
    with iv_out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["ruta", "permiso_ruta", "herramienta", "permisivo", "estricto", "reglas_permisivas", "reglas_estrictas"],
        )
        w.writeheader()
        w.writerows(iv_rows)

    # ------------------------------------------------------------------
    # 2. CASOS SEMBRADOS (V vs S): analisis/casos_sembrados.csv
    # ------------------------------------------------------------------
    controles = list(csv.DictReader((root / "casos_sembrados" / "controles.csv").open(encoding="utf-8")))
    sem_alertas = [a for a in alertas if a["grupo"] == "sembrado"]

    # Mapear alertas atribuidas por (caso, variante, herramienta)
    atrib_sem: dict[tuple[str, str, str], list[dict[str, Any]]] = collections.defaultdict(list)
    for a in sem_alertas:
        _, caso, var = a["objetivo"].split("__", 2)
        if a["estado_atribucion"] == "atribuida":
            atrib_sem[(caso, var, a["herramienta"])].append(a)

    # Resolver alias de CIS-5.2 en caso_05 -> CIS-5.2-SSH (C19) y CIS-5.2-RDP (C20)
    def controles_equivalentes(row_c: dict[str, str]) -> set[str]:
        ccat = row_c["control_catalogo"].strip()
        if row_c["id_control"] == "C19":
            return {"CIS-5.2-SSH", "CIS-5.2"}
        if row_c["id_control"] == "C20":
            return {"CIS-5.2-RDP", "CIS-5.2"}
        return {ccat}

    sem_rows: list[dict[str, Any]] = []
    resumen_sem: dict[str, dict[str, int]] = {
        t: {"det_V": 0, "fp_S": 0, "alertas_totales_S": 0, "alertas_fp_S": 0, "incidentales_S": 0}
        for t in ("checkov", "trivy", "kics")
    }
    fp_claves_s: dict[str, set[tuple[str, str, str]]] = {t: set() for t in ("checkov", "trivy", "kics")}

    for c in controles:
        caso = c["caso"]
        recs_obj = {x.strip() for x in c["recurso_objetivo"].split("|") if x.strip()}
        ctrls_eq = controles_equivalentes(c)
        for tool in ("checkov", "trivy", "kics"):
            regs_v: set[str] = set()
            for a in atrib_sem[(caso, "V", tool)]:
                actrls = set(a["control"].split("|")) if a["control"] else set()
                if a["recurso"] in recs_obj and (actrls & ctrls_eq):
                    regs_v.add(a["regla"])

            regs_s: set[str] = set()
            for a in atrib_sem[(caso, "S", tool)]:
                actrls = set(a["control"].split("|")) if a["control"] else set()
                if a["recurso"] in recs_obj and (actrls & ctrls_eq):
                    regs_s.add(a["regla"])
                    fp_claves_s[tool].add((caso, a["recurso"], a["regla"]))

            det_v = int(len(regs_v) > 0)
            fp_s = int(len(regs_s) > 0)
            resumen_sem[tool]["det_V"] += det_v
            resumen_sem[tool]["fp_S"] += fp_s

            sem_rows.append({
                "id_control": c["id_control"],
                "caso": caso,
                "servicio": c["servicio"],
                "control_catalogo": c["control_catalogo"],
                "recurso_objetivo": c["recurso_objetivo"],
                "herramienta": tool,
                "detectado_V": det_v,
                "fp_control_S": fp_s,
                "reglas_V": "|".join(sorted(regs_v)),
                "reglas_fp_S": "|".join(sorted(regs_s)),
            })

    # Contar alertas totales vs incidentales en todas las variantes S
    for a in sem_alertas:
        if not a["objetivo"].endswith("__S"):
            continue
        _, caso, _ = a["objetivo"].split("__", 2)
        t = a["herramienta"]
        resumen_sem[t]["alertas_totales_S"] += 1
        if (caso, a["recurso"], a["regla"]) in fp_claves_s[t]:
            resumen_sem[t]["alertas_fp_S"] += 1
        else:
            resumen_sem[t]["incidentales_S"] += 1

    sem_out_csv = root / "analisis" / "casos_sembrados.csv"
    with sem_out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "id_control", "caso", "servicio", "control_catalogo", "recurso_objetivo",
                "herramienta", "detectado_V", "fp_control_S", "reglas_V", "reglas_fp_S",
            ],
        )
        w.writeheader()
        w.writerows(sem_rows)

    # ------------------------------------------------------------------
    # 3. Reporte en evidencia/
    # ------------------------------------------------------------------
    lines = [
        f"Evaluacion de oraculos de control - Fase 5 ({dt.date.today().isoformat()})",
        "",
        "1. IAM Vulnerable (31 rutas, decision 1 vez por regla en matriz/iam_vulnerable_reglas.csv):",
        f"   Reglas distintas sobre recursos IAM en privesc*.tf: {len(reglas_rows)}",
    ]
    for t in ("checkov", "trivy", "kics"):
        p = resumen_iv[t]["perm"]
        e = resumen_iv[t]["est"]
        pp_p = 100.0 * p / 31.0
        pp_e = 100.0 * e / 31.0
        caida = pp_p - pp_e
        lines.append(
            f"   - {t:7}: permisivo={p:2}/31 ({pp_p:5.1f}%) | estricto={e:2}/31 ({pp_e:5.1f}%) | caida={caida:5.1f} pp"
        )

    lines.extend([
        "",
        "2. Casos sembrados (7 casos, 27 controles V/S, analisis/casos_sembrados.csv):",
    ])
    for t in ("checkov", "trivy", "kics"):
        r = resumen_sem[t]
        fp_pct = 100.0 * r["fp_S"] / len(controles)
        det_pct = 100.0 * r["det_V"] / len(controles)
        lines.append(
            f"   - {t:7}: detectados_V={r['det_V']:2}/27 ({det_pct:5.1f}%) | "
            f"FP_control_S={r['fp_S']:2}/27 ({fp_pct:4.1f}%) | "
            f"alertas_totales_S={r['alertas_totales_S']:3} (control_FP={r['alertas_fp_S']}, incidentales={r['incidentales_S']})"
        )

    ev_path = root / "evidencia" / f"{dt.date.today().isoformat()}_evaluacion_oraculos.txt"
    ev_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nArchivos escritos:\n  - {iv_reglas_csv}\n  - {iv_out_csv}\n  - {sem_out_csv}\n  - {ev_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
