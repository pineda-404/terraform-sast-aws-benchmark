#!/usr/bin/env python3
"""Fase 6: analisis estadistico congelado (DISENO_CONGELADO.md §4).

Calcula exactamente las metricas congeladas del estudio:
  - J_reglas y cobertura 3/3, 2/3, 1/3, 0/3 (H1)
  - Prevalencia por herramienta y servicio (corpus de 45 modulos)
  - Porcentaje de acuerdo P_o, kappa de Fleiss y AC1 de Gwet con IC 95%
    por cluster bootstrap por modulo (B=10,000, semilla fija 20261126) (H2)
  - kappa de Cohen por pares (descriptiva)
  - Recall permisivo y estricto en IAM Vulnerable (31 rutas) (H3a)
  - Falsos positivos de control en casos sembrados (27 controles V/S) (H3b)

Valida Fleiss contra `statsmodels` y AC1 contra caso analitico de referencia,
y genera:
  - analisis/metricas.json
  - analisis/tablas/*.tex
  - analisis/figuras/*.pdf
  - evidencia/<fecha>_validacion_estadistica.txt
"""

from __future__ import annotations

import collections
import csv
import datetime as dt
import json
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import cohen_kappa_score
from statsmodels.stats.inter_rater import aggregate_raters, fleiss_kappa

SEMILLA = 20261126
B_BOOTSTRAP = 10_000
TOOLS = ("checkov", "trivy", "kics")
TOOL_LABELS = {"checkov": "Checkov", "trivy": "Trivy", "kics": "KICS"}
SERVICIOS = ("IAM", "S3", "VPC_SG")


def calcular_fleiss_ac1_po(mat: np.ndarray) -> tuple[float, float | None, float]:
    """Calcula (P_o, kappa_fleiss, AC1_gwet) para matriz binaria (N x 3).

    Si 1 - P_e_fleiss == 0 (varianza nula), devuelve kappa_fleiss = None.
    """
    n_u, n_r = mat.shape
    assert n_r == 3
    n1 = mat.sum(axis=1)
    n0 = n_r - n1

    # Proporcion de unidades con acuerdo unanime (3 de 3)
    po = float(np.mean((n1 == 0) | (n1 == n_r)))

    # P_i de Fleiss / Gwet (con n=3, P_i vale 1 si unanime y 1/3 si 2 vs 1)
    p_i = (n0 * (n0 - 1) + n1 * (n1 - 1)) / (n_r * (n_r - 1))
    p_bar = float(np.mean(p_i))

    p1 = float(np.sum(n1) / (n_u * n_r))
    p0 = 1.0 - p1

    # Fleiss
    pe_fleiss = p0 * p0 + p1 * p1
    denom_f = 1.0 - pe_fleiss
    fleiss = None if abs(denom_f) < 1e-15 else float((p_bar - pe_fleiss) / denom_f)

    # Gwet AC1 (Q = 2 categorias -> P_e = 2 * p1 * (1 - p1))
    pe_gwet = 2.0 * p1 * (1.0 - p1)
    denom_g = 1.0 - pe_gwet
    ac1 = 1.0 if abs(denom_g) < 1e-15 else float((p_bar - pe_gwet) / denom_g)

    return po, fleiss, ac1


def cluster_bootstrap(df: pd.DataFrame, b_reps: int = B_BOOTSTRAP, semilla: int = SEMILLA) -> dict[str, Any]:
    """Cluster bootstrap por modulo (remuestreo con reemplazo de modulos)."""
    rng = np.random.default_rng(semilla)
    modulos = df["modulo"].unique()
    n_mods = len(modulos)

    # Pre-extraer vectores de conteos por modulo para acelerar 10,000 replicas manteniendo exactitud
    bloques: list[tuple[int, float, float, int]] = []
    for m in modulos:
        sub = df.loc[df["modulo"] == m, ["X_checkov", "X_trivy", "X_kics"]].to_numpy(dtype=np.int64)
        n1 = sub.sum(axis=1)
        n0 = 3 - n1
        unanimes = int(np.sum((n1 == 0) | (n1 == 3)))
        sum_pi = float(np.sum((n0 * (n0 - 1) + n1 * (n1 - 1)) / 6.0))
        sum_n1 = int(np.sum(n1))
        bloques.append((len(sub), sum_pi, float(unanimes), sum_n1))

    arr_len = np.array([b[0] for b in bloques], dtype=np.float64)
    arr_pi = np.array([b[1] for b in bloques], dtype=np.float64)
    arr_un = np.array([b[2] for b in bloques], dtype=np.float64)
    arr_n1 = np.array([b[3] for b in bloques], dtype=np.float64)

    po_vals = np.empty(b_reps, dtype=np.float64)
    ac1_vals = np.empty(b_reps, dtype=np.float64)
    fleiss_vals: list[float] = []
    descartadas_fleiss = 0

    idx_mat = rng.integers(0, n_mods, size=(b_reps, n_mods))
    tot_len = arr_len[idx_mat].sum(axis=1)
    tot_pi = arr_pi[idx_mat].sum(axis=1)
    tot_un = arr_un[idx_mat].sum(axis=1)
    tot_n1 = arr_n1[idx_mat].sum(axis=1)

    po_vals = tot_un / tot_len
    p_bar = tot_pi / tot_len
    p1 = tot_n1 / (3.0 * tot_len)
    p0 = 1.0 - p1

    pe_f = p0 * p0 + p1 * p1
    denom_f = 1.0 - pe_f
    valid_f = np.abs(denom_f) >= 1e-15
    descartadas_fleiss = int(np.sum(~valid_f))
    fleiss_arr = (p_bar[valid_f] - pe_f[valid_f]) / denom_f[valid_f]

    pe_g = 2.0 * p1 * (1.0 - p1)
    ac1_vals = (p_bar - pe_g) / (1.0 - pe_g)

    def ic95(arr: np.ndarray) -> list[float]:
        if len(arr) == 0:
            return [float("nan"), float("nan")]
        lo, hi = np.percentile(arr, [2.5, 97.5])
        return [round(float(lo), 4), round(float(hi), 4)]

    return {
        "replicas_totales": b_reps,
        "semilla": semilla,
        "modulos_en_cluster": int(n_mods),
        "replicas_descartadas_fleiss": descartadas_fleiss,
        "po_ic95": ic95(po_vals),
        "fleiss_ic95": ic95(fleiss_arr),
        "ac1_ic95": ic95(ac1_vals),
    }


def validar_implementacion(df: pd.DataFrame, ev_path: Path) -> dict[str, Any]:
    """Valida Fleiss contra statsmodels y AC1 contra caso analitico de referencia."""
    mat = df[["X_checkov", "X_trivy", "X_kics"]].to_numpy(dtype=np.int64)
    po, k_manual, ac1_manual = calcular_fleiss_ac1_po(mat)

    agg, _ = aggregate_raters(mat, n_cat=2)
    k_sm = float(fleiss_kappa(agg, method="fleiss"))
    diff_fleiss = abs((k_manual or 0.0) - k_sm)
    assert diff_fleiss < 1e-12, f"Discrepancia Fleiss vs statsmodels: {diff_fleiss}"

    # Caso analitico cerrado para AC1 (Q=2, n=3, N=10):
    # 7 unidades (0,0,0), 1 unidad (1,1,1), 2 unidades (0,0,1)
    # P_bar = (7*1 + 1*1 + 2*(1/3)) / 10 = 8.6666666667 / 10 = 0.8666666667
    # p1 = (0*7 + 3*1 + 1*2) / 30 = 5/30 = 1/6; P_e_gwet = 2*(1/6)*(5/6) = 10/36 = 0.2777777778
    # AC1 = (26/30 - 10/36) / (1 - 10/36) = (156/180 - 50/180) / (130/180) = 106/130 = 0.8153846154
    test_mat = np.array(
        [[0, 0, 0]] * 7 + [[1, 1, 1]] * 1 + [[0, 0, 1]] * 2,
        dtype=np.int64,
    )
    _, k_t, ac1_t = calcular_fleiss_ac1_po(test_mat)
    agg_t, _ = aggregate_raters(test_mat, n_cat=2)
    k_t_sm = float(fleiss_kappa(agg_t, method="fleiss"))
    ac1_exact = 106.0 / 130.0
    diff_ac1 = abs(ac1_t - ac1_exact)
    diff_kt = abs((k_t or 0.0) - k_t_sm)
    assert diff_ac1 < 1e-12, f"Discrepancia AC1 analitico: {diff_ac1}"
    assert diff_kt < 1e-12, f"Discrepancia Fleiss caso analitico: {diff_kt}"

    lines = [
        f"Validacion estadistica obligatoria - Fase 6 ({dt.date.today().isoformat()})",
        "",
        "1. Validacion de kappa de Fleiss sobre analisis/unidades.csv (N=508, n=3):",
        f"   - Implementacion propia : {k_manual:.12f}",
        f"   - statsmodels (fleiss)  : {k_sm:.12f}",
        f"   - Diferencia absoluta   : {diff_fleiss:.3e} (< 1e-12 OK)",
        "",
        "2. Validacion analitica de AC1 de Gwet y Fleiss (N=10, n=3, Q=2; 7x(0,0,0), 1x(1,1,1), 2x(0,0,1)):",
        f"   - AC1 implementacion    : {ac1_t:.12f}",
        f"   - AC1 valor exacto      : {ac1_exact:.12f} (106/130)",
        f"   - Diferencia absoluta   : {diff_ac1:.3e} (< 1e-12 OK)",
        f"   - Fleiss implementacion : {k_t:.12f} vs statsmodels {k_t_sm:.12f} (diff={diff_kt:.3e} OK)",
        "",
        f"3. Valores observados globales en U: P_o={po:.6f}, Fleiss={k_manual:.6f}, AC1={ac1_manual:.6f}",
    ]
    ev_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "fleiss_propio": round(k_manual or 0.0, 12),
        "fleiss_statsmodels": round(k_sm, 12),
        "diff_fleiss": diff_fleiss,
        "ac1_analitico_diff": diff_ac1,
    }


def generar_tablas_latex(metricas: dict[str, Any], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    creadas: list[Path] = []

    # 1. Corpus por servicio
    c = metricas["corpus"]
    tex = [
        r"\begin{tabular}{lrrr}",
        r"\toprule",
        r"Servicio & Módulos seleccionados & Módulos con unidades en $\mathcal{U}$ & Unidades $(r, c)$ en $\mathcal{U}$ \\",
        r"\midrule",
    ]
    for s in SERVICIOS:
        d = c["por_servicio"][s]
        s_lbl = "VPC/SG" if s == "VPC_SG" else s
        tex.append(f"{s_lbl} & {d['modulos_totales']} & {d['modulos_en_U']} & {d['unidades_U']} \\\\")
    tex.extend([
        r"\midrule",
        f"\\textbf{{Total}} & \\textbf{{{c['modulos_totales']}}} & \\textbf{{{c['modulos_en_U']}}} & \\textbf{{{c['unidades_U']}}} \\\\",
        r"\bottomrule",
        r"\end{tabular}",
    ])
    p = out_dir / "tabla_corpus.tex"
    p.write_text("\n".join(tex) + "\n", encoding="utf-8")
    creadas.append(p)

    # 2. Cobertura H1
    h1 = metricas["h1_cobertura"]
    tex = [
        r"\begin{tabular}{lrrrrr}",
        r"\toprule",
        r"Servicio & $3/3$ & $2/3$ & $1/3$ & $0/3$ & Total \\",
        r"\midrule",
    ]
    for s in SERVICIOS:
        d = h1["por_servicio"][s]
        s_lbl = "VPC/SG" if s == "VPC_SG" else s
        tex.append(f"{s_lbl} & {d['3/3']} & {d['2/3']} & {d['1/3']} & {d['0/3']} & {d['total']} \\\\")
    g = h1["global"]
    tex.extend([
        r"\midrule",
        f"\\textbf{{Total}} & \\textbf{{{g['3/3']}}} & \\textbf{{{g['2/3']}}} & \\textbf{{{g['1/3']}}} & \\textbf{{{g['0/3']}}} & \\textbf{{{g['total']}}} \\\\",
        r"\bottomrule",
        r"\end{tabular}",
    ])
    p = out_dir / "tabla_cobertura_h1.tex"
    p.write_text("\n".join(tex) + "\n", encoding="utf-8")
    creadas.append(p)

    # 3. Prevalencia por herramienta y servicio (denominador = 45 modulos; 15 por servicio)
    prev = metricas["prevalencia"]
    tex = [
        r"\begin{tabular}{lcccc}",
        r"\toprule",
        r"Herramienta & IAM ($n=15$) & S3 ($n=15$) & VPC/SG ($n=15$) & Global ($n=45$) \\",
        r"\midrule",
    ]
    for t in TOOLS:
        cells = []
        for s in SERVICIOS:
            d = prev["por_servicio"][s][t]
            cells.append(f"{d['modulos_con_smell']}/{d['denominador']} ({d['porcentaje']:.1f}\\%)")
        dg = prev["global"][t]
        cells.append(f"{dg['modulos_con_smell']}/{dg['denominador']} ({dg['porcentaje']:.1f}\\%)")
        tex.append(f"{TOOL_LABELS[t]} & " + " & ".join(cells) + r" \\")
    tex.extend([r"\bottomrule", r"\end{tabular}"])
    p = out_dir / "tabla_prevalencia.tex"
    p.write_text("\n".join(tex) + "\n", encoding="utf-8")
    creadas.append(p)

    # 4. Concordancia H2 (P_o, Fleiss, AC1 con IC 95%)
    h2 = metricas["h2_concordancia"]
    tex = [
        r"\begin{tabular}{lrrccc}",
        r"\toprule",
        r"Ámbito & Módulos & $N$ & $P_o$ [IC 95\%] & $\kappa$ de Fleiss [IC 95\%] & $AC_1$ de Gwet [IC 95\%] \\",
        r"\midrule",
    ]
    for clave, lbl in (("global", "\\textbf{Global}"), ("IAM", "IAM"), ("S3", "S3"), ("VPC_SG", "VPC/SG")):
        d = h2["global"] if clave == "global" else h2["por_servicio"][clave]
        po_s = f"{d['P_o']:.4f} [{d['bootstrap']['po_ic95'][0]:.4f}, {d['bootstrap']['po_ic95'][1]:.4f}]"
        fl_s = (
            f"{d['fleiss_kappa']:.4f} [{d['bootstrap']['fleiss_ic95'][0]:.4f}, {d['bootstrap']['fleiss_ic95'][1]:.4f}]"
            if d["fleiss_kappa"] is not None
            else "N/D"
        )
        ac_s = f"{d['gwet_ac1']:.4f} [{d['bootstrap']['ac1_ic95'][0]:.4f}, {d['bootstrap']['ac1_ic95'][1]:.4f}]"
        tex.append(f"{lbl} & {d['modulos']} & {d['N']} & {po_s} & {fl_s} & {ac_s} \\\\")
    tex.extend([r"\bottomrule", r"\end{tabular}"])
    p = out_dir / "tabla_concordancia_h2.tex"
    p.write_text("\n".join(tex) + "\n", encoding="utf-8")
    creadas.append(p)

    # 5. Cohen por pares (descriptiva)
    coh = metricas["cohen_pares"]
    tex = [
        r"\begin{tabular}{lcc}",
        r"\toprule",
        r"Par de herramientas & Acuerdo observado ($P_o$ par) & $\kappa$ de Cohen \\",
        r"\midrule",
    ]
    for par_key, par_lbl in (
        ("checkov__trivy", "Checkov -- Trivy"),
        ("checkov__kics", "Checkov -- KICS"),
        ("trivy__kics", "Trivy -- KICS"),
    ):
        d = coh[par_key]
        tex.append(f"{par_lbl} & {d['po_par']:.4f} & {d['cohen_kappa']:.4f} \\\\")
    tex.extend([r"\bottomrule", r"\end{tabular}"])
    p = out_dir / "tabla_cohen_pares.tex"
    p.write_text("\n".join(tex) + "\n", encoding="utf-8")
    creadas.append(p)

    # 6. IAM Vulnerable H3a
    h3a = metricas["h3a_iam_vulnerable"]
    tex = [
        r"\begin{tabular}{lccc}",
        r"\toprule",
        r"Herramienta & \textit{Recall} permisivo ($n=31$) & \textit{Recall} estricto ($n=31$) & Caída (pp) \\",
        r"\midrule",
    ]
    for t in TOOLS:
        d = h3a["por_herramienta"][t]
        tex.append(
            f"{TOOL_LABELS[t]} & {d['permisivo_n']}/31 ({d['permisivo_pct']:.1f}\\%) & "
            f"{d['estricto_n']}/31 ({d['estricto_pct']:.1f}\\%) & {d['caida_pp']:.1f} \\\\"
        )
    tex.extend([r"\bottomrule", r"\end{tabular}"])
    p = out_dir / "tabla_iam_vulnerable_h3a.tex"
    p.write_text("\n".join(tex) + "\n", encoding="utf-8")
    creadas.append(p)

    # 7. Casos sembrados H3b
    h3b = metricas["h3b_casos_sembrados"]
    tex = [
        r"\begin{tabular}{lccc}",
        r"\toprule",
        r"Herramienta & Detectados en V ($n=27$) & FP de control en S ($n=27$) & Alertas incidentales en S \\",
        r"\midrule",
    ]
    for t in TOOLS:
        d = h3b["por_herramienta"][t]
        tex.append(
            f"{TOOL_LABELS[t]} & {d['detectados_V']}/27 ({d['detectados_V_pct']:.1f}\\%) & "
            f"{d['fp_control_S']}/27 ({d['fp_control_S_pct']:.1f}\\%) & {d['incidentales_S']} \\\\"
        )
    tex.extend([r"\bottomrule", r"\end{tabular}"])
    p = out_dir / "tabla_sembrados_h3b.tex"
    p.write_text("\n".join(tex) + "\n", encoding="utf-8")
    creadas.append(p)

    return creadas


def generar_figuras(metricas: dict[str, Any], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    creadas: list[Path] = []
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    colores = {"checkov": "#2b5c8f", "trivy": "#d97706", "kics": "#2e7d32"}

    # Fig 1: Prevalencia por servicio y global
    fig, ax = plt.subplots(figsize=(7.2, 4.0))
    grupos = ["IAM\n(n=15)", "S3\n(n=15)", "VPC/SG\n(n=15)", "Global\n(n=45)"]
    x = np.arange(len(grupos))
    w = 0.25
    prev = metricas["prevalencia"]
    for i, t in enumerate(TOOLS):
        vals = [prev["por_servicio"][s][t]["porcentaje"] for s in SERVICIOS] + [prev["global"][t]["porcentaje"]]
        bars = ax.bar(x + (i - 1) * w, vals, width=w, label=TOOL_LABELS[t], color=colores[t])
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 1.5, f"{v:.1f}%", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x)
    ax.set_xticklabels(grupos)
    ax.set_ylabel("Módulos con al menos un smell en $\\mathcal{C}_{\\mathrm{comp}}$ (%)")
    ax.set_ylim(0, 100)
    ax.legend(frameon=False)
    fig.tight_layout()
    p1 = out_dir / "fig_prevalencia.pdf"
    fig.savefig(p1)
    plt.close(fig)
    creadas.append(p1)

    # Fig 2: Recall permisivo vs estricto en IAM Vulnerable
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    h3a = metricas["h3a_iam_vulnerable"]["por_herramienta"]
    x = np.arange(len(TOOLS))
    w = 0.34
    perm = [h3a[t]["permisivo_pct"] for t in TOOLS]
    est = [h3a[t]["estricto_pct"] for t in TOOLS]
    b1 = ax.bar(x - w / 2, perm, width=w, label="Recall permisivo", color="#64748b")
    b2 = ax.bar(x + w / 2, est, width=w, label="Recall estricto", color="#1d4ed8")
    ax.axhline(85.0, color="#dc2626", linestyle="--", linewidth=1.1, label="Umbral H3a (85%)")
    for bars in (b1, b2):
        for b in bars:
            v = b.get_height()
            ax.text(b.get_x() + b.get_width() / 2, v + 1.5, f"{v:.1f}%", ha="center", va="bottom", fontsize=8.5)
    ax.set_xticks(x)
    ax.set_xticklabels([TOOL_LABELS[t] for t in TOOLS])
    ax.set_ylabel("Recall sobre 31 rutas (%)")
    ax.set_ylim(0, 114)
    ax.legend(frameon=False, loc="upper right")
    fig.tight_layout()
    p2 = out_dir / "fig_recall_iam_vulnerable.pdf"
    fig.savefig(p2)
    plt.close(fig)
    creadas.append(p2)

    # Fig 3: Mapa de calor de kappa de Cohen por pares
    coh = metricas["cohen_pares"]
    m_coh = np.array([
        [1.0, coh["checkov__trivy"]["cohen_kappa"], coh["checkov__kics"]["cohen_kappa"]],
        [coh["checkov__trivy"]["cohen_kappa"], 1.0, coh["trivy__kics"]["cohen_kappa"]],
        [coh["checkov__kics"]["cohen_kappa"], coh["trivy__kics"]["cohen_kappa"], 1.0],
    ])
    fig, ax = plt.subplots(figsize=(4.6, 4.0))
    im = ax.imshow(m_coh, cmap="Blues", vmin=0.0, vmax=1.0)
    lbls = [TOOL_LABELS[t] for t in TOOLS]
    ax.set_xticks(range(3))
    ax.set_yticks(range(3))
    ax.set_xticklabels(lbls)
    ax.set_yticklabels(lbls)
    for i in range(3):
        for j in range(3):
            v = m_coh[i, j]
            ax.text(j, i, f"{v:.3f}", ha="center", va="center", color="white" if v > 0.6 else "black", fontweight="bold")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="$\\kappa$ de Cohen")
    fig.tight_layout()
    p3 = out_dir / "fig_cohen_heatmap.pdf"
    fig.savefig(p3)
    plt.close(fig)
    creadas.append(p3)

    return creadas


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    df_u = pd.read_csv(root / "analisis" / "unidades.csv")
    df_mod = pd.read_csv(root / "corpus" / "modulos.csv")
    df_mod["modulo"] = df_mod["namespace"] + "__" + df_mod["nombre"]
    df_eq = pd.read_csv(root / "matriz" / "equivalencias.csv")
    df_iv = pd.read_csv(root / "analisis" / "iam_vulnerable.csv")
    df_sem = pd.read_csv(root / "analisis" / "casos_sembrados.csv")
    df_al = pd.read_csv(root / "resultados" / "normalizados" / "alertas.csv")

    # ------------------------------------------------------------------
    # 0. Validacion obligatoria de Fleiss y AC1
    # ------------------------------------------------------------------
    ev_path = root / "evidencia" / f"{dt.date.today().isoformat()}_validacion_estadistica.txt"
    validacion = validar_implementacion(df_u, ev_path)

    # ------------------------------------------------------------------
    # 1. Corpus
    # ------------------------------------------------------------------
    corpus_info: dict[str, Any] = {
        "modulos_totales": int(len(df_mod)),
        "modulos_en_U": int(df_u["modulo"].nunique()),
        "modulos_sin_unidades_U": sorted(set(df_mod["modulo"]) - set(df_u["modulo"])),
        "unidades_U": int(len(df_u)),
        "por_servicio": {},
    }
    for s in SERVICIOS:
        sub_m = df_mod[df_mod["servicio"] == s]
        sub_u = df_u[df_u["servicio"] == s]
        corpus_info["por_servicio"][s] = {
            "modulos_totales": int(len(sub_m)),
            "modulos_en_U": int(sub_u["modulo"].nunique()),
            "unidades_U": int(len(sub_u)),
        }

    # ------------------------------------------------------------------
    # 2. H1: Cobertura y J_reglas desde matriz/equivalencias.csv
    # ------------------------------------------------------------------
    cov_global = collections.Counter(df_eq["cobertura"].str.strip())
    c_33 = int(cov_global["3/3"])
    c_ge1 = int(cov_global["3/3"] + cov_global["2/3"] + cov_global["1/3"])
    j_reglas = c_33 / c_ge1
    h1_por_svc: dict[str, Any] = {}
    for s in SERVICIOS:
        sub = df_eq[df_eq["servicio"] == s]
        cnt = collections.Counter(sub["cobertura"].str.strip())
        h1_por_svc[s] = {
            "3/3": int(cnt["3/3"]),
            "2/3": int(cnt["2/3"]),
            "1/3": int(cnt["1/3"]),
            "0/3": int(cnt["0/3"]),
            "total": int(len(sub)),
        }
    h1_info = {
        "global": {
            "3/3": c_33,
            "2/3": int(cov_global["2/3"]),
            "1/3": int(cov_global["1/3"]),
            "0/3": int(cov_global["0/3"]),
            "total": int(len(df_eq)),
            "cubiertos_al_menos_una": c_ge1,
        },
        "por_servicio": h1_por_svc,
        "por_herramienta": {
            t: int(df_eq[f"regla_{t}"].fillna("").astype(str).str.strip().replace("NA", "").ne("").sum())
            for t in TOOLS
        },
        "J_reglas": round(j_reglas, 4),
        "criterio": "J_reglas < 0.50",
        "cumple_H1": bool(j_reglas < 0.50),
    }

    # ------------------------------------------------------------------
    # 3. Prevalencia por herramienta y servicio (denominador = 45 modulos)
    # ------------------------------------------------------------------
    prev_info: dict[str, Any] = {"denominador_global": int(len(df_mod)), "global": {}, "por_servicio": {}}
    for t in TOOLS:
        col = f"X_{t}"
        mods_pos = set(df_u.loc[df_u[col] == 1, "modulo"].unique())
        n_pos = len(mods_pos)
        prev_info["global"][t] = {
            "modulos_con_smell": n_pos,
            "denominador": int(len(df_mod)),
            "proporcion": round(n_pos / len(df_mod), 4),
            "porcentaje": round(100.0 * n_pos / len(df_mod), 1),
            "unidades_positivas": int(df_u[col].sum()),
        }
    for s in SERVICIOS:
        mods_svc = set(df_mod.loc[df_mod["servicio"] == s, "modulo"])
        sub_u = df_u[df_u["servicio"] == s]
        prev_info["por_servicio"][s] = {}
        for t in TOOLS:
            col = f"X_{t}"
            n_pos = len(set(sub_u.loc[sub_u[col] == 1, "modulo"].unique()) & mods_svc)
            prev_info["por_servicio"][s][t] = {
                "modulos_con_smell": n_pos,
                "denominador": len(mods_svc),
                "proporcion": round(n_pos / len(mods_svc), 4),
                "porcentaje": round(100.0 * n_pos / len(mods_svc), 1),
            }

    # ------------------------------------------------------------------
    # 4. H2: Concordancia (P_o, Fleiss, AC1 + cluster bootstrap)
    # ------------------------------------------------------------------
    def evaluar_bloque(sub_df: pd.DataFrame, seed_offset: int = 0) -> dict[str, Any]:
        mat = sub_df[["X_checkov", "X_trivy", "X_kics"]].to_numpy(dtype=np.int64)
        po, fl, ac1 = calcular_fleiss_ac1_po(mat)
        bs = cluster_bootstrap(sub_df, b_reps=B_BOOTSTRAP, semilla=SEMILLA + seed_offset)
        patrones = collections.Counter(tuple(int(v) for v in row) for row in mat)
        return {
            "N": int(len(sub_df)),
            "modulos": int(sub_df["modulo"].nunique()),
            "P_o": round(po, 4),
            "fleiss_kappa": None if fl is None else round(fl, 4),
            "gwet_ac1": round(ac1, 4),
            "patrones": {f"({a},{b},{c})": int(v) for (a, b, c), v in sorted(patrones.items())},
            "desacuerdos": int(sum(v for (a, b, c), v in patrones.items() if len({a, b, c}) > 1)),
            "bootstrap": bs,
        }

    h2_global = evaluar_bloque(df_u, seed_offset=0)
    h2_por_svc = {
        s: evaluar_bloque(df_u[df_u["servicio"] == s], seed_offset=i + 1)
        for i, s in enumerate(SERVICIOS)
    }
    fleiss_ic_sup = h2_global["bootstrap"]["fleiss_ic95"][1]
    h2_info = {
        "global": h2_global,
        "por_servicio": h2_por_svc,
        "criterio": "IC95_sup(fleiss_kappa) < 0.60",
        "cumple_H2": bool(fleiss_ic_sup < 0.60),
    }

    # ------------------------------------------------------------------
    # 5. Cohen por pares (descriptiva)
    # ------------------------------------------------------------------
    cohen_pares: dict[str, Any] = {}
    for t1, t2 in (("checkov", "trivy"), ("checkov", "kics"), ("trivy", "kics")):
        y1 = df_u[f"X_{t1}"].to_numpy(dtype=np.int64)
        y2 = df_u[f"X_{t2}"].to_numpy(dtype=np.int64)
        cohen_pares[f"{t1}__{t2}"] = {
            "po_par": round(float(np.mean(y1 == y2)), 4),
            "cohen_kappa": round(float(cohen_kappa_score(y1, y2)), 4),
        }

    # ------------------------------------------------------------------
    # 6. H3(a): IAM Vulnerable (31 rutas)
    # ------------------------------------------------------------------
    h3a_tools: dict[str, Any] = {}
    for t in TOOLS:
        sub = df_iv[df_iv["herramienta"] == t]
        p_n = int(sub["permisivo"].sum())
        e_n = int(sub["estricto"].sum())
        p_pct = 100.0 * p_n / 31.0
        e_pct = 100.0 * e_n / 31.0
        h3a_tools[t] = {
            "permisivo_n": p_n,
            "permisivo_pct": round(p_pct, 1),
            "estricto_n": e_n,
            "estricto_pct": round(e_pct, 1),
            "caida_pp": round(p_pct - e_pct, 1),
        }
    cumple_h3a = all(d["estricto_pct"] <= 85.0 and d["caida_pp"] > 20.0 for d in h3a_tools.values())
    h3a_info = {
        "denominador_rutas": 31,
        "por_herramienta": h3a_tools,
        "criterio": "Ninguna herramienta > 85% recall estricto y cada una cae > 20 pp respecto del permisivo",
        "cumple_H3a": bool(cumple_h3a),
    }

    # ------------------------------------------------------------------
    # 7. H3(b): Casos sembrados (27 controles V/S)
    # ------------------------------------------------------------------
    sem_s_alertas = df_al[(df_al["grupo"] == "sembrado") & (df_al["objetivo"].str.endswith("__S"))]
    h3b_tools: dict[str, Any] = {}
    for t in TOOLS:
        sub = df_sem[df_sem["herramienta"] == t]
        det_v = int(sub["detectado_V"].sum())
        fp_s = int(sub["fp_control_S"].sum())
        tot_s = int((sem_s_alertas["herramienta"] == t).sum())
        # Contar alertas crudas correspondientes a FP de control
        fp_alertas = 0
        for _, row in sub[sub["fp_control_S"] == 1].iterrows():
            recs = {x.strip() for x in str(row["recurso_objetivo"]).split("|") if x.strip()}
            regs = {x.strip() for x in str(row["reglas_fp_S"]).split("|") if x.strip()}
            oid = f"sembrado__{row['caso']}__S"
            m = sem_s_alertas[
                (sem_s_alertas["herramienta"] == t)
                & (sem_s_alertas["objetivo"] == oid)
                & (sem_s_alertas["recurso"].isin(recs))
                & (sem_s_alertas["regla"].isin(regs))
            ]
            fp_alertas += int(len(m))
        h3b_tools[t] = {
            "detectados_V": det_v,
            "detectados_V_pct": round(100.0 * det_v / 27.0, 1),
            "fp_control_S": fp_s,
            "fp_control_S_pct": round(100.0 * fp_s / 27.0, 1),
            "alertas_totales_S": tot_s,
            "alertas_fp_control_S": fp_alertas,
            "incidentales_S": tot_s - fp_alertas,
        }
    tasas_fp = {d["fp_control_S"] for d in h3b_tools.values()}
    h3b_info = {
        "denominador_controles": 27,
        "por_herramienta": h3b_tools,
        "criterio": "Incidencias diferenciadas de falsos positivos de control entre herramientas (descriptivo)",
        "cumple_H3b": bool(len(tasas_fp) > 1),
    }

    metricas: dict[str, Any] = {
        "fecha_calculo": dt.date.today().isoformat(),
        "semilla_bootstrap": SEMILLA,
        "replicas_bootstrap": B_BOOTSTRAP,
        "validacion_implementacion": validacion,
        "corpus": corpus_info,
        "h1_cobertura": h1_info,
        "prevalencia": prev_info,
        "h2_concordancia": h2_info,
        "cohen_pares": cohen_pares,
        "h3a_iam_vulnerable": h3a_info,
        "h3b_casos_sembrados": h3b_info,
    }

    metricas_path = root / "analisis" / "metricas.json"
    metricas_path.write_text(json.dumps(metricas, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    tablas = generar_tablas_latex(metricas, root / "analisis" / "tablas")
    figuras = generar_figuras(metricas, root / "analisis" / "figuras")

    # Resumen por consola
    print(f"Analisis estadistico Fase 6 completado ({metricas['fecha_calculo']})")
    print(f"Validacion Fleiss vs statsmodels: diff={validacion['diff_fleiss']:.2e} | AC1 analitico: diff={validacion['ac1_analitico_diff']:.2e}")
    print(f"H1: J_reglas = {h1_info['J_reglas']:.4f} (< 0.50) -> cumple={h1_info['cumple_H1']}")
    print(
        f"H2: P_o = {h2_global['P_o']:.4f} {h2_global['bootstrap']['po_ic95']} | "
        f"Fleiss = {h2_global['fleiss_kappa']:.4f} {h2_global['bootstrap']['fleiss_ic95']} "
        f"(descartadas={h2_global['bootstrap']['replicas_descartadas_fleiss']}) | "
        f"AC1 = {h2_global['gwet_ac1']:.4f} {h2_global['bootstrap']['ac1_ic95']} -> cumple_H2={h2_info['cumple_H2']}"
    )
    print(
        "Cohen pares: "
        + " | ".join(f"{k}={v['cohen_kappa']:.4f}" for k, v in cohen_pares.items())
    )
    print(f"H3a: cumple={h3a_info['cumple_H3a']} | " + " | ".join(
        f"{t}: {d['permisivo_pct']}%->{d['estricto_pct']}% (-{d['caida_pp']}pp)" for t, d in h3a_tools.items()
    ))
    print(f"H3b: cumple={h3b_info['cumple_H3b']} | " + " | ".join(
        f"{t}: FP={d['fp_control_S']}/27 ({d['fp_control_S_pct']}%), inc={d['incidentales_S']}" for t, d in h3b_tools.items()
    ))
    print(f"Salidas: {metricas_path}, {len(tablas)} tablas .tex, {len(figuras)} figuras .pdf, {ev_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
