#!/usr/bin/env python3
"""Fases 4 y 5: ejecuta Checkov, Trivy y KICS en Docker con versiones fijadas por digest.

- Excluye de forma homogenea examples/, example/, tests/, test/, .git/ y .terraform/
  montando una copia temporal de solo lectura (/src:ro) identica para los tres escaneres.
- Fija la cache de Trivy en `.trivy/` usando el digest exacto de `checks_bundle` en
  `config/versiones.yaml` y `--skip-check-update` en las corridas posteriores.
- Uso:
    uv run python scripts/05_escanear.py --modo piloto
    uv run python scripts/05_escanear.py --modo completo
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml

EXCLUIR_DIRS = {"examples", "example", "tests", "test", ".git", ".terraform"}

PILOTO_MODULOS = [
    "unfunco__oidc-github",
    "terraform-aws-modules__s3-bucket",
    "terraform-aws-modules__security-group",
    "clouddrove__vpc",
]

PILOTO_PRIVESC = [
    "privesc1-CreateNewPolicyVersion.tf",
    "privesc7-AttachUserPolicy.tf",
    "privesc12-PutRolePolicy.tf",
    "privesc15-PassExistingRoleToNewLambdaThenInvoke.tf",
]

PILOTO_CASOS = [
    ("caso_05_vpc_sg_ipv4_puertos", "V"),
    ("caso_05_vpc_sg_ipv4_puertos", "S"),
]


def cargar_versiones(root: Path) -> dict[str, Any]:
    return yaml.safe_load((root / "config" / "versiones.yaml").read_text(encoding="utf-8"))


def verificar_docker() -> None:
    res = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if res.returncode != 0:
        err = (res.stderr or res.stdout).strip().splitlines()[0] if (res.stderr or res.stdout) else "sin detalle"
        raise RuntimeError(
            f"No se pudo conectar al daemon de Docker ({err}).\n"
            "Si recien te agregaste al grupo docker, ejecuta en tu terminal con `sg docker`:\n"
            '  sg docker -c "uv run python scripts/05_escanear.py --modo piloto"'
        )


def stage_dir(origen: Path, destino: Path, solo_archivos: list[str] | None = None) -> int:
    """Copia unicamente los archivos .tf/.tf.json del modulo raiz a un directorio limpio.

    Esto excluye de forma homogenea examples/, example/, tests/, test/, _test/,
    wrappers/, generate/ y submodulos auxiliares, alineandose con el modulo raiz
    publicado en el Terraform Registry (seleccion de Fase 1).
    """
    destino.mkdir(parents=True, exist_ok=True)
    copiados = 0
    if solo_archivos is not None:
        for nombre in solo_archivos:
            src = origen / nombre
            if src.exists():
                shutil.copy2(src, destino / nombre)
                copiados += 1
        return copiados

    for src in sorted(origen.iterdir()):
        if src.is_file() and (src.suffix == ".tf" or src.name.endswith(".tf.json")):
            shutil.copy2(src, destino / src.name)
            copiados += 1
    return copiados


def validar_json(path: Path) -> tuple[bool, str]:
    if not path.exists() or path.stat().st_size == 0:
        return False, "archivo ausente o vacio"
    try:
        json.loads(path.read_text(encoding="utf-8"))
        return True, "ok"
    except Exception as exc:
        return False, f"JSON invalido: {exc}"


def preparar_cache_trivy(root: Path, trivy_img: str, bundle_digest: str, uid_gid: str) -> None:
    cache_dir = root / ".trivy"
    cache_dir.mkdir(parents=True, exist_ok=True)
    marcador = cache_dir / ".bundle_digest"
    if marcador.exists() and marcador.read_text(encoding="utf-8").strip() == bundle_digest:
        return

    print(f"Descargando bundle fijado de Trivy en .trivy/ ({bundle_digest})...")
    with tempfile.TemporaryDirectory(prefix="trivy_warm_") as tmp:
        (Path(tmp) / "dummy.tf").write_text('terraform { required_version = ">= 1.0" }\n', encoding="utf-8")
        cmd = [
            "docker", "run", "--rm",
            "-u", uid_gid,
            "-e", "HOME=/tmp",
            "-v", f"{tmp}:/src:ro",
            "-v", f"{cache_dir}:/cache",
            trivy_img,
            "config",
            "--misconfig-scanners", "terraform",
            "--cache-dir", "/cache",
            "--checks-bundle-repository", bundle_digest,
            "--format", "json",
            "--quiet",
            "/src",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode not in (0, 1):
            raise RuntimeError(f"Error preparando cache Trivy: {res.stderr.strip()}")
    marcador.write_text(bundle_digest + "\n", encoding="utf-8")


def correr_checkov(img: str, src_dir: Path, out_json: Path) -> tuple[bool, float, str]:
    t0 = time.monotonic()
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{src_dir}:/src:ro",
        img,
        "-d", "/src",
        "--framework", "terraform",
        "-o", "json",
        "--quiet",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    dt_s = time.monotonic() - t0
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(res.stdout, encoding="utf-8")
    ok, msg = validar_json(out_json)
    if not ok and res.stderr:
        msg = f"{msg} | stderr={res.stderr.strip()[:200]}"
    return ok, dt_s, msg


def correr_trivy(img: str, src_dir: Path, out_json: Path, cache_dir: Path, uid_gid: str) -> tuple[bool, float, str]:
    t0 = time.monotonic()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "docker", "run", "--rm",
        "-u", uid_gid,
        "-e", "HOME=/tmp",
        "-v", f"{src_dir}:/src:ro",
        "-v", f"{out_json.parent}:/out",
        "-v", f"{cache_dir}:/cache",
        img,
        "config",
        "--misconfig-scanners", "terraform",
        "--cache-dir", "/cache",
        "--skip-check-update",
        "--format", "json",
        "--output", f"/out/{out_json.name}",
        "--quiet",
        "/src",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    dt_s = time.monotonic() - t0
    ok, msg = validar_json(out_json)
    if not ok and res.stderr:
        msg = f"{msg} | stderr={res.stderr.strip()[:200]}"
    return ok, dt_s, msg


def correr_kics(img: str, src_dir: Path, out_json: Path, uid_gid: str) -> tuple[bool, float, str]:
    t0 = time.monotonic()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    stem = out_json.stem
    cmd = [
        "docker", "run", "--rm",
        "-u", uid_gid,
        "-e", "HOME=/tmp",
        "-v", f"{src_dir}:/src:ro",
        "-v", f"{out_json.parent}:/out",
        img,
        "scan",
        "-p", "/src",
        "-t", "Terraform",
        "-o", "/out",
        "--output-name", stem,
        "--report-formats", "json",
        "--no-progress",
        "--silent",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    dt_s = time.monotonic() - t0
    ok, msg = validar_json(out_json)
    if not ok and res.stderr:
        msg = f"{msg} | stderr={res.stderr.strip()[:200]}"
    return ok, dt_s, msg


def construir_objetivos(root: Path, modo: str) -> list[dict[str, Any]]:
    objetivos: list[dict[str, Any]] = []
    if modo == "piloto":
        for mid in PILOTO_MODULOS:
            objetivos.append({
                "grupo": "corpus",
                "id": f"corpus__{mid}",
                "origen": root / "corpus" / "descargados" / mid,
                "solo_archivos": None,
            })
        for caso, var in PILOTO_CASOS:
            objetivos.append({
                "grupo": "sembrado",
                "id": f"sembrado__{caso}__{var}",
                "origen": root / "casos_sembrados" / caso / var,
                "solo_archivos": None,
            })
        objetivos.append({
            "grupo": "iam_vulnerable",
            "id": "iam_vulnerable__piloto_4rutas",
            "origen": root / "iam_vulnerable" / "repo" / "modules" / "free-resources" / "privesc-paths",
            "solo_archivos": ["variables.tf", "sre.tf", "service-linked-role-common.tf", *PILOTO_PRIVESC],
        })
        return objetivos

    # Modo completo (Fase 5)
    with (root / "corpus" / "modulos.csv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            mid = f"{row['namespace']}__{row['nombre']}"
            objetivos.append({
                "grupo": "corpus",
                "id": f"corpus__{mid}",
                "origen": root / "corpus" / "descargados" / mid,
                "solo_archivos": None,
            })
    for vdir in sorted((root / "casos_sembrados").glob("caso_*/*")):
        if vdir.is_dir() and vdir.name in ("V", "S"):
            objetivos.append({
                "grupo": "sembrado",
                "id": f"sembrado__{vdir.parent.name}__{vdir.name}",
                "origen": vdir,
                "solo_archivos": None,
            })
    objetivos.append({
        "grupo": "iam_vulnerable",
        "id": "iam_vulnerable__todas_31rutas",
        "origen": root / "iam_vulnerable" / "repo" / "modules" / "free-resources" / "privesc-paths",
        "solo_archivos": None,
    })
    return objetivos


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--modo", choices=("piloto", "completo"), default="piloto")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    ver = cargar_versiones(root)["herramientas"]
    ck_img = ver["checkov"]["digest"]
    tr_img = ver["trivy"]["digest"]
    tr_bundle = ver["trivy"]["checks_bundle"]["digest"]
    kc_img = ver["kics"]["digest"]

    uid_gid = f"{os.getuid()}:{os.getgid()}"
    verificar_docker()
    cache_trivy = root / ".trivy"
    preparar_cache_trivy(root, tr_img, tr_bundle, uid_gid)

    crudos_base = root / "resultados" / "crudos" / args.modo
    objetivos = construir_objetivos(root, args.modo)
    print(f"Iniciando escaneo modo={args.modo} sobre {len(objetivos)} objetivos...")

    tiempos: list[dict[str, Any]] = []
    fallos = 0

    for idx, obj in enumerate(objetivos, start=1):
        oid = obj["id"]
        origen: Path = obj["origen"]
        if not origen.exists():
            print(f"[ERROR] No existe {origen}", file=sys.stderr)
            fallos += 1
            continue

        with tempfile.TemporaryDirectory(prefix=f"stage_{oid[:20]}_") as tmp:
            stage = Path(tmp) / "src"
            n_tf = stage_dir(origen, stage, obj["solo_archivos"])
            print(f"[{idx}/{len(objetivos)}] {oid} ({n_tf} archivos .tf)")

            for tool, fn in (
                ("checkov", lambda p: correr_checkov(ck_img, stage, p)),
                ("trivy", lambda p: correr_trivy(tr_img, stage, p, cache_trivy, uid_gid)),
                ("kics", lambda p: correr_kics(kc_img, stage, p, uid_gid)),
            ):
                out_json = crudos_base / tool / f"{oid}.json"
                ok, secs, msg = fn(out_json)
                estado = "OK" if ok else "FAIL"
                if not ok:
                    fallos += 1
                print(f"    {tool:7}: {estado:4} ({secs:5.1f}s) {'' if ok else msg}")
                tiempos.append({
                    "modo": args.modo,
                    "grupo": obj["grupo"],
                    "objetivo": oid,
                    "archivos_tf": n_tf,
                    "herramienta": tool,
                    "ok": int(ok),
                    "segundos": round(secs, 2),
                    "detalle": msg,
                })

    tiempos_csv = crudos_base / f"tiempos_{args.modo}.csv"
    tiempos_csv.parent.mkdir(parents=True, exist_ok=True)
    with tiempos_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["modo", "grupo", "objetivo", "archivos_tf", "herramienta", "ok", "segundos", "detalle"])
        w.writeheader()
        w.writerows(tiempos)

    print(f"\nEscaneo {args.modo} finalizado. Fallos: {fallos}. Tiempos en {tiempos_csv}")
    return 0 if fallos == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
