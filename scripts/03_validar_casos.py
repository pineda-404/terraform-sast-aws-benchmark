#!/usr/bin/env python3
"""Fase 2: valida sintacticamente todas las variantes V/S de casos sembrados con terraform validate."""

from __future__ import annotations

import datetime as dt
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    casos_dir = root / "casos_sembrados"
    evidencia_dir = root / "evidencia"
    evidencia_dir.mkdir(parents=True, exist_ok=True)

    variantes = sorted(
        p for p in list(casos_dir.glob("caso_*/V")) + list(casos_dir.glob("caso_*/S")) if p.is_dir()
    )
    if not variantes:
        print("Error: no se encontraron variantes V/S en casos_sembrados/")
        return 1

    fecha = dt.date.today().isoformat()
    log_path = evidencia_dir / f"{fecha}_terraform_validate_casos.txt"
    lineas: list[str] = []
    ok_count = 0

    with tempfile.TemporaryDirectory(prefix="tf_plugin_cache_") as cache_dir:
        env = os.environ.copy()
        env["TF_PLUGIN_CACHE_DIR"] = cache_dir

        for vdir in variantes:
            rel = vdir.relative_to(root)
            lineas.append(f"=== {rel} ===")

            init_res = subprocess.run(
                ["terraform", f"-chdir={vdir}", "init", "-backend=false", "-input=false", "-no-color"],
                capture_output=True,
                text=True,
                env=env,
            )
            if init_res.returncode != 0:
                lineas.append(f"[ERROR init] {init_res.stderr.strip()}")
                print(f"FAIL init: {rel}")
                continue

            val_res = subprocess.run(
                ["terraform", f"-chdir={vdir}", "validate", "-no-color"],
                capture_output=True,
                text=True,
                env=env,
            )
            salida = (val_res.stdout + val_res.stderr).strip()
            lineas.append(salida)
            if val_res.returncode == 0:
                ok_count += 1
                print(f"OK   {rel}")
            else:
                print(f"FAIL {rel}: {salida}")

            shutil.rmtree(vdir / ".terraform", ignore_errors=True)
            lock = vdir / ".terraform.lock.hcl"
            if lock.exists():
                lock.unlink()

    resumen = f"Resumen: {ok_count}/{len(variantes)} variantes validas"
    lineas.append(resumen)
    log_path.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    print(resumen)
    print(f"Evidencia guardada en: {log_path}")
    return 0 if ok_count == len(variantes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
