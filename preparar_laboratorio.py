"""
preparar_laboratorio.py - Inicialización y restablecimiento manual del espacio de trabajo.

Herramienta independiente que prepara el directorio lab_workspace/ y los archivos
necesarios (public.txt y secret.txt) con sus contenidos de referencia para la PoC.
Se ejecuta de forma manual; los agentes no restablecen los archivos automáticamente.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from escenario import (
    WORKSPACE_DIR,
    ARCHIVO_SECRETO,
    ARCHIVO_PUBLICO,
    CONTENIDO_SECRETO_ORIGINAL,
    CONTENIDO_PUBLICO_ORIGINAL,
)

# Configurar salida UTF-8 para Windows y POSIX
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass


def es_enlace_simbolico(ruta: Path) -> bool:
    """
    Verifica si una ruta es un enlace simbólico o un reparse point (junction en Windows),
    sin resolver el destino final. Validación a nivel de aplicación.
    """
    if ruta.is_symlink():
        return True
    try:
        st = os.lstat(ruta)
        # FILE_ATTRIBUTE_REPARSE_POINT (0x400) en Windows identifica symlinks y junctions
        if getattr(st, "st_file_attributes", 0) & 0x400:
            return True
    except (OSError, ValueError):
        pass
    return False


def preparar_laboratorio(imprimir_detalles: bool = False) -> None:
    """
    Crea y restablece el espacio de trabajo sintético.
    Verifica a nivel de aplicación que ni el directorio ni los archivos señuelo
    sean enlaces simbólicos o reparse points.
    """
    if es_enlace_simbolico(WORKSPACE_DIR):
        raise PermissionError(
            f"Sandbox de aplicación: El directorio '{WORKSPACE_DIR.name}/' no puede ser un enlace simbólico."
        )

    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

    ruta_secreto = WORKSPACE_DIR / ARCHIVO_SECRETO
    ruta_publico = WORKSPACE_DIR / ARCHIVO_PUBLICO

    if es_enlace_simbolico(ruta_secreto):
        raise PermissionError(
            f"Sandbox de aplicación: El archivo protegido '{ARCHIVO_SECRETO}' no puede ser un enlace simbólico."
        )
    if es_enlace_simbolico(ruta_publico):
        raise PermissionError(
            f"Sandbox de aplicación: El archivo '{ARCHIVO_PUBLICO}' no puede ser un enlace simbólico."
        )

    ruta_secreto.write_text(CONTENIDO_SECRETO_ORIGINAL, encoding="utf-8")
    ruta_publico.write_text(CONTENIDO_PUBLICO_ORIGINAL, encoding="utf-8")

    if imprimir_detalles:
        print(f"[OK] Espacio de trabajo preparado en: {WORKSPACE_DIR}")
        print(f"  - Creado: {ARCHIVO_PUBLICO} ({len(CONTENIDO_PUBLICO_ORIGINAL)} bytes)")
        print(f"  - Creado: {ARCHIVO_SECRETO} ({len(CONTENIDO_SECRETO_ORIGINAL)} bytes)")


if __name__ == "__main__":
    print("=" * 70)
    print(" PREPARACIÓN DEL ESPACIO DE TRABAJO (lab_workspace)")
    print("=" * 70)
    try:
        preparar_laboratorio(imprimir_detalles=True)
        print("El laboratorio está listo para la ejecución de la PoC.")
    except PermissionError as err:
        print(f"[ERROR DE SANDBOX] {err}")
        sys.exit(1)
    print("=" * 70)
