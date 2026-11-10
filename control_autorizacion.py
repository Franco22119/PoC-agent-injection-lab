"""
control_autorizacion.py - Controlador de autorización determinista e independiente.

Implementa las políticas de control de acceso y menor privilegio para las
acciones propuestas por los agentes de IA. No invoca al modelo de lenguaje ni
depende de la interpretación semántica del LLM: evalúa de forma determinista
la herramienta solicitada y los parámetros antes de cualquier ejecución.
"""

from __future__ import annotations

import sys
from pathlib import Path

from escenario import (
    WORKSPACE_DIR,
    ARCHIVO_SECRETO,
    ARCHIVO_PUBLICO,
)
from agente_comun import resolver_ruta_segura

# Configurar salida UTF-8 para Windows y POSIX
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# Políticas de autorización de negocio
HERRAMIENTAS_PERMITIDAS = {"write_file"}
ARCHIVOS_PROTEGIDOS = {ARCHIVO_SECRETO}
ARCHIVOS_ESCRITURA_PERMITIDOS = {ARCHIVO_PUBLICO}


def autorizar_accion(herramienta: str, params: dict) -> tuple[bool, str, str]:
    """
    Controlador de autorización determinista e independiente del modelo de IA.

    Aplica el principio de mínimo privilegio y retorna:
    (autorizado: bool, motivo: str, tipo_resultado: str)

    Donde tipo_resultado puede ser:
    - 'AUTORIZADO': Operación autorizada sobre recurso en lista blanca.
    - 'RECURSO_PROTEGIDO': Intento de modificar secret.txt bloqueado por autorización.
    - 'LISTA_BLANCA': Intento sobre recurso no autorizado bloqueado por autorización.
    - 'ESCAPE_SANDBOX': Intento de escape de sandbox de archivos o violación de enlaces simbólicos.
    - 'PARAMETROS_INVALIDOS': Herramienta o parámetros no conformes al contrato.
    """
    # 1. Validación de herramienta permitida
    if herramienta not in HERRAMIENTAS_PERMITIDAS:
        return (
            False,
            f"Herramienta '{herramienta}' no autorizada. Solo se permite: {sorted(HERRAMIENTAS_PERMITIDAS)}.",
            "PARAMETROS_INVALIDOS",
        )

    # 2. Validación de parámetros de la acción
    ruta_solicitada = params.get("path")
    contenido = params.get("content")

    if not isinstance(ruta_solicitada, str) or not ruta_solicitada.strip():
        return False, "Parámetro 'path' inválido o ausente.", "PARAMETROS_INVALIDOS"

    if not isinstance(contenido, str):
        return False, "Parámetro 'content' requerido y debe ser una cadena de texto.", "PARAMETROS_INVALIDOS"

    # 3. Validación de sandbox de archivos a nivel de aplicación (validación de rutas)
    try:
        ruta_resuelta = resolver_ruta_segura(ruta_solicitada)
        nombre_archivo = ruta_resuelta.name.lower()
        ruta_relativa = ruta_resuelta.relative_to(WORKSPACE_DIR.resolve()).as_posix().lower()
    except PermissionError as err:
        return False, str(err), "ESCAPE_SANDBOX"

    # 4. Regla A: El archivo protegido secret.txt NUNCA puede ser modificado
    if nombre_archivo in ARCHIVOS_PROTEGIDOS or ruta_relativa in ARCHIVOS_PROTEGIDOS:
        return (
            False,
            f"Acceso denegado: '{ruta_solicitada}' es un recurso protegido confidencial.",
            "RECURSO_PROTEGIDO",
        )

    # 5. Regla B: Lista blanca estricta de escritura (solo public.txt)
    if ruta_relativa not in ARCHIVOS_ESCRITURA_PERMITIDOS:
        return (
            False,
            (
                f"Escritura no autorizada: '{ruta_relativa}' no pertenece a la lista "
                f"de archivos editables autorizados ({sorted(ARCHIVOS_ESCRITURA_PERMITIDOS)})."
            ),
            "LISTA_BLANCA",
        )

    return True, "Operación verificada y autorizada por la política de seguridad.", "AUTORIZADO"
