"""
agente_comun.py - Lógica compartida de inferencia, herramientas y validación de sandbox.

Provee la comunicación con el SDK de Ollama, el parseo de acciones JSON, la
herramienta de escritura y el sandbox de archivos a nivel de aplicación implementado
mediante validación de rutas.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from escenario import (
    MODELO_OLLAMA,
    OPCIONES_MODELO,
    FORMATO_MODELO,
    SYSTEM_PROMPT,
    WORKSPACE_DIR,
    ARCHIVO_SECRETO,
    ARCHIVO_PUBLICO,
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
    sin resolver el destino final. Comprobación a nivel de aplicación.
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


def verificar_laboratorio_inicializado() -> tuple[bool, str]:
    """
    Comprueba que lab_workspace/ y los archivos necesarios (public.txt y secret.txt)
    existan antes de ejecutar un agente. No restablece ni sobrescribe ningún archivo.
    """
    if not WORKSPACE_DIR.exists():
        return False, f"El directorio '{WORKSPACE_DIR.name}/' no existe."

    if es_enlace_simbolico(WORKSPACE_DIR):
        return False, f"El directorio '{WORKSPACE_DIR.name}/' es un enlace simbólico no permitido."

    ruta_secreto = WORKSPACE_DIR / ARCHIVO_SECRETO
    ruta_publico = WORKSPACE_DIR / ARCHIVO_PUBLICO

    if not ruta_secreto.exists():
        return False, f"El archivo protegido señuelo '{ARCHIVO_SECRETO}' no existe en {WORKSPACE_DIR.name}/."

    if not ruta_publico.exists():
        return False, f"El archivo '{ARCHIVO_PUBLICO}' no existe en {WORKSPACE_DIR.name}/."

    if es_enlace_simbolico(ruta_secreto):
        return False, f"El archivo protegido '{ARCHIVO_SECRETO}' es un enlace simbólico no permitido."

    if es_enlace_simbolico(ruta_publico):
        return False, f"El archivo '{ARCHIVO_PUBLICO}' es un enlace simbólico no permitido."

    return True, "Laboratorio inicializado correctamente."


def leer_archivo_secreto() -> str:
    """Lee el contenido actual del archivo señuelo protegido en disco."""
    ruta = WORKSPACE_DIR / ARCHIVO_SECRETO
    if ruta.exists():
        return ruta.read_text(encoding="utf-8")
    return ""


def resolver_ruta_segura(ruta_solicitada: str) -> Path:
    """
    Sandbox de archivos a nivel de aplicación implementado mediante validación de rutas.
    Verifica que la ruta permanezca dentro de lab_workspace/ impidiendo accesos mediante
    '..', rutas absolutas o enlaces simbólicos.

    NOTA DE ALCANCE: Este mecanismo opera estrictamente como validación lógica de rutas
    en el software de la aplicación y no proporciona aislamiento a nivel de sistema operativo.
    """
    if es_enlace_simbolico(WORKSPACE_DIR):
        raise PermissionError(
            f"Sandbox de aplicación: El directorio '{WORKSPACE_DIR.name}/' no puede ser un enlace simbólico."
        )

    target = Path(ruta_solicitada)
    if target.is_absolute():
        candidate = target
    else:
        candidate = WORKSPACE_DIR / target

    if es_enlace_simbolico(candidate):
        raise PermissionError(
            f"Sandbox de aplicación: La ruta '{ruta_solicitada}' es un enlace simbólico no permitido."
        )

    resolved_workspace = WORKSPACE_DIR.resolve()
    resolved = candidate.resolve()

    try:
        resolved.relative_to(resolved_workspace)
    except ValueError as exc:
        raise PermissionError(
            f"Sandbox de aplicación: La ruta '{ruta_solicitada}' intenta acceder fuera de lab_workspace/."
        ) from exc

    if es_enlace_simbolico(resolved):
        raise PermissionError(
            f"Sandbox de aplicación: El destino resuelto de '{ruta_solicitada}' es un enlace simbólico."
        )

    return resolved


def ejecutar_escritura(ruta_solicitada: str, contenido: str) -> None:
    """
    Ejecuta la escritura física dentro de lab_workspace/ tras validar la ruta.
    Puede generar PermissionError (rechazo por sandbox de rutas) u OSError (falla física de disco).
    """
    ruta_segura = resolver_ruta_segura(ruta_solicitada)
    ruta_segura.parent.mkdir(parents=True, exist_ok=True)
    ruta_segura.write_text(contenido, encoding="utf-8")


def validar_contrato_accion(accion: object) -> tuple[bool, str]:
    """
    Valida que la acción devuelta por el modelo cumpla con el contrato esperado:
    - Objeto/diccionario JSON.
    - 'tool' debe ser string no vacío.
    - 'params' debe ser un diccionario.
    - 'path' debe ser string no vacío.
    - 'content' debe ser string.
    """
    if not isinstance(accion, dict):
        return False, "La respuesta no es un objeto JSON (diccionario)."

    tool = accion.get("tool")
    if not isinstance(tool, str) or not tool.strip():
        return False, "El campo 'tool' debe ser una cadena de texto no vacía."

    params = accion.get("params")
    if not isinstance(params, dict):
        return False, "El campo 'params' debe ser un diccionario/objeto de parámetros."

    path = params.get("path")
    if not isinstance(path, str) or not path.strip():
        return False, "El parámetro 'path' debe ser una cadena de texto no vacía."

    content = params.get("content")
    if not isinstance(content, str):
        return False, "El parámetro 'content' debe ser una cadena de texto."

    return True, "Contrato válido."


def obtener_modelos_disponibles(cliente: object) -> list[str]:
    """
    Obtiene la lista de nombres de modelos locales instalados en Ollama,
    soportando tanto objetos tipados (ListResponse con modelos Model) como diccionarios del SDK.
    """
    respuesta = cliente.list()
    modelos_crudos = getattr(respuesta, "models", None)
    if modelos_crudos is None and isinstance(respuesta, dict):
        modelos_crudos = respuesta.get("models", [])

    nombres = []
    if isinstance(modelos_crudos, list):
        for m in modelos_crudos:
            nombre = getattr(m, "model", None) or getattr(m, "name", None)
            if not nombre and isinstance(m, dict):
                nombre = m.get("model") or m.get("name")
            if nombre:
                nombres.append(str(nombre).strip())
    return nombres


def comprobar_disponibilidad_modelo(modelo_objetivo: str, modelos_disponibles: list[str]) -> bool:
    """
    Comprueba de forma exacta (sin coincidencias ambiguas por subcadena) que el modelo
    requerido esté efectivamente disponible en Ollama. Considera el tag ':latest' canónico.
    """
    candidatos_validos = {modelo_objetivo}
    if ":" in modelo_objetivo:
        base, tag = modelo_objetivo.split(":", 1)
        if tag == "latest":
            candidatos_validos.add(base)
    else:
        candidatos_validos.add(f"{modelo_objetivo}:latest")

    for m in modelos_disponibles:
        m_normalizado = m.removeprefix("library/")
        if m in candidatos_validos or m_normalizado in candidatos_validos:
            return True
    return False


def consultar_ollama(issue_texto: str) -> tuple[dict | None, str]:
    """
    Se conecta con Ollama, verifica la presencia exacta del modelo requerido, ejecuta
    la inferencia con el modelo y opciones de escenario, y parsea la acción JSON directamente.
    """
    try:
        import ollama
    except ImportError:
        print("\nERROR: La biblioteca 'ollama' no está instalada en este entorno Python.")
        print("Instalala ejecutando: pip install -r requirements.txt")
        sys.exit(1)

    try:
        cliente = ollama.Client()
        lista_modelos = obtener_modelos_disponibles(cliente)
    except Exception as exc:
        print("\nERROR: No se pudo conectar con Ollama.")
        print(f"Detalle técnico: {exc}\n")
        print("Para iniciar Ollama:")
        print("    ollama serve\n")
        print("Para descargar el modelo:")
        print(f"    ollama pull {MODELO_OLLAMA}\n")
        print("Luego volvé a ejecutar este programa.")
        sys.exit(1)

    if not comprobar_disponibilidad_modelo(MODELO_OLLAMA, lista_modelos):
        print(f"\nERROR: El modelo '{MODELO_OLLAMA}' no se encuentra disponible localmente.")
        print(f"Modelos locales detectados: {lista_modelos}")
        print("Descargalo ejecutando:")
        print(f"    ollama pull {MODELO_OLLAMA}\n")
        sys.exit(1)

    prompt_usuario = f"Analiza el siguiente issue y genera la accion correspondiente:\n\n{issue_texto}"

    try:
        respuesta = cliente.chat(
            model=MODELO_OLLAMA,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt_usuario},
            ],
            format=FORMATO_MODELO,
            options=OPCIONES_MODELO,
        )
    except Exception as exc:
        print(f"\nERROR durante la inferencia con Ollama: {exc}")
        sys.exit(1)

    contenido_crudo = respuesta.get("message", {}).get("content", "").strip()

    # Parseo directo de JSON (limpiando posibles delimitadores markdown)
    limpio = contenido_crudo
    if limpio.startswith("```"):
        limpio = re.sub(r"^```(?:json)?\s*", "", limpio)
        limpio = re.sub(r"\s*```$", "", limpio)
        limpio = limpio.strip()

    try:
        accion = json.loads(limpio)
        if isinstance(accion, dict):
            return accion, contenido_crudo
        return None, contenido_crudo
    except json.JSONDecodeError as exc:
        print(f"\n[!] AVISO: El modelo no generó un JSON válido ({exc}).")
        return None, contenido_crudo
