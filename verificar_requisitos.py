"""
verificar_requisitos.py - Verificación de precondiciones y entorno para la PoC.

Verifica de forma no destructiva:
1. Versión de Python compatible (>= 3.10).
2. Instalación de la biblioteca cliente 'ollama'.
3. Conectividad con el servicio local de Ollama (daemon activo).
4. Disponibilidad exacta del modelo 'llama3.2:latest' (soporte de ListResponse tipado del SDK).

No ejecuta inferencias sobre el modelo ni altera el espacio de trabajo del laboratorio.
Retorna código de salida 0 si todos los requisitos se cumplen, o 1 en caso contrario.
"""

from __future__ import annotations

import sys
from escenario import MODELO_OLLAMA
from agente_comun import obtener_modelos_disponibles, comprobar_disponibilidad_modelo

# Configurar salida UTF-8 para Windows y POSIX
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass


def verificar_entorno() -> bool:
    print("=" * 70)
    print(" VERIFICACIÓN DE REQUISITOS DEL SISTEMA Y DEPENDENCIAS")
    print("=" * 70)

    todos_ok = True

    # 1. Versión de Python
    version_actual = sys.version_info
    print(f"\n[1/4] Verificando versión de Python...")
    if version_actual >= (3, 10):
        print(f"  [OK] Python {version_actual.major}.{version_actual.minor}.{version_actual.micro} detectado (>= 3.10 requerido).")
    else:
        print(f"  [ERROR] Se requiere Python 3.10 o superior. Versión actual: {sys.version.split()[0]}.")
        todos_ok = False

    # 2. Biblioteca cliente de Ollama
    print(f"\n[2/4] Verificando biblioteca 'ollama' en el entorno Python...")
    ollama_modulo = None
    try:
        import ollama
        ollama_modulo = ollama
        print("  [OK] Paquete 'ollama' importado correctamente.")
    except ImportError:
        print("  [ERROR] Paquete 'ollama' no encontrado.")
        print("    Solución: pip install -r requirements.txt")
        todos_ok = False

    # 3. Servicio Ollama activo
    print(f"\n[3/4] Verificando conectividad con el servicio local de Ollama...")
    cliente_ollama = None
    modelos_disponibles = []
    if ollama_modulo is not None:
        try:
            cliente_ollama = ollama_modulo.Client()
            modelos_disponibles = obtener_modelos_disponibles(cliente_ollama)
            print(f"  [OK] Conexión establecida con el servicio de Ollama.")
            print(f"       Modelos locales detectados: {len(modelos_disponibles)} ({', '.join(modelos_disponibles) if modelos_disponibles else 'ninguno'})")
        except Exception as exc:
            print(f"  [ERROR] No fue posible comunicarse con el daemon de Ollama.")
            print(f"          Detalle: {exc}")
            print("    Solución: Asegurate de iniciar el servicio ejecutando en una terminal:")
            print("              ollama serve")
            todos_ok = False
    else:
        print("  [OMITIDO] Se requiere instalar la biblioteca 'ollama' para probar la conexión.")
        todos_ok = False

    # 4. Modelo requerido disponible
    print(f"\n[4/4] Verificando disponibilidad exacta del modelo '{MODELO_OLLAMA}'...")
    if cliente_ollama is not None:
        modelo_encontrado = comprobar_disponibilidad_modelo(MODELO_OLLAMA, modelos_disponibles)
        if modelo_encontrado:
            print(f"  [OK] Modelo '{MODELO_OLLAMA}' disponible localmente en Ollama.")
        else:
            print(f"  [ERROR] El modelo '{MODELO_OLLAMA}' no se encuentra descargado.")
            print("    Solución: Descargalo ejecutando en tu terminal:")
            print(f"              ollama pull {MODELO_OLLAMA}")
            todos_ok = False
    else:
        print(f"  [OMITIDO] No se pudo comprobar el modelo por falta de conexión.")
        todos_ok = False

    print("\n" + "=" * 70)
    if todos_ok:
        print(" ESTADO GENERAL: TODOS LOS REQUISITOS ESTÁN SATISFECHOS [OK]")
        print(" Para ejecutar los experimentos:")
        print("   1. python preparar_laboratorio.py  (paso manual si aún no preparaste lab_workspace/)")
        print("   2. python inseguro.py")
        print("   3. python seguro.py")
    else:
        print(" ESTADO GENERAL: SE DETECTARON PRECONDICIONES FALTANTES [ERROR]")
        print(" Revisá las soluciones indicadas arriba antes de ejecutar los experimentos.")
    print("=" * 70)

    return todos_ok


if __name__ == "__main__":
    exito = verificar_entorno()
    sys.exit(0 if exito else 1)
