# agent-injection-lab

Prueba de concepto (PoC) académica que demuestra una vulnerabilidad de **Prompt Injection Indirecta** en agentes de Inteligencia Artificial conectados a herramientas, y su mitigación efectiva mediante un **controlador de autorización determinista e independiente del modelo**.

---

## Disclaimer

Este trabajo es un proyecto académico para la materia **TALLER DE SEGURIDAD INFORMÁTICA / CIBERSEGURIDAD DE REDES E INFRAESTRUCTURAS CRÍTICAS** en el período de cursada segundo cuatrimestre 2026, organizado y propuesto por el **Grupo 4** (FIUBA).

---

## 1. Estructura del Repositorio

El laboratorio implementa una arquitectura modular con estricta separación de responsabilidades:

| Archivo | Responsabilidad |
|---|---|
| `escenario.py` | Prompt del sistema, issue que contiene la inyección y configuración compartida del modelo. |
| `agente_comun.py` | Lógica compartida por ambas variantes: interacción con Ollama, procesamiento de respuestas JSON, sandbox de rutas y ejecución común. No contiene autorización de negocio. |
| `control_autorizacion.py` | Definición de `autorizar_accion(herramienta, params)` y reglas independientes de autorización de negocio (mínimo privilegio y lista blanca). |
| `inseguro.py` | Ejecución de la variante vulnerable: ejecuta la acción propuesta por el modelo sin autorización de negocio. |
| `seguro.py` | Ejecución de la variante protegida: incorpora el control de autorización antes de cualquier escritura. |
| `preparar_laboratorio.py` | Preparación e inicialización manual del espacio de trabajo sintético. |
| `verificar_requisitos.py` | Comprobación no destructiva de dependencias, versión de Python y disponibilidad del servicio y modelo de Ollama. |
| `lab_workspace/` | Espacio de trabajo sintético del laboratorio (creado dinámicamente, ignorado en Git) con `public.txt` y `secret.txt`. |
| `requirements.txt` | Dependencia mínima (`ollama>=0.4.0`). |
| `README.md` | Guía de instalación, uso y documentación de arquitectura. |

---

## 2. Requisitos Previos

- **Python**: Versión 3.10 o superior (verificado con Python 3.12).
- **Ollama**: Motor de inferencia local para modelos LLM ([https://ollama.com](https://ollama.com)).
- **Modelo LLM**: `llama3.2:latest` (aproximadamente 2.0 GB).

---

## 3. Instalación

1. Clonar el repositorio y posicionarse en la carpeta raíz:
   ```bash
   cd agent-injection-lab
   ```

2. Crear y activar un entorno virtual:
   - **En Windows (PowerShell):**
     ```powershell
     python -m venv .venv
     .venv\Scripts\Activate.ps1
     ```
   - **En Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. Instalar la biblioteca cliente requerida:
   ```bash
   pip install -r requirements.txt
   ```

4. Descargar el modelo local en Ollama y verificar que el daemon esté activo:
   ```bash
   ollama pull llama3.2:latest
   ollama serve
   ```
   *(Si Ollama ya corre en segundo plano escuchando en `http://127.0.0.1:11434`, no es necesario ejecutar `ollama serve` nuevamente)*.

---

## 4. Guía de Ejecución Paso a Paso

El flujo de trabajo es transparente y auditable en cada etapa:

### Paso 1: Preparación manual del espacio de trabajo
Crea o restablece el directorio `lab_workspace/` con los archivos de referencia `public.txt` y `secret.txt`.

**La preparación es un paso manual**: los agentes `inseguro.py` y `seguro.py` no restablecen los archivos automáticamente, lo que permite que cada ejecución preserve el estado del disco hasta que el usuario decida reinicializarlo:
```bash
python preparar_laboratorio.py
```

### Paso 2: Verificación de requisitos y precondiciones
Comprueba de forma rápida y no destructiva que la versión de Python, la biblioteca `ollama`, la conectividad al daemon local y la presencia de `llama3.2:latest` estén listas (utilizando la respuesta tipada del SDK):
```bash
python verificar_requisitos.py
```

### Paso 3: Ejecución del escenario vulnerable
Ejecuta el agente sin control de autorización. El LLM procesa un issue que contiene una inyección de prompt indirecta. Al carecer de autorización de negocio independiente, el sistema confía en la propuesta del modelo y sobrescribe `secret.txt`:
```bash
python inseguro.py
```

### Paso 4: Restablecimiento y ejecución del escenario protegido
Para evaluar el escenario protegido desde el estado de referencia, se restablece el laboratorio manualmente y se ejecuta el agente protegido:
```bash
python preparar_laboratorio.py
python seguro.py
```
El agente protegido recibe la misma entrada bajo **paridad de configuración experimental**, pero consulta obligatoriamente a `control_autorizacion.py` antes de escribir. La política de mínimo privilegio rechaza la modificación del recurso protegido y `secret.txt` permanece intacto.

---

## 5. Sandbox de Archivos a Nivel de Aplicación vs. Autorización de Negocio

Es importante distinguir dos capas de control con alcances diferentes dentro del laboratorio:

| Aspecto | Sandbox de archivos (`agente_comun.py`) | Autorización de negocio (`control_autorizacion.py`) |
|---|---|---|
| **Implementación** | `resolver_ruta_segura()` (lanza `ErrorSandboxRutas`). | `autorizar_accion(herramienta, params)`. |
| **Presente en** | `inseguro.py` y `seguro.py` (capa compartida). | Exclusivo de `seguro.py`. |
| **Qué controla** | Restringe las rutas dentro de `lab_workspace/`, rechaza bytes nulos (`\x00`), path traversal (`../`) y enlaces simbólicos/junctions. | Aplica la política de mínimo privilegio: herramienta permitida (`write_file`), denegación de recursos protegidos (`secret.txt`) y lista blanca (`public.txt`). |
| **Limitación / Alcance** | Es una validación de rutas a nivel de aplicación (no aislamiento de proceso o sistema operativo) y **no distingue archivos públicos de sensibles** dentro de `lab_workspace/`. | Intercepta la propuesta del modelo antes de escribir en disco, neutralizando ataques de inyección indirecta incluso cuando apuntan a rutas válidas dentro de `lab_workspace/`. |

Por esta razón, aunque `inseguro.py` cuenta con el sandbox de rutas para evitar escrituras fuera de `lab_workspace/`, **no bloquea la modificación de `lab_workspace/secret.txt`** cuando el modelo es manipulado por la inyección indirecta. Solo la incorporación de la capa de autorización de negocio en `seguro.py` detiene el abuso antes de acceder al sistema de archivos.

