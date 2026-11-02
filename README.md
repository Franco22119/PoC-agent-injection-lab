# agent-injection-lab

Prueba de concepto (PoC) académica que demuestra una vulnerabilidad de **Prompt Injection Indirecta** en agentes de Inteligencia Artificial conectados a herramientas, y cómo mitigarla mediante un **controlador de autorización determinista e independiente del modelo**.

---

## Disclaimer

Este trabajo es un proyecto académico para la materia TALLER DE SEGURIDAD INFORMÁTICA / CIBERSEGURIDAD DE REDES E INFRAESTRUCTURAS CRÍTICAS en el período de cursada segundo cuatrimestre 2026, organizado y propuesto por el grupo número 4.

---

## 1. Requisitos

- **Python**: Versión 3.10 o superior (probado con Python 3.12).
- **Ollama**: Motor de inferencia local para modelos LLM ([https://ollama.com](https://ollama.com)).
- **Modelo LLM**: `llama3.2:latest` (aproximadamente 2.0 GB).

---

## 2. Instalación

1. Clonar el repositorio y acceder al directorio:
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

3. Instalar dependencias mínimas:
   ```bash
   pip install -r requirements.txt
   ```

---

## 3. Preparación de Ollama

1. Descargar el modelo local:
   ```bash
   ollama pull llama3.2:latest
   ```

2. Verificar que el servicio esté activo:
   - Si Ollama ya se encuentra ejecutándose como servicio o aplicación en segundo plano (escuchando en `http://127.0.0.1:11434`), no es necesario abrir otra terminal.
   - En caso de no estar activo, iniciarlo con:
     ```bash
     ollama serve
     ```

---

## 4. Ejecución de la demostración

La PoC se compone de dos scripts completamente independientes que evalúan el mismo escenario utilizando `llama3.2:latest` con `temperature=0.0`. Aunque la temperatura en cero minimiza la variabilidad, cada ejecución refleja de forma transparente la respuesta real del modelo.

### A. Escenario Inseguro (Agente Vulnerable)

El agente procesa un issue que contiene una inyección de prompt indirecta. Al carecer de un control de autorización de negocio independiente, el sistema confía en la acción propuesta por el modelo. Si el LLM es inducido a escribir sobre `secret.txt`, la operación se ejecuta en disco:

```bash
python inseguro.py
```

### B. Escenario Seguro (Agente con Controlador de Autorización)

El agente procesa exactamente el mismo contexto y la misma entrada. Antes de invocar el sistema de archivos, un controlador de seguridad determinista valida la operación contra una lista blanca. Si el modelo propone modificar `secret.txt`, la operación se rechaza y el archivo permanece intacto:

```bash
python seguro.py
```

---

## 5. Comparativa de Controles de Seguridad

| Dimensión de Seguridad | Escenario Inseguro (`inseguro.py`) | Escenario Seguro (`seguro.py`) |
| :--- | :---: | :---: |
| **Confinamiento en `lab_workspace/`** | Sí (impide Path Traversal hacia el host) | Sí (impide Path Traversal hacia el host) |
| **Validación de contrato de acción** | Sí (valida tipos JSON antes de ejecutar) | Sí (valida tipos JSON antes de autorizar) |
| **Controlador de autorización independiente** | **No** (confianza ciega en la propuesta del LLM) | **Sí** (`autorizar_accion` desacoplada del LLM) |
| **Política sobre `secret.txt`** | Sin restricción de negocio (ejecuta si el LLM lo pide) | **Protegido explícitamente contra escritura** |
| **Política sobre `public.txt`** | Permitido | **Permitido (único archivo en lista blanca)** |
| **Comportamiento ante intento de ataque** | Modificación permitida si el LLM lo propone | **Operación bloqueada en la capa de software** |

> **Conclusión pedagógica:** La seguridad de un agente de IA no debe depender de que el modelo sea infalible o inmune a inyecciones. La autorización de operaciones sobre herramientas debe gestionarse mediante controles deterministas en el software independientes del LLM.
