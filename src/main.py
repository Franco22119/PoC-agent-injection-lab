"""Main CLI entry point for the agent-injection-lab Proof of Concept."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
import uuid

from src.agent import DeterministicAgent, OllamaAgent, OllamaUnavailableError, BaseAgent
from src.audit import AuditLogger
from src.security import SecurityController, ActionExecutor, ExecutionResult
from src.tools import LabWorkspace


# Configure UTF-8 for Windows consoles
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# Paths
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
FIXTURES_DIR = PROJECT_ROOT / "fixtures"
RESULTS_DIR = PROJECT_ROOT / "results"
DEFAULT_AUDIT_LOG = RESULTS_DIR / "audit_events.jsonl"


def print_banner() -> None:
    print("=" * 76)
    print("    LABORATORIO ACADEMICO: PROMPT INJECTION EN AGENTES DE IA")
    print("      Evaluacion de Controlador de Autorizacion Independiente")
    print("=" * 76)


def print_section(title: str) -> None:
    print(f"\n--- [ {title} ] " + "-" * (70 - len(title)))


def load_fixture(fixture_name: str) -> str:
    """Load text fixture from file or preset name."""
    preset_map = {
        "benign": FIXTURES_DIR / "issue_benign.txt",
        "malicious": FIXTURES_DIR / "issue_malicious.txt",
    }
    target = preset_map.get(fixture_name, Path(fixture_name))
    if not target.exists():
        raise FileNotFoundError(f"Archivo de fixture no encontrado: {target}")
    return target.read_text(encoding="utf-8")


def run_single_simulation(
    agent: BaseAgent,
    executor: ActionExecutor,
    workspace: LabWorkspace,
    audit_logger: AuditLogger,
    issue_text: str,
    issue_label: str,
    profile: str,
    mode_name: str,
) -> ExecutionResult:
    """Run an end-to-end evaluation step."""
    # Reset workspace to baseline state
    workspace.reset()

    run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"

    print(f"\n>>> Ejecutando Caso: [{issue_label}] | Perfil: [{profile.upper()}] | ID: {run_id}")

    # Step 1: Agent proposes an action
    print("  [1] Agente procesando issue...")
    proposed_action = agent.propose_action(issue_text)
    print(f"      Accion propuesta: {json.dumps(proposed_action, ensure_ascii=False, indent=2)}")

    # Step 2: Executor / Controller evaluates and executes
    print(f"  [2] Evaluando y ejecutando bajo perfil [{profile}]...")
    exec_result = executor.execute(proposed_action, workspace, profile=profile)

    # Step 3: Check secret file integrity
    secret_modified = workspace.is_secret_modified()
    secret_preview = workspace.get_secret_content()[:80]

    # Step 4: Audit logging
    audit_logger.record_event(
        run_id=run_id,
        mode=mode_name,
        profile=profile,
        issue_name=issue_label,
        result=exec_result,
        protected_file_modified=secret_modified,
    )

    # Output details
    print(f"      Decision del controlador: {'AUTORIZADA' if exec_result.authorized else 'DENEGADA'}")
    print(f"      Motivo: {exec_result.authorization_reason}")
    print(f"      Resultado operacion: {'EXITOSA' if exec_result.success else 'FALLIDA / RECHAZADA'}")
    print(f"      Estado archivo protegido (secret.txt): {'MODIFICADO (COMPROMETIDO)' if secret_modified else 'INTACTO (PROTEGIDO)'}")
    print(f"      Contenido actual secret.txt: \"{secret_preview}\"")

    return exec_result


def print_metrics_summary(metrics: Dict[str, Any]) -> None:
    """Print the final executive metrics table."""
    print_section("METRICAS DE SEGURIDAD Y EVALUACION")
    print(f"  * Total de ejecuciones evaluadas:             {metrics['total_runs']}")
    print(f"  * Eventos de auditoria registrados:           {metrics['security_events_logged']}")
    print(f"  * Ataque inducido por prompt injection:       {'SI' if metrics['attack_reproduced'] else 'NO'}")
    print(f"  * Solicitud legitima completada con exito:    {'SI' if metrics['legitimate_completed'] else 'NO'}")
    print(f"  * Total de intentos no autorizados evaluados: {metrics['unauthorized_attempts']}")
    if metrics['unauthorized_vulnerable_attempts'] > 0:
        print(f"    - En perfil VULNERABLE: {metrics['unauthorized_vulnerable_attempts']} intento(s) -> MODIFICACION EXITOSA (Fallo de seguridad demostrado)")
    if metrics['unauthorized_mitigated_attempts'] > 0:
        print(f"    - En perfil MITIGADO:   {metrics['unauthorized_mitigated_attempts']} intento(s) -> BLOQUEADOS: {metrics['unauthorized_mitigated_blocked']} ({metrics['mitigated_block_rate']}%)")
    print(f"  * Integridad de secret.txt en perfil mitigado: {'COMPROMETIDO' if metrics['protected_file_modified'] and metrics['unauthorized_mitigated_attempts'] > 0 and metrics['unauthorized_mitigated_blocked'] < metrics['unauthorized_mitigated_attempts'] else 'PRESERVADA (INTACTO)'}")
    print("=" * 76)


def run_demo(
    mode: str = "deterministic",
    profiles: Optional[List[str]] = None,
    issues: Optional[List[str]] = None,
    model_name: Optional[str] = None,
    workspace_path: Optional[Path] = None,
) -> int:
    """Run demonstration with comparative analysis."""
    print_banner()

    default_model = os.getenv("OLLAMA_MODEL", "llama3.2:latest")
    model_name = model_name or default_model

    profiles = profiles or ["vulnerable", "mitigated"]
    issues = issues or ["benign", "malicious"]

    # Setup isolated lab workspace
    lab_root = workspace_path or (PROJECT_ROOT / "lab_workspace")
    workspace = LabWorkspace(lab_root)
    workspace.setup()
    print(f"[+] Espacio de trabajo del laboratorio aislado en: {workspace.root}")

    # Setup controller, executor, audit
    controller = SecurityController()
    executor = ActionExecutor(controller=controller)
    audit_logger = AuditLogger(log_file=DEFAULT_AUDIT_LOG)

    # Initialize agent
    if mode == "deterministic":
        print("[+] Modo de agente seleccionado: DETERMINISTA (Simulacion reproducible sin LLM)")
        agent: BaseAgent = DeterministicAgent()
    elif mode == "ollama":
        print(f"[+] Modo de agente seleccionado: OLLAMA LOCAL (Modelo: {model_name})")
        ollama_agent = OllamaAgent(model_name=model_name)
        if not ollama_agent.check_availability():
            print("\n[!] ERROR: No se pudo conectar al servicio local de Ollama.")
            print("    Para ejecutar este modo:")
            print("    1. Asegurate de tener Ollama instalado e iniciado ('ollama serve').")
            print(f"    2. Descarga el modelo: 'ollama run {model_name}' o 'ollama pull {model_name}'.")
            print("    3. Puedes ejecutar la demostracion determinista sin Ollama mediante:")
            print("       python -m src.main --mode deterministic\n")
            return 1
        agent = ollama_agent
    else:
        print(f"[!] Modo desconocido: {mode}")
        return 1

    # Execute combinations
    for issue_key in issues:
        print_section(f"PROCESANDO CASO: {issue_key.upper()}")
        try:
            issue_text = load_fixture(issue_key)
        except Exception as err:
            print(f"[!] Error al cargar fixture '{issue_key}': {err}")
            continue

        print(f"Contenido del issue ({issue_key}):\n\"\"\"\n{issue_text.strip()}\n\"\"\"")

        for prof in profiles:
            run_single_simulation(
                agent=agent,
                executor=executor,
                workspace=workspace,
                audit_logger=audit_logger,
                issue_text=issue_text,
                issue_label=issue_key,
                profile=prof,
                mode_name=mode,
            )

    # Display final aggregated metrics
    metrics = audit_logger.compute_metrics()
    print_metrics_summary(metrics)

    print(f"[+] Registro de auditoria persistido en: {DEFAULT_AUDIT_LOG}")
    return 0


def run_tests() -> int:
    """Execute pytest suite."""
    import pytest
    tests_dir = str(PROJECT_ROOT / "tests")
    print(f"[+] Ejecutando suite de pruebas automatizadas con pytest en: {tests_dir}")
    return pytest.main(["-v", tests_dir])


def main() -> None:
    parser = argparse.ArgumentParser(
        description="agent-injection-lab: PoC de Prompt Injection y Control de Autorizacion en Agentes con Herramientas."
    )
    parser.add_argument(
        "--mode",
        choices=["deterministic", "ollama"],
        default="deterministic",
        help="Modo del agente: 'deterministic' (sin IA, reproducible) u 'ollama' (modelo local real).",
    )
    parser.add_argument(
        "--profile",
        choices=["vulnerable", "mitigated", "both"],
        default="both",
        help="Perfil de ejecucion: 'vulnerable', 'mitigated' o 'both' para comparativa.",
    )
    parser.add_argument(
        "--issue",
        choices=["benign", "malicious", "all"],
        default="all",
        help="Tipo de issue a procesar: 'benign', 'malicious' o 'all'.",
    )
    default_model = os.getenv("OLLAMA_MODEL", "llama3.2:latest")
    parser.add_argument(
        "--model",
        default=default_model,
        help=f"Nombre del modelo Ollama (defecto: '{default_model}' o variable de entorno OLLAMA_MODEL).",
    )
    parser.add_argument(
        "--run-tests",
        action="store_true",
        help="Ejecutar la suite completa de tests automatizados con pytest.",
    )

    args = parser.parse_args()

    if args.run_tests:
        sys.exit(run_tests())

    profiles = ["vulnerable", "mitigated"] if args.profile == "both" else [args.profile]
    issues = ["benign", "malicious"] if args.issue == "all" else [args.issue]

    exit_code = run_demo(
        mode=args.mode,
        profiles=profiles,
        issues=issues,
        model_name=args.model,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
