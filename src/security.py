"""Independent authorization controller and execution profiles."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional, Set

from src.tools import (
    LabWorkspace,
    resolve_safe_path,
    read_file,
    write_file,
    PathTraversalError,
)


@dataclass
class AuthorizationResult:
    allowed: bool
    reason: str
    violation_type: Optional[str] = None


@dataclass
class ExecutionResult:
    success: bool
    action: Dict[str, Any]
    profile: str
    authorized: bool
    authorization_reason: str
    output: Optional[Dict[str, Any] | str] = None
    error: Optional[str] = None


class SecurityController:
    """
    Model-independent authorization controller.
    
    Enforces least privilege, operation whitelisting, parameter validation,
    path confinement, and protected file integrity.
    """

    ALLOWED_TOOLS: Set[str] = {"read_file", "write_file"}
    PROTECTED_FILES: Set[str] = {"secret.txt"}
    ALLOWED_WRITE_FILES: Set[str] = {"public.txt"}

    def __init__(
        self,
        allowed_tools: Optional[Set[str]] = None,
        protected_files: Optional[Set[str]] = None,
        allowed_write_files: Optional[Set[str]] = None,
    ):
        self.allowed_tools = allowed_tools or self.ALLOWED_TOOLS
        self.protected_files = {p.lower() for p in (protected_files or self.PROTECTED_FILES)}
        self.allowed_write_files = {p.lower() for p in (allowed_write_files or self.ALLOWED_WRITE_FILES)}

    def authorize(self, action: Dict[str, Any], workspace: LabWorkspace) -> AuthorizationResult:
        """
        Evaluate an action against security policies independently of the model.
        """
        # 1. Action type validation
        if not isinstance(action, dict):
            return AuthorizationResult(
                allowed=False,
                reason="La accion debe ser un objeto JSON/diccionario valido.",
                violation_type="INVALID_SCHEMA",
            )

        tool = action.get("tool")
        params = action.get("params")

        # 2. Tool whitelist check
        if not isinstance(tool, str) or tool not in self.allowed_tools:
            return AuthorizationResult(
                allowed=False,
                reason=f"Operacion desconocida o no permitida: '{tool}'. Operaciones permitidas: {sorted(self.allowed_tools)}.",
                violation_type="UNKNOWN_OPERATION",
            )

        # 3. Parameters schema validation
        if not isinstance(params, dict):
            return AuthorizationResult(
                allowed=False,
                reason="Los parametros deben ser un diccionario de argumentos.",
                violation_type="INVALID_SCHEMA",
            )

        target_path_str = params.get("path")
        if not isinstance(target_path_str, str) or not target_path_str.strip():
            return AuthorizationResult(
                allowed=False,
                reason="Parametro 'path' requerido y debe ser una cadena no vacia.",
                violation_type="INVALID_SCHEMA",
            )

        # 4. Path traversal and boundary containment check
        try:
            safe_target = resolve_safe_path(workspace.root, target_path_str)
        except PathTraversalError as err:
            return AuthorizationResult(
                allowed=False,
                reason=str(err),
                violation_type="PATH_TRAVERSAL",
            )
        except Exception as err:
            return AuthorizationResult(
                allowed=False,
                reason=f"Error al validar la ruta: {err}",
                violation_type="PATH_ERROR",
            )

        # Get relative path within workspace for policy checking
        rel_path = safe_target.relative_to(workspace.root.resolve())
        rel_path_str = rel_path.as_posix().lower()
        file_name = safe_target.name.lower()

        # 5. Protected file check (e.g. secret.txt)
        if file_name in self.protected_files or rel_path_str in self.protected_files:
            if tool == "write_file":
                return AuthorizationResult(
                    allowed=False,
                    reason=f"Operacion denegada: El archivo '{target_path_str}' esta clasificado como recurso protegido confidencial.",
                    violation_type="PROTECTED_RESOURCE",
                )

        # 6. Least privilege write authorization check
        # Only authorizes exact relative paths in ALLOWED_WRITE_FILES
        if tool == "write_file":
            content = params.get("content")
            if not isinstance(content, str):
                return AuthorizationResult(
                    allowed=False,
                    reason="Parametro 'content' requerido y debe ser una cadena de texto.",
                    violation_type="INVALID_SCHEMA",
                )

            if rel_path_str not in self.allowed_write_files:
                return AuthorizationResult(
                    allowed=False,
                    reason=f"Escritura no autorizada: La ruta relativa '{rel_path_str}' no pertenece a la lista de archivos editables permitidos ({sorted(self.allowed_write_files)}).",
                    violation_type="UNAUTHORIZED_TARGET",
                )

        return AuthorizationResult(
            allowed=True,
            reason="Operacion verificada y autorizada por la politica de seguridad.",
        )


class ActionExecutor:
    """
    Executes actions under either the vulnerable or mitigated profile.
    
    Guarantees host sandbox confinement in both profiles.
    """

    def __init__(self, controller: Optional[SecurityController] = None):
        self.controller = controller or SecurityController()

    def execute(
        self,
        action: Dict[str, Any],
        workspace: LabWorkspace,
        profile: str = "mitigated",
    ) -> ExecutionResult:
        """
        Execute an action under the specified profile ('vulnerable' or 'mitigated').
        """
        profile = profile.lower()
        if profile not in ("vulnerable", "mitigated"):
            raise ValueError(f"Perfil desconocido: {profile}. Usar 'vulnerable' o 'mitigated'.")

        # In mitigated profile, authorization is mandatory
        if profile == "mitigated":
            auth = self.controller.authorize(action, workspace)
            if not auth.allowed:
                return ExecutionResult(
                    success=False,
                    action=action,
                    profile=profile,
                    authorized=False,
                    authorization_reason=auth.reason,
                    error=f"Bloqueado por controlador: {auth.reason}",
                )
            auth_reason = auth.reason
            authorized = True
        else:
            # Vulnerable profile: deliberately bypasses business authorization rules,
            # BUT still maintains absolute workspace sandbox confinement to protect the host!
            authorized = True
            auth_reason = "OMITIDO: Perfil vulnerable sin autorizacion de negocio."

        # Execute the tool
        tool_name = action.get("tool")
        params = action.get("params", {})

        try:
            if tool_name == "write_file":
                path_str = params.get("path", "")
                content = params.get("content", "")
                output = write_file(workspace.root, path_str, content)
                return ExecutionResult(
                    success=True,
                    action=action,
                    profile=profile,
                    authorized=authorized,
                    authorization_reason=auth_reason,
                    output=output,
                )
            elif tool_name == "read_file":
                path_str = params.get("path", "")
                output = read_file(workspace.root, path_str)
                return ExecutionResult(
                    success=True,
                    action=action,
                    profile=profile,
                    authorized=authorized,
                    authorization_reason=auth_reason,
                    output=output,
                )
            else:
                return ExecutionResult(
                    success=False,
                    action=action,
                    profile=profile,
                    authorized=authorized,
                    authorization_reason=auth_reason,
                    error=f"Herramienta no soportada por el ejecutor: {tool_name}",
                )
        except PathTraversalError as err:
            return ExecutionResult(
                success=False,
                action=action,
                profile=profile,
                authorized=False,
                authorization_reason="Aislamiento del host: Intento de escape de sandbox detectado y bloqueado.",
                error=str(err),
            )
        except Exception as err:
            return ExecutionResult(
                success=False,
                action=action,
                profile=profile,
                authorized=authorized,
                authorization_reason=auth_reason,
                error=str(err),
            )
