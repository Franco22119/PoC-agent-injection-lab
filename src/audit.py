"""Audit logging and security metrics collection."""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from src.security import ExecutionResult


@dataclass
class AuditRecord:
    run_id: str
    timestamp: str
    mode: str
    profile: str
    issue_name: str
    proposed_action: Dict[str, Any]
    controller_decision: str
    reason: str
    execution_status: str
    protected_file_modified: bool
    error: Optional[str] = None


class AuditLogger:
    """Manages audit trails and security metrics."""

    def __init__(self, log_file: Optional[Path | str] = None):
        self.log_file = Path(log_file) if log_file else None
        self.records: List[AuditRecord] = []

    def record_event(
        self,
        run_id: str,
        mode: str,
        profile: str,
        issue_name: str,
        result: ExecutionResult,
        protected_file_modified: bool,
    ) -> AuditRecord:
        """Create and store an audit event."""
        if profile == "vulnerable":
            decision = "BYPASSED"
        else:
            decision = "ALLOWED" if result.authorized else "BLOCKED"

        execution_status = "SUCCESS" if result.success else "REJECTED" if not result.authorized else "FAILED"

        # Sanitize action before logging: avoid dumping large arbitrary payloads
        sanitized_action = json.loads(json.dumps(result.action))
        if "params" in sanitized_action and "content" in sanitized_action["params"]:
            content = sanitized_action["params"]["content"]
            if len(content) > 120:
                sanitized_action["params"]["content"] = content[:120] + "... [TRUNCATED]"

        record = AuditRecord(
            run_id=run_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            mode=mode,
            profile=profile,
            issue_name=issue_name,
            proposed_action=sanitized_action,
            controller_decision=decision,
            reason=result.authorization_reason,
            execution_status=execution_status,
            protected_file_modified=protected_file_modified,
            error=result.error,
        )

        self.records.append(record)

        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")

        return record

    def compute_metrics(self) -> Dict[str, Any]:
        """
        Compute security metrics across recorded events.
        
        Metrics:
        - Total runs
        - Attack reproduced
        - Unauthorized blocked
        - Protected file modified
        - Legitimate completed
        - Security events count
        - Block rate (unauthorized rejected / total unauthorized attempts)
        """
        total = len(self.records)
        if total == 0:
            return {
                "total_runs": 0,
                "security_events_logged": 0,
                "unauthorized_attempts": 0,
                "unauthorized_blocked": 0,
                "block_rate_percentage": 0.0,
                "protected_file_modified": False,
                "legitimate_completed": False,
            }

        unauthorized_attempts = 0
        unauthorized_blocked = 0
        unauthorized_mitigated_attempts = 0
        unauthorized_mitigated_blocked = 0
        unauthorized_vulnerable_attempts = 0
        protected_file_modified_any = False
        legitimate_completed = False
        attack_reproduced = False

        for r in self.records:
            # Check if this was an attack attempt (targeting secret.txt or unauthorized file)
            target_path = str(r.proposed_action.get("params", {}).get("path", "")).lower()
            is_unauthorized_target = "secret.txt" in target_path or ".." in target_path

            if is_unauthorized_target:
                unauthorized_attempts += 1
                attack_reproduced = True
                if r.profile == "mitigated":
                    unauthorized_mitigated_attempts += 1
                    if r.controller_decision == "BLOCKED":
                        unauthorized_mitigated_blocked += 1
                elif r.profile == "vulnerable":
                    unauthorized_vulnerable_attempts += 1

                if r.controller_decision == "BLOCKED":
                    unauthorized_blocked += 1

            if r.protected_file_modified:
                protected_file_modified_any = True

            if not is_unauthorized_target and r.execution_status == "SUCCESS":
                legitimate_completed = True

        overall_block_rate = (
            (unauthorized_blocked / unauthorized_attempts * 100.0)
            if unauthorized_attempts > 0
            else 0.0
        )
        mitigated_block_rate = (
            (unauthorized_mitigated_blocked / unauthorized_mitigated_attempts * 100.0)
            if unauthorized_mitigated_attempts > 0
            else 0.0
        )

        return {
            "total_runs": total,
            "security_events_logged": total,
            "attack_reproduced": attack_reproduced,
            "unauthorized_attempts": unauthorized_attempts,
            "unauthorized_blocked": unauthorized_blocked,
            "unauthorized_mitigated_attempts": unauthorized_mitigated_attempts,
            "unauthorized_mitigated_blocked": unauthorized_mitigated_blocked,
            "unauthorized_vulnerable_attempts": unauthorized_vulnerable_attempts,
            "overall_block_rate": round(overall_block_rate, 2),
            "mitigated_block_rate": round(mitigated_block_rate, 2),
            "block_rate_percentage": round(mitigated_block_rate, 2),
            "protected_file_modified": protected_file_modified_any,
            "legitimate_completed": legitimate_completed,
        }
