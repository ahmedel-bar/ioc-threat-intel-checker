"""Atomic Red Team engine stub.

Wraps Red Canary's Invoke-AtomicRedTeam (PowerShell) so a PlanStep with
engine=atomic and payload.atomic_guid (or payload.name) can execute the
matching atomic test on the target host.

NOT YET IMPLEMENTED — interface is locked so the orchestrator can call it
once execution is enabled. Implementation will shell out to:

    powershell -ExecutionPolicy Bypass -Command "
        Import-Module Invoke-AtomicRedTeam;
        Invoke-AtomicTest <technique> -TestGuids <guid> -InputArgs @{...}
    "

…on a remote host via WinRM/SSH or via a pre-deployed agent.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.emulation.models import EngineKind, ExecutionRecord, PlanStep, EngagementScope

logger = logging.getLogger(__name__)


def execute(step: PlanStep, scope: EngagementScope, context: dict) -> ExecutionRecord:
    started = datetime.now(timezone.utc).isoformat()
    payload = step.payload or {}
    guid = payload.get("atomic_guid") or payload.get("name", "")

    logger.warning(
        "[ATOMIC] Engine not yet implemented — would have run %s (%s) on %s",
        step.technique_id, guid, ",".join(scope.allowed_hosts) or "<no hosts>",
    )
    return ExecutionRecord(
        run_id=context.get("run_id", 0),
        step_idx=step.order,
        technique_id=step.technique_id,
        engine=EngineKind.ATOMIC.value,
        command=f"Invoke-AtomicTest {step.technique_id} -TestGuids {guid}",
        ok=False,
        error="atomic_runner not yet implemented — stub only",
        started_at=started,
        ended_at=datetime.now(timezone.utc).isoformat(),
    )
