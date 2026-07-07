"""Safety rails enforced before any step executes against a real environment.

Three guards:
  1. Authorization gate     — scope must carry authorized_by + auth_hash
  2. Blocked-technique list — refuse destructive/forbidden TTPs (e.g. T1486)
  3. Engine-mode allowance  — tabletop bypasses host/network checks, atomic/caldera require allowed_hosts

The orchestrator calls `check_step(step, scope)` before each execution; on
violation it logs to execution_records with ok=False and skips the step.
"""
from __future__ import annotations

import logging
import threading

from app.emulation.models import EngineKind, EngagementScope, PlanStep

logger = logging.getLogger(__name__)

# Process-wide kill-switch. Set via safety.kill_switch.set() to halt any
# in-flight orchestrator loop after the current step.
kill_switch = threading.Event()


class SafetyViolation(Exception):
    """Raised when a step fails a safety check."""


def reset_kill_switch():
    kill_switch.clear()


def check_step(step: PlanStep, scope: EngagementScope) -> None:
    """Raise SafetyViolation if the step must not execute."""
    if kill_switch.is_set():
        raise SafetyViolation("kill-switch active")

    if step.technique_id in (scope.blocked_techniques or []):
        raise SafetyViolation(
            f"technique {step.technique_id} is in scope.blocked_techniques"
        )

    # Tabletop is always safe — it never touches a real host
    if step.engine == EngineKind.TABLETOP.value:
        return

    # Live engines require explicit authorization
    if not scope.authorized_by or not scope.authorization_hash:
        raise SafetyViolation(
            "live engine requires scope.authorized_by + authorization_hash"
        )

    if not scope.allowed_hosts and not scope.allowed_subnets:
        raise SafetyViolation(
            "live engine requires at least one allowed_host or allowed_subnet"
        )


def assert_engine_available(engine: str) -> None:
    """Hard refuse if the engine isn't implemented yet. Tabletop always works."""
    if engine == EngineKind.TABLETOP.value:
        return
    if engine in (EngineKind.ATOMIC.value, EngineKind.CALDERA.value):
        # Stubs exist; orchestrator will record a non-OK ExecutionRecord but
        # we don't refuse the run outright — useful for dry-run planning.
        logger.warning("[SAFETY] Engine '%s' is a stub — step will be recorded as failed", engine)
        return
    raise SafetyViolation(f"unknown engine: {engine}")
