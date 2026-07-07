"""Runs an EmulationPlan step-by-step against a chosen engine.

Public API:
    create_run(plan_id, customer_id, scope, engine_override=None) -> run_id
    execute_run(run_id, ingest_queue=None, context_extra=None) -> dict (summary)

A run lifecycle:
    PENDING → AUTHORIZED (after create_run with valid scope) → RUNNING → COMPLETED|ABORTED|FAILED
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from app import database as db
from app.emulation import safety
from app.emulation.engines import atomic_runner, caldera_client, log_injector
from app.emulation.loader import get_plan
from app.emulation.models import (
    EmulationPlan,
    EngagementScope,
    EngineKind,
    ExecutionRecord,
    PlanStep,
    RunStatus,
)

logger = logging.getLogger(__name__)

# ── Engine dispatch ───────────────────────────────────────────────────────────
_ENGINES = {
    EngineKind.TABLETOP.value: log_injector.execute,
    EngineKind.ATOMIC.value:   atomic_runner.execute,
    EngineKind.CALDERA.value:  caldera_client.execute,
}


# ── Run lifecycle ─────────────────────────────────────────────────────────────

def create_run(
    plan_id: str,
    customer_id: str,
    scope: EngagementScope,
    engine_override: str | None = None,
) -> int:
    """Persist a new run row in AUTHORIZED state. Raises if plan is missing."""
    plan = get_plan(plan_id)
    if plan is None:
        raise ValueError(f"plan {plan_id!r} not found in DB — run loader.seed_from_disk() first")

    engine = engine_override or (plan.steps[0].engine if plan.steps else EngineKind.TABLETOP.value)
    safety.assert_engine_available(engine)

    conn = db.get_conn()
    cur = conn.execute("""
        INSERT INTO emulation_runs
            (plan_id, customer_id, engine, scope_json, status, authorized_by, auth_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        plan_id, customer_id, engine,
        json.dumps(asdict(scope)),
        RunStatus.AUTHORIZED.value,
        scope.authorized_by, scope.authorization_hash,
    ))
    conn.commit()
    run_id = cur.lastrowid
    logger.info("[ORCHESTRATOR] Run %d authorized — plan=%s customer=%s engine=%s",
                run_id, plan_id, customer_id, engine)
    return run_id


def _set_status(run_id: int, status: RunStatus, started: bool = False, ended: bool = False):
    conn = db.get_conn()
    sets = ["status = ?"]
    vals: list[Any] = [status.value]
    if started:
        sets.append("started_at = datetime('now')")
    if ended:
        sets.append("ended_at = datetime('now')")
    conn.execute(f"UPDATE emulation_runs SET {', '.join(sets)} WHERE id = ?", (*vals, run_id))
    conn.commit()


def _persist_record(rec: ExecutionRecord) -> int:
    conn = db.get_conn()
    cur = conn.execute("""
        INSERT INTO execution_records
            (run_id, step_idx, technique_id, engine, command, evidence, ok, error, started_at, ended_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        rec.run_id, rec.step_idx, rec.technique_id, rec.engine,
        rec.command, rec.evidence, 1 if rec.ok else 0, rec.error,
        rec.started_at, rec.ended_at,
    ))
    conn.commit()
    return cur.lastrowid


def _persist_expected(record_id: int, step: PlanStep):
    """Pre-create detection_validations rows in 'miss' state. A validator
    job (run separately, after telemetry has had time to land in Splunk)
    flips `detected=1` when a matching alert is found."""
    conn = db.get_conn()
    for q in step.expected_detections or []:
        conn.execute(
            "INSERT INTO detection_validations (record_id, expected_query, detected) VALUES (?, ?, 0)",
            (record_id, q),
        )
    conn.commit()


def execute_run(
    run_id: int,
    ingest_queue=None,
    context_extra: dict | None = None,
    step_delay_secs: float = 0.5,
) -> dict:
    """Walk every step in the plan, dispatch to the chosen engine, record evidence.

    Args:
        run_id: id returned by create_run()
        ingest_queue: live queue for the tabletop engine (typically pipeline.ingest_queue)
        context_extra: extra render context (e.g. {"customer_domain": "acme.corp"})
        step_delay_secs: pause between steps to make timelines easier to read in Splunk

    Returns summary: {"executed": N, "ok": N, "failed": N, "skipped": N, "started": ts, "ended": ts}
    """
    conn = db.get_conn()
    row = conn.execute(
        "SELECT plan_id, customer_id, engine, scope_json, status FROM emulation_runs WHERE id = ?",
        (run_id,),
    ).fetchone()
    if not row:
        raise ValueError(f"run {run_id} not found")
    if row["status"] not in (RunStatus.AUTHORIZED.value, RunStatus.PENDING.value):
        raise RuntimeError(f"run {run_id} is in status {row['status']} — cannot execute")

    plan = get_plan(row["plan_id"])
    if plan is None:
        raise ValueError(f"plan {row['plan_id']} disappeared between create and execute")

    scope = EngagementScope(**json.loads(row["scope_json"]))
    engine_override = row["engine"]

    context = {
        "run_id":    run_id,
        "actor_id":  plan.actor_id,
        "customer_domain": scope.customer_id,
        "ingest_queue": ingest_queue,
        **(context_extra or {}),
    }

    safety.reset_kill_switch()
    _set_status(run_id, RunStatus.RUNNING, started=True)
    started_at = datetime.now(timezone.utc).isoformat()

    executed = ok = failed = skipped = 0

    for step in plan.steps:
        # Engine resolution: orchestrator-level override beats per-step engine
        effective_engine = engine_override or step.engine
        step_for_exec = PlanStep(**{**asdict(step), "engine": effective_engine})

        # Safety gate
        try:
            safety.check_step(step_for_exec, scope)
        except safety.SafetyViolation as exc:
            skipped += 1
            rec = ExecutionRecord(
                run_id=run_id, step_idx=step.order, technique_id=step.technique_id,
                engine=effective_engine, ok=False, error=f"safety: {exc}",
                started_at=datetime.now(timezone.utc).isoformat(),
                ended_at=datetime.now(timezone.utc).isoformat(),
            )
            rec_id = _persist_record(rec)
            _persist_expected(rec_id, step_for_exec)
            if str(exc) == "kill-switch active":
                _set_status(run_id, RunStatus.ABORTED, ended=True)
                logger.warning("[ORCHESTRATOR] Run %d aborted by kill-switch at step %d",
                               run_id, step.order)
                return _summary(run_id, started_at, executed, ok, failed, skipped, "ABORTED")
            continue

        # Dispatch
        engine_fn = _ENGINES.get(effective_engine)
        if engine_fn is None:
            failed += 1
            rec = ExecutionRecord(
                run_id=run_id, step_idx=step.order, technique_id=step.technique_id,
                engine=effective_engine, ok=False, error=f"no engine '{effective_engine}'",
                started_at=datetime.now(timezone.utc).isoformat(),
                ended_at=datetime.now(timezone.utc).isoformat(),
            )
            rec_id = _persist_record(rec)
            _persist_expected(rec_id, step_for_exec)
            continue

        rec = engine_fn(step_for_exec, scope, context)
        executed += 1
        if rec.ok:
            ok += 1
        else:
            failed += 1
        rec_id = _persist_record(rec)
        _persist_expected(rec_id, step_for_exec)

        if step_delay_secs > 0:
            time.sleep(step_delay_secs)

    final_status = RunStatus.COMPLETED if failed == 0 else RunStatus.FAILED
    _set_status(run_id, final_status, ended=True)
    logger.info("[ORCHESTRATOR] Run %d %s — executed=%d ok=%d failed=%d skipped=%d",
                run_id, final_status.value, executed, ok, failed, skipped)
    return _summary(run_id, started_at, executed, ok, failed, skipped, final_status.value)


def _summary(run_id, started_at, executed, ok, failed, skipped, status) -> dict:
    return {
        "run_id":   run_id,
        "status":   status,
        "executed": executed,
        "ok":       ok,
        "failed":   failed,
        "skipped":  skipped,
        "started":  started_at,
        "ended":    datetime.now(timezone.utc).isoformat(),
    }


# ── Read helpers ──────────────────────────────────────────────────────────────

def get_run(run_id: int) -> dict | None:
    row = db.get_conn().execute(
        "SELECT * FROM emulation_runs WHERE id = ?", (run_id,)
    ).fetchone()
    return dict(row) if row else None


def list_runs(customer_id: str | None = None, limit: int = 50) -> list[dict]:
    if customer_id:
        rows = db.get_conn().execute(
            "SELECT * FROM emulation_runs WHERE customer_id = ? "
            "ORDER BY created_at DESC LIMIT ?",
            (customer_id, limit),
        ).fetchall()
    else:
        rows = db.get_conn().execute(
            "SELECT * FROM emulation_runs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_run_records(run_id: int) -> list[dict]:
    rows = db.get_conn().execute(
        "SELECT * FROM execution_records WHERE run_id = ? ORDER BY step_idx",
        (run_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def run_gap_report(run_id: int) -> dict:
    """How many expected detections fired vs missed? Foundation for the
    MITRE Navigator gap layer."""
    conn = db.get_conn()
    total = conn.execute(
        "SELECT COUNT(*) AS n FROM detection_validations dv "
        "JOIN execution_records er ON er.id = dv.record_id WHERE er.run_id = ?",
        (run_id,),
    ).fetchone()["n"]
    detected = conn.execute(
        "SELECT COUNT(*) AS n FROM detection_validations dv "
        "JOIN execution_records er ON er.id = dv.record_id "
        "WHERE er.run_id = ? AND dv.detected = 1",
        (run_id,),
    ).fetchone()["n"]
    return {
        "run_id":          run_id,
        "expected_total":  total,
        "detected":        detected,
        "missed":          total - detected,
        "coverage_pct":    round(detected / total * 100, 1) if total else 0.0,
    }
