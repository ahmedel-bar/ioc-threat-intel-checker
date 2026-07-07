"""Tabletop engine — synthesizes expected telemetry into the ingest queue.

Zero blast radius: it does not touch the customer environment at all.
It simply fabricates the log events an actor's TTP *would* produce and pushes
them through the same ingest pipeline that real Splunk events flow through.

This lets the purple-team loop validate detections end-to-end without any
authorization risk — ideal for first runs and for environments where live
emulation is not permitted.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.emulation.models import EngineKind, ExecutionRecord, PlanStep, EngagementScope

logger = logging.getLogger(__name__)


def _render(template: str, fields: dict, context: dict) -> str:
    """Fill {placeholders} using fields then context, with timestamp shortcut."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    merged = {"ts": now, **context, **fields}
    # Two-pass render so {{customer_domain}} inside fields resolves from context
    for k, v in list(merged.items()):
        if isinstance(v, str):
            merged[k] = v.replace("{{customer_domain}}", str(context.get("customer_domain", "example.com")))
    try:
        return template.format(**merged)
    except KeyError as exc:
        logger.warning("[TABLETOP] Missing template field %s for %s", exc, template[:60])
        return template


def execute(step: PlanStep, scope: EngagementScope, context: dict) -> ExecutionRecord:
    """Render the step's event_template and push it into the ingest queue.

    `context` must include the live `ingest_queue` reference under key 'ingest_queue'.
    """
    started = datetime.now(timezone.utc).isoformat()
    payload = step.payload or {}
    template = payload.get("event_template", "")
    fields   = payload.get("fields", {}) or {}
    sourcetype = payload.get("sourcetype", "synthetic")

    if not template:
        return ExecutionRecord(
            run_id=context.get("run_id", 0),
            step_idx=step.order,
            technique_id=step.technique_id,
            engine=EngineKind.TABLETOP.value,
            ok=False,
            error="no event_template in payload",
            started_at=started,
            ended_at=datetime.now(timezone.utc).isoformat(),
        )

    raw = _render(template, fields, context)
    event = {
        "_raw": raw,
        "sourcetype": sourcetype,
        "_emulation": {
            "run_id":       context.get("run_id"),
            "step_idx":     step.order,
            "technique_id": step.technique_id,
            "actor_id":     context.get("actor_id"),
        },
    }

    ingest_queue = context.get("ingest_queue")
    if ingest_queue is None:
        return ExecutionRecord(
            run_id=context.get("run_id", 0),
            step_idx=step.order,
            technique_id=step.technique_id,
            engine=EngineKind.TABLETOP.value,
            ok=False,
            error="ingest_queue not provided in context",
            started_at=started,
            ended_at=datetime.now(timezone.utc).isoformat(),
        )

    try:
        ingest_queue.put_nowait(event)
    except Exception as exc:
        return ExecutionRecord(
            run_id=context.get("run_id", 0),
            step_idx=step.order,
            technique_id=step.technique_id,
            engine=EngineKind.TABLETOP.value,
            command=raw,
            ok=False,
            error=f"queue put failed: {exc}",
            started_at=started,
            ended_at=datetime.now(timezone.utc).isoformat(),
        )

    logger.info("[TABLETOP] step=%d %s injected (%s)", step.order, step.technique_id, sourcetype)
    return ExecutionRecord(
        run_id=context.get("run_id", 0),
        step_idx=step.order,
        technique_id=step.technique_id,
        engine=EngineKind.TABLETOP.value,
        command=raw,
        evidence=f"injected into ingest_queue (sourcetype={sourcetype})",
        ok=True,
        started_at=started,
        ended_at=datetime.now(timezone.utc).isoformat(),
    )
