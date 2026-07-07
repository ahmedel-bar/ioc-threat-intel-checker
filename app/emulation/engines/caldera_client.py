"""MITRE CALDERA REST client stub.

For PlanSteps with engine=caldera and payload.ability_id, this will POST
an operation to a running CALDERA server and poll for results.

NOT YET IMPLEMENTED — interface is locked so the orchestrator can call it
once execution is enabled. Reference API:

    POST {CALDERA_URL}/api/v2/operations
      Headers: KEY: <api_key>
      Body:    {"name": ..., "adversary": {"adversary_id": <plan_id>},
                "planner": {"id": "atomic"}, "source": {"id": "..."}}

    GET  {CALDERA_URL}/api/v2/operations/{op_id}/links   → status per ability
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.emulation.models import EngineKind, ExecutionRecord, PlanStep, EngagementScope

logger = logging.getLogger(__name__)


def execute(step: PlanStep, scope: EngagementScope, context: dict) -> ExecutionRecord:
    started = datetime.now(timezone.utc).isoformat()
    ability = (step.payload or {}).get("ability_id", "")

    logger.warning(
        "[CALDERA] Engine not yet implemented — would have run ability %s for %s",
        ability, step.technique_id,
    )
    return ExecutionRecord(
        run_id=context.get("run_id", 0),
        step_idx=step.order,
        technique_id=step.technique_id,
        engine=EngineKind.CALDERA.value,
        command=f"POST /api/v2/operations  ability_id={ability}",
        ok=False,
        error="caldera_client not yet implemented — stub only",
        started_at=started,
        ended_at=datetime.now(timezone.utc).isoformat(),
    )
