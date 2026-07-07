"""Execution engines — each translates a PlanStep into actual activity.

All engines expose:
    execute(step: PlanStep, scope: EngagementScope, context: dict) -> ExecutionRecord
"""
