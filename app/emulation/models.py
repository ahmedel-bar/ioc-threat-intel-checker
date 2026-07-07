"""Domain models for adversary emulation.

Plain stdlib dataclasses to stay aligned with the project's no-Pydantic style.
Serialization helpers (`from_dict` / `to_dict`) handle YAML <-> object mapping.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Tactic(str, Enum):
    RECONNAISSANCE      = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS      = "initial-access"
    EXECUTION           = "execution"
    PERSISTENCE         = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION     = "defense-evasion"
    CREDENTIAL_ACCESS   = "credential-access"
    DISCOVERY           = "discovery"
    LATERAL_MOVEMENT    = "lateral-movement"
    COLLECTION          = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION        = "exfiltration"
    IMPACT              = "impact"


class EngineKind(str, Enum):
    TABLETOP = "tabletop"   # log_injector — synthesize expected telemetry only
    ATOMIC   = "atomic"     # Atomic Red Team — single-host technique tests
    CALDERA  = "caldera"    # MITRE CALDERA — multi-host chained operations


class RunStatus(str, Enum):
    PENDING   = "PENDING"
    AUTHORIZED = "AUTHORIZED"
    RUNNING   = "RUNNING"
    COMPLETED = "COMPLETED"
    ABORTED   = "ABORTED"
    FAILED    = "FAILED"


@dataclass
class TTP:
    """A single ATT&CK technique an actor uses."""
    technique_id: str                # e.g. "T1059.001"
    technique_name: str              # e.g. "PowerShell"
    tactic: str                      # one of Tactic values
    sub_technique: str = ""
    tool: str = ""                   # e.g. "Cobalt Strike"
    notes: str = ""


@dataclass
class ThreatActor:
    """Structured threat actor profile."""
    id: str                          # short slug, e.g. "apt29"
    name: str                        # canonical name
    aliases: list[str] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    geos: list[str] = field(default_factory=list)
    motivation: str = ""
    description: str = ""
    source: str = "MITRE ATT&CK"     # provenance
    ttps: list[TTP] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ThreatActor":
        ttps = [TTP(**t) for t in d.get("ttps", [])]
        return cls(**{**d, "ttps": ttps})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlanStep:
    """One ordered step in an emulation plan.

    `expected_detections` is a list of Splunk SPL queries (or detection names)
    that *should* fire when this technique runs. The validator compares
    actual SplunkHunter alerts against these to compute the gap.
    """
    order: int
    technique_id: str
    technique_name: str
    tactic: str
    description: str = ""
    engine: str = EngineKind.TABLETOP.value
    # Engine-specific payload:
    #   tabletop  → {"event_template": "...", "fields": {...}, "sourcetype": "..."}
    #   atomic    → {"atomic_guid": "..."}  or  {"name": "...", "input_args": {...}}
    #   caldera   → {"ability_id": "..."}
    payload: dict[str, Any] = field(default_factory=dict)
    expected_detections: list[str] = field(default_factory=list)
    cleanup: str = ""                # rollback command/note


@dataclass
class EmulationPlan:
    """Ordered emulation plan for a specific actor."""
    id: str                          # slug, e.g. "apt29_diplomatic"
    actor_id: str
    name: str
    version: str = "1.0"
    description: str = ""
    steps: list[PlanStep] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EmulationPlan":
        steps = [PlanStep(**s) for s in d.get("steps", [])]
        return cls(**{**d, "steps": steps})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EngagementScope:
    """Authorization boundary for a run — checked before every step."""
    customer_id: str
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_subnets: list[str] = field(default_factory=list)
    blocked_techniques: list[str] = field(default_factory=list)   # e.g. ["T1486"] ransomware
    authorized_by: str = ""
    authorization_hash: str = ""                                  # signed sign-off
    starts: str = ""
    ends: str = ""


@dataclass
class ExecutionRecord:
    """Result of running a single PlanStep."""
    run_id: int
    step_idx: int
    technique_id: str
    engine: str
    command: str = ""
    evidence: str = ""            # stdout / event id / agent task id
    ok: bool = True
    error: str = ""
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ended_at: str = ""
