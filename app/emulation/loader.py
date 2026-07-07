"""Load actor + plan YAML files from disk into the database."""
import json
import logging
from pathlib import Path

import yaml

from app import database as db
from app.emulation.models import EmulationPlan, ThreatActor

logger = logging.getLogger(__name__)

BASE = Path(__file__).resolve().parent
ACTORS_DIR = BASE / "actors"
PLANS_DIR  = BASE / "plans"


# ── Actor loading ─────────────────────────────────────────────────────────────

def load_actor_file(path: Path) -> ThreatActor:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return ThreatActor.from_dict(data)


def upsert_actor(actor: ThreatActor):
    conn = db.get_conn()
    conn.execute("""
        INSERT INTO threat_actors (id, name, aliases, sectors, geos, motivation, description, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,
            aliases=excluded.aliases,
            sectors=excluded.sectors,
            geos=excluded.geos,
            motivation=excluded.motivation,
            description=excluded.description,
            source=excluded.source,
            updated_at=datetime('now')
    """, (
        actor.id, actor.name,
        json.dumps(actor.aliases), json.dumps(actor.sectors), json.dumps(actor.geos),
        actor.motivation, actor.description, actor.source,
    ))
    # Replace TTPs wholesale — keeps the set in sync with the YAML source of truth
    conn.execute("DELETE FROM actor_ttps WHERE actor_id = ?", (actor.id,))
    for ttp in actor.ttps:
        conn.execute("""
            INSERT OR IGNORE INTO actor_ttps
                (actor_id, technique_id, technique_name, tactic, sub_technique, tool, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (actor.id, ttp.technique_id, ttp.technique_name, ttp.tactic,
              ttp.sub_technique, ttp.tool, ttp.notes))
    conn.commit()
    logger.info("[EMULATION] Upserted actor %s (%d TTPs)", actor.id, len(actor.ttps))


# ── Plan loading ──────────────────────────────────────────────────────────────

def load_plan_file(path: Path) -> EmulationPlan:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return EmulationPlan.from_dict(data)


def upsert_plan(plan: EmulationPlan):
    conn = db.get_conn()
    conn.execute("""
        INSERT INTO emulation_plans (id, actor_id, name, version, description, steps_json)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            actor_id=excluded.actor_id,
            name=excluded.name,
            version=excluded.version,
            description=excluded.description,
            steps_json=excluded.steps_json
    """, (
        plan.id, plan.actor_id, plan.name, plan.version, plan.description,
        json.dumps([s.__dict__ for s in plan.steps]),
    ))
    conn.commit()
    logger.info("[EMULATION] Upserted plan %s (%d steps)", plan.id, len(plan.steps))


# ── Bulk seed ─────────────────────────────────────────────────────────────────

def seed_from_disk() -> dict:
    """Load every actor + plan YAML shipped with the module. Returns counts."""
    actors_loaded = 0
    plans_loaded  = 0

    if ACTORS_DIR.exists():
        for yml in sorted(ACTORS_DIR.glob("*.yaml")):
            try:
                upsert_actor(load_actor_file(yml))
                actors_loaded += 1
            except Exception as exc:
                logger.error("[EMULATION] Failed to load actor %s: %s", yml.name, exc)

    if PLANS_DIR.exists():
        for yml in sorted(PLANS_DIR.glob("*.yaml")):
            try:
                upsert_plan(load_plan_file(yml))
                plans_loaded += 1
            except Exception as exc:
                logger.error("[EMULATION] Failed to load plan %s: %s", yml.name, exc)

    return {"actors": actors_loaded, "plans": plans_loaded}


# ── Read helpers ──────────────────────────────────────────────────────────────

def get_plan(plan_id: str) -> EmulationPlan | None:
    row = db.get_conn().execute(
        "SELECT id, actor_id, name, version, description, steps_json "
        "FROM emulation_plans WHERE id = ?", (plan_id,)
    ).fetchone()
    if not row:
        return None
    steps = json.loads(row["steps_json"])
    return EmulationPlan.from_dict({
        "id":          row["id"],
        "actor_id":    row["actor_id"],
        "name":        row["name"],
        "version":     row["version"],
        "description": row["description"],
        "steps":       steps,
    })


def list_actors() -> list[dict]:
    rows = db.get_conn().execute(
        "SELECT id, name, aliases, sectors, geos, source FROM threat_actors ORDER BY name"
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        for k in ("aliases", "sectors", "geos"):
            d[k] = json.loads(d[k] or "[]")
        out.append(d)
    return out
