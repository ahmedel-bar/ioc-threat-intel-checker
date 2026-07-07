"""SQLite schema for the emulation module.

Lives in a separate `init_emulation_schema()` call rather than polluting
`app/database.py`, so the module is self-contained and can be disabled by
simply not calling the initializer.
"""
import logging
import sqlite3

from app import database as db

logger = logging.getLogger(__name__)


def init_emulation_schema():
    """Create emulation tables if absent. Safe to call repeatedly."""
    conn = db.get_conn()
    conn.executescript("""
        -- ── Actor knowledge base ──────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS threat_actors (
            id           TEXT PRIMARY KEY,           -- slug, e.g. 'apt29'
            name         TEXT NOT NULL,              -- canonical name
            aliases      TEXT DEFAULT '[]',          -- JSON array
            sectors      TEXT DEFAULT '[]',          -- JSON array
            geos         TEXT DEFAULT '[]',          -- JSON array
            motivation   TEXT DEFAULT '',
            description  TEXT DEFAULT '',
            source       TEXT DEFAULT 'MITRE ATT&CK',
            updated_at   TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS actor_ttps (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id       TEXT NOT NULL,
            technique_id   TEXT NOT NULL,            -- e.g. 'T1059.001'
            technique_name TEXT NOT NULL,
            tactic         TEXT NOT NULL,
            sub_technique  TEXT DEFAULT '',
            tool           TEXT DEFAULT '',
            notes          TEXT DEFAULT '',
            UNIQUE(actor_id, technique_id),
            FOREIGN KEY(actor_id) REFERENCES threat_actors(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_actor_ttp_tech ON actor_ttps(technique_id);
        CREATE INDEX IF NOT EXISTS idx_actor_ttp_actor ON actor_ttps(actor_id);

        -- ── Emulation plans (ordered TTPs per actor) ──────────────────────────
        CREATE TABLE IF NOT EXISTS emulation_plans (
            id          TEXT PRIMARY KEY,            -- slug, e.g. 'apt29_diplomatic'
            actor_id    TEXT NOT NULL,
            name        TEXT NOT NULL,
            version     TEXT DEFAULT '1.0',
            description TEXT DEFAULT '',
            steps_json  TEXT NOT NULL DEFAULT '[]',  -- serialized list[PlanStep]
            created_at  TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(actor_id) REFERENCES threat_actors(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_plan_actor ON emulation_plans(actor_id);

        -- ── Runs (an execution of a plan against a customer) ──────────────────
        CREATE TABLE IF NOT EXISTS emulation_runs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_id       TEXT NOT NULL,
            customer_id   TEXT NOT NULL,
            engine        TEXT NOT NULL,             -- tabletop|atomic|caldera
            scope_json    TEXT NOT NULL DEFAULT '{}',
            status        TEXT NOT NULL DEFAULT 'PENDING',
            started_at    TEXT,
            ended_at      TEXT,
            authorized_by TEXT DEFAULT '',
            auth_hash     TEXT DEFAULT '',
            created_at    TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(plan_id) REFERENCES emulation_plans(id)
        );

        CREATE INDEX IF NOT EXISTS idx_run_status ON emulation_runs(status);
        CREATE INDEX IF NOT EXISTS idx_run_customer ON emulation_runs(customer_id, created_at);

        -- ── Per-step execution evidence ───────────────────────────────────────
        CREATE TABLE IF NOT EXISTS execution_records (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id        INTEGER NOT NULL,
            step_idx      INTEGER NOT NULL,
            technique_id  TEXT NOT NULL,
            engine        TEXT NOT NULL,
            command       TEXT DEFAULT '',
            evidence      TEXT DEFAULT '',
            ok            INTEGER DEFAULT 1,
            error         TEXT DEFAULT '',
            started_at    TEXT DEFAULT (datetime('now')),
            ended_at      TEXT,
            FOREIGN KEY(run_id) REFERENCES emulation_runs(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_exec_run ON execution_records(run_id);

        -- ── Detection validation (purple-team loop) ───────────────────────────
        CREATE TABLE IF NOT EXISTS detection_validations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id       INTEGER NOT NULL,
            expected_query  TEXT NOT NULL,           -- SPL or detection name
            detected        INTEGER DEFAULT 0,       -- 0 = miss, 1 = caught
            matched_alert_id INTEGER,                -- FK to alerts.id (loose; alerts may be pruned)
            gap_notes       TEXT DEFAULT '',
            checked_at      TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(record_id) REFERENCES execution_records(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_validation_record ON detection_validations(record_id);
        CREATE INDEX IF NOT EXISTS idx_validation_detected ON detection_validations(detected);
    """)
    conn.commit()
    logger.info("[EMULATION] Schema initialized")


def reset_emulation_schema():
    """DROP and recreate all emulation tables. Destructive — dev/test only."""
    conn = db.get_conn()
    for tbl in (
        "detection_validations",
        "execution_records",
        "emulation_runs",
        "emulation_plans",
        "actor_ttps",
        "threat_actors",
    ):
        try:
            conn.execute(f"DROP TABLE IF EXISTS {tbl}")
        except sqlite3.OperationalError as exc:
            logger.warning("[EMULATION] Drop %s failed: %s", tbl, exc)
    conn.commit()
    init_emulation_schema()
