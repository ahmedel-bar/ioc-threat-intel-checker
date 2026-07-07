# Cerebrum — siem-intel

## User Preferences
- User asks broad "fix everything" prompts — implement all identified issues in one pass without asking for approval of individual items.

## Key Learnings
- Project public name is **Vigilant** (tagline: "Always Watching, Always Protecting"). Use this on title/closing slides instead of "siem-intel".
- P.pptx (12 slides) uses named shapes (`CardAText`, `TextBox 13`, `Text 5`, etc.) — edit by shape.name, not index. Slide 7 is image-only (no text); slide 8 has an architecture diagram image overlapping its body text frame — leave that frame empty to avoid overlap.
- When editing PPTX text via python-pptx, preserve formatting by overwriting `tf.paragraphs[0].runs[0].text` and pruning later runs/paragraphs — assigning `tf.text` directly drops fonts/colors.
- `SECRET_KEY` warning already implemented in `app/__init__.py` — don't add it again elsewhere.
- `VTBroker._reset_if_new_day()` is correctly locked: `today` is a local variable computed before lock acquisition; `self._day` comparison happens inside the lock. Pattern is correct.
- Config class reads all env vars at import time — `.env` changes require server restart to take effect. This is by design.
- `db.tx()` context manager is the standard for DB writes in this codebase — use it instead of calling `db.get_conn()` directly for mutations.
- Feed sync uses `executemany` + single commit with row-by-row fallback for resilience. Don't revert to per-row-commit loops.
- `datetime.utcnow()` is deprecated in Python 3.12+ — always use `datetime.now(timezone.utc)` in this project.

## Do-Not-Repeat
- [2026-06-15] Don't add a SECRET_KEY warning to run.py or pipeline.py — it already exists in app/__init__.py.
- [2026-06-15] Don't use `db.get_conn().execute()` + `db.get_conn().commit()` as two separate calls for writes — use `with db.tx() as conn:` instead.
- [2026-06-15] Don't use `datetime.utcnow()` — deprecated. Use `datetime.now(timezone.utc)`.

## Decision Log
- [2026-06-15] `_bulk_insert` uses `executemany` with single commit + row-by-row fallback. Batch path is the fast path; fallback handles rare malformed rows from feeds without dropping the entire batch.
