# Development Guide for security-code-review Skill

## Build & Test Commands
- Check Environment: `sh scripts/run-python.sh --check`
- Validate Rules Package (rules.json / rules.yaml / schema consistency): `sh scripts/run-python.sh scripts/validate_package.py`
- Run Unit Tests: `python -m unittest discover -s tests -v`
  - The full suite takes ~6 minutes. JSON and `ERROR:` lines in the output are printed by CLI paths under test (blocked / aborted / stalled cases), not failures; check the final `OK` / `FAILED` summary.
- Quality Acceptance: `python scripts/quality_acceptance.py`

## Where Things Live
- `scripts/review_safety.py`: single-agent review gates (source snapshot, rule ownership, evidence closure, staged integration and replay). It never creates or launches sub-agents.
- `scripts/multi_agent_contract.py`, `scripts/multi_agent_guard.py`: multi-agent work contracts and admission gates.
- `scripts/review_waves_abort.py`: quarantine of uncommitted staged batches, including the SHA256-bound legacy staged-only exception and crash recovery.

## Line Endings
- `.gitattributes` enforces LF (`* text=auto eol=lf`), overriding a local `core.autocrlf=true`. After changing it, run `git add --renormalize .` so the working tree matches.
