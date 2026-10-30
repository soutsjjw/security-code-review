# Development Guide for security-code-review Skill

## Build & Test Commands
- Check Environment: `sh scripts/run-python.sh --check`
- Validate Rules Package (rules.json / rules.yaml / schema consistency): `sh scripts/run-python.sh scripts/validate_package.py`
- Regenerate Rule Docs: `python scripts/render_rules_markdown.py --write` after changing `rules.json`; `docs/70-rules-standardized.md` is generated, so never edit it by hand (`validate_package.py` fails when they drift).
- Refresh Package Checksums: `python scripts/package_manifest.py --write` (after `git add` of new files; `--check` verifies, and `validate_package.py` fails on a stale `SHA256SUMS.txt`)
- Run Unit Tests: `python -m unittest discover -s tests -v`
  - The full suite takes ~6 minutes. JSON and `ERROR:` lines in the output are printed by CLI paths under test (blocked / aborted / stalled cases), not failures; check the final `OK` / `FAILED` summary.
- Quality Acceptance: `python scripts/quality_acceptance.py`

## Where Things Live
- `scripts/review_safety.py`: single-agent review gates (staging, integration, snapshot refresh and replay). It never creates or launches sub-agents.
- `scripts/review_snapshot.py`: source inventory hashes, review snapshot, rule scopes and evidence closure, below `review_safety`.
- `scripts/multi_agent_contract.py`, `scripts/multi_agent_guard.py`: multi-agent work contracts and admission gates.
- `scripts/review_core.py` (canonical digest, SHA256, JSON read, snapshot fingerprint), `scripts/scope_paths.py`, `scripts/control_proofs.py`: base layers that must not import upper modules; `tests/test_module_layering.py` enforces this and fails on any import cycle, lazy imports included.
- Shared lower layers per subsystem: `review_waves_state.py` (repair-wave checkpoint state), `partial_review_store.py` (category artifacts), `adversarial_evidence.py` (second-pass evidence), `standard_guides.py` (TACERT / OWASP mappings).
- `scripts/` holds both CLIs and libraries, and many modules are both (documented `scripts/<name>.py` paths are imported elsewhere), so it stays one flat directory. Keep CLI logic inside `main()` behind `if __name__ == "__main__"`; `tests/test_module_layering.py` fails when importing any script prints or exits.
- Patch a function in the module that defines it (for example `review_snapshot.snapshot_errors`, `review_waves_state._load_state`); callers reach those through the module attribute or a call-time import so one patch covers every call site.
- Rule review scope (`local` / `cross_file` / `project`) lives in `inspection.review_scope` of `rules.json` / `rules.yaml` / `rules/*.yaml`; `review_snapshot.rule_scopes()` reads it.
- `scripts/review_waves_abort.py`: quarantine of uncommitted staged batches, including the SHA256-bound legacy staged-only exception and crash recovery.

## Line Endings
- `.gitattributes` enforces LF (`* text=auto eol=lf`), overriding a local `core.autocrlf=true`. After changing it, run `git add --renormalize .` so the working tree matches.
