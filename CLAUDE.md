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
- `scripts/lib/review_safety.py`: single-agent review gates (staging, integration, snapshot refresh and replay). It never creates or launches sub-agents.
- `scripts/lib/review_snapshot.py`: source inventory hashes, review snapshot, rule scopes and evidence closure, below `review_safety`.
- `scripts/lib/multi_agent_contract.py`, `scripts/lib/multi_agent_guard.py`: multi-agent work contracts and admission gates.
- `scripts/lib/review_core.py` (canonical digest, SHA256, JSON read, snapshot fingerprint), `scripts/lib/scope_paths.py`, `scripts/lib/control_proofs.py`: base layers that must not import upper modules; `tests/test_module_layering.py` enforces this and fails on any import cycle, lazy imports included.
- Shared lower layers per subsystem: `review_waves_state.py` (repair-wave checkpoint state), `partial_review_store.py` (category artifacts), `adversarial_evidence.py` (second-pass evidence), `standard_guides.py` (TACERT / OWASP mappings), `multi_agent_ledger.py` (multi-agent ledger state; `multi_agent_planning.py` and `multi_agent_workers.py` sit above it, `multi_agent.py` is only the CLI and re-exports).
- `rule_guidance.py` builds the per-rule standards mappings, adjudication guidance and `standard_documents` for both `review_queue.py` and `partial_review.py`; `partial_review_cli.py` runs `review_queue.py --categories`.
- All code lives in `scripts/lib/`. Each `scripts/<name>.py` is a thin wrapper that runs `scripts/lib/<name>.py` as `__main__`, so documented CLI paths stay stable; only the launcher helper `scripts/check_python_env.py` is real code there. Tests and modules import from `scripts/lib` by bare module name.
- A lib module with `if __name__ == "__main__"` needs a matching wrapper (and vice versa), and its CLI logic stays inside `main()`; `tests/test_module_layering.py` enforces both and fails when importing any lib module prints or exits.
- Patch a function in the module that defines it (for example `review_snapshot.snapshot_errors`, `review_waves_state._load_state`); callers reach those through the module attribute or a call-time import so one patch covers every call site.
- Rule review scope (`local` / `cross_file` / `project`) lives in `inspection.review_scope` of `rules.json` / `rules.yaml` / `rules/*.yaml`; `review_snapshot.rule_scopes()` reads it.
- Review rigor (`high` / `standard`) lives in `inspection.review_tier` and is read through `review_snapshot.rule_tiers()` / `high_tier_rules()`. It drives second-pass hypothesis counts, incremental verification order and repair-wave sampling strata; never hard-code rule ID or category-prefix risk lists. It is unrelated to finding severity, which stays `not_preassigned`.
- `scripts/lib/review_waves_abort.py`: quarantine of uncommitted staged batches, including the SHA256-bound legacy staged-only exception and crash recovery.

## Line Endings
- `.gitattributes` enforces LF (`* text=auto eol=lf`), overriding a local `core.autocrlf=true`. After changing it, run `git add --renormalize .` so the working tree matches.
