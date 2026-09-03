# Project Conventions

## Structure

- Positioning: `docs/positioning/`
- Product requirements: `docs/prd/`
- Technical specifications: `docs/specs/`
- Impact analyses: `docs/impact/`
- Architecture decisions: `docs/adr/`
- Plans: `docs/plans/`
- Test plans: `docs/test-plans/`
- Engine code: `core/`
- Configuration: `config/`
- Reusable commands: `scripts/`
- Skills: `skills/`
- Tests: `tests/unit/` and `tests/integration/`

## Naming

- Documentation filenames use kebab-case.
- One feature uses the same basename across Positioning, PRD, Spec, Impact,
  and Test Plan.
- Python engine modules use snake_case.
- Unit tests use `test_<module>.py`.
- Platform adapters use `<platform>_adapter.py` and must not own universal
  graph semantics.

## Data and Logic

Keep graph topology, policy vocabularies, thresholds, platform commands,
paths, and environment values in configuration. Core code contains only
universal graph execution, validation, state reduction, and audit logic.

## Versioning

- Update active product documents in place; Git retains revision history.
- Freeze every human-approved Intent Baseline by content digest.
- A semantic PRD change creates a new baseline version and invalidates affected
  descendants.
