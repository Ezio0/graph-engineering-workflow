# Project Agent Instructions

## Product Boundary

Build a platform-neutral Graph Engineering system for software delivery. Model
specialist Agent Loops as executable nodes, typed state transfer and routing as
edges, and human decisions as explicit graph nodes.

The repository at
`/Users/ezio/Documents/MyProjects/agent-engineering-workflow` is a read-only
reference. Never modify it from this project and never require it at runtime.

## Delivery Boundary

1. Keep Positioning and PRD human-in-the-loop. The agent must ask focused
   questions until material ambiguity is resolved.
2. Do not begin Spec or implementation until the human owner explicitly
   approves the PRD and its Intent Baseline.
3. After PRD approval, automate reversible delivery work. Interrupt the human
   only for intent changes, authority expansion, material architecture choices,
   non-convergence, external blockers, and irreversible actions.
4. Treat commit, push, merge, deployment, release, and external communication
   as separately authorized actions.

## Architecture Rules

- A graph node is an executable Agent Loop or deterministic control node, not
  merely an artifact label.
- Define edges explicitly with typed inputs, routing conditions, trust
  requirements, and invalidation behavior.
- Store graph-wide state durably and make transitions replayable and auditable.
- Keep validation, authority enforcement, digest binding, loop budgets, and
  irreversible gates deterministic.
- Keep platform-neutral semantics in the core. Put Codex, Hermes, OpenClaw,
  and future integrations behind runtime adapters.
- Keep user-specific and environment-specific values in configuration, never
  in engine logic.

## Required Workflow

Read `docs/CONVENTIONS.md` before creating or moving files.

Before implementation, complete and approve:

1. `docs/positioning/graph-engineering-workflow.md`
2. `docs/prd/graph-engineering-workflow.md`
3. `docs/specs/graph-engineering-workflow.md`
4. `docs/impact/graph-engineering-workflow.md`
5. Any required ADRs
6. An implementation plan and test plan

No tests means not done. Require independent review of routine artifacts and
Candidate evidence before requesting irreversible authority.
