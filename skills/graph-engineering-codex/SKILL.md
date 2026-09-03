---
name: graph-engineering-codex
description: Continue an approved Graph Engineering delivery from a Codex owner turn. Use for discovery, task creation, clarification, approval, run, status, recovery, escalation, and result presentation through the installed local runtime adapter.
---

# Graph Engineering Codex

Treat the installed application as the only source of graph truth and mutation authority.

1. Ask the Codex runtime adapter for the owner-bound locator and runtime lineage.
2. Use only the verified canonical executable returned by that adapter. Never search `PATH` or a source checkout.
3. Run its `capabilities --format json` handshake with the configured locator and runtime record before any task mutation.
4. Stop on an incompatible version, missing capability, owner mismatch, or lineage mismatch. Present only the non-disclosing rejection returned by the application.
5. Submit one versioned, self-digested `owner-flow` envelope per owner turn. Choose exactly one operation from `discover`, `create`, `clarify`, `approve`, `run`, `status`, `resume`, `escalate`, or `result`; use the returned durable task ID for later turns.
6. Present the typed result and exit code returned by the application without interpreting either as a completion decision.

Do not keep work running after the Codex turn exits. Resume only through a fresh handshake on the same owner and lineage.
