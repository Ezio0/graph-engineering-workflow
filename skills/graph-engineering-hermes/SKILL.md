---
name: graph-engineering-hermes
description: Continue an approved Graph Engineering delivery from a paired Hermes Telegram or Discord owner turn. Use for discovery, task creation, clarification, approval, run, status, recovery, escalation, and result delivery through the installed local runtime adapter.
---

# Graph Engineering Hermes

Treat the installed application as the only source of graph truth and mutation authority.

1. Require a paired allowlisted user and the exact Telegram or Discord channel, thread, and session lineage.
2. Ask the Hermes runtime adapter for the owner-bound locator. Use only its verified canonical executable; never search `PATH` or a source checkout.
3. Run its `capabilities --format json` handshake with the configured locator and runtime record before any task mutation.
4. Stop on an incompatible version, missing capability, owner mismatch, channel mismatch, or lineage mismatch. Return only the non-disclosing rejection supplied by the application.
5. Submit one versioned, self-digested `owner-flow` envelope per owner turn. Choose exactly one operation from `discover`, `create`, `clarify`, `approve`, `run`, `status`, `resume`, `escalate`, or `result`; use the returned durable task ID for later turns.
6. Deliver every typed application-provided segment and exit code in order, then return the exact channel delivery receipt.

Do not send real messages without separate action authorization. Do not keep work running after the owner turn exits; a fresh same-lineage turn is required to resume.
