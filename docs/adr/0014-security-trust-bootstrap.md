# ADR 0014: Security trust bootstrap

Date: 2026-10-08. Status: design under independent review within the exact Owner
approved six-file request r1. Implementation and irreversible authority are absent.

## Context

Report r1 cannot demonstrate genuine R9 positive acceptance because production can
read/validate security trust but cannot initially persist it. SQL fixture insertion
and private issuer seals cannot satisfy R9-T2. The Owner authorized design of an
attested installation initializer and same-owner durable task initializer, with
empty execution authority and replay/mismatch/crash/race oracles.

## Decision

Implement the approved choice as explicit maintenance initialization under existing
installation-exclusive control and a deterministic task service under current
command scope/owned transaction. Load the closed31-member trust resource vector
through actual installation attestation, never caller-supplied maps. Derive task
identity/baselines/frozen scope from bounded durable replay/approval records.
Use the single digest-bound aggregate ProjectScope target; no executable individual
target or authority is created. Initial registries are empty and authority_digests
is empty. Existing schema versions and executable authority transitions remain.

Two closed append-only receipt tables preserve original initialization provenance
alongside an optional security-bootstrap1.0.0 marker. Installation trust+receipt and
task state+receipt each commit atomically. This is an implementation detail of the
approved auditable initialization, not an extra authority ledger for delivery.
Do not repurpose task transaction receipts: those bind task revision/event head;
bootstrap changes no graph revision. Do not add a graph event that existing replay
cannot understand. Same request returns its original receipt after currentness
checks and never resets evolved registries/holds/authority; mismatches or partial
rows refuse. Issuers check new provenance and fresh installation/durable bindings
on every applicable entry point. Legacy unmarked fixtures stay distinguishable.

Migration preserves complete optional receipts as historical origin. Origin tuple
is not destination currentness authority; imported roots need current destination
attestation plus unchanged task/runtime/scope/baseline/resource bindings. Existing
PMF export prohibition persists. No automatic upgrade, repair or baseline refresh.

## Alternatives and consequences

Giving tests a production trust-document setter would defeat genuine provenance.
Calling initializer from every reader would permit silent partial repair. Existing
mutable state alone loses original creation evidence after normal evolution; an
append-only auxiliary receipt retains replay identity without changing task events.
A general authority grant/bootstrap framework is outside this narrow local trust
initializer. New action target registration and reapproval/rebase adaptation remain
separate existing/future authorized paths; initializer cannot authorize execution.

The added receipt namespaces require optional migration validation and resource/
pin closure, frozen in the proposed implementation inventory. A failed invariant
blocks new initialization or issuer use. Legacy resource bytes and PMF/report
contracts remain. No architecture adoption beyond this approved initializer, no
external dependency, Owner install upgrade or real-data rollout is authorized.

## Verification and references

B1-C01–06 require real source/wheel resource/runtime construction, empty initial
authority, durable derivation, exact replay after evolution, faults/races/currentness,
no-PMF migration preservation and genuine report lifecycle. Synthetic typed external
outputs may be supplied; validation/completion/SQL trust/issuer seals may not be
substituted. Tests remain unexecuted during design.

[Spec B1](../specs/graph-engineering-workflow.md#security-trust-bootstrap-design--b1-2026-10-08),
[PRD](../prd/graph-engineering-workflow.md), [Impact](../impact/graph-engineering-workflow.md),
[Plan](../plans/2026-08-13-graph-engineering-workflow.md),
[Test Plan](../test-plans/graph-engineering-workflow.md).
