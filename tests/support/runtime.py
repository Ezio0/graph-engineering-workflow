"""Test-only bootstrap for historical application fixtures."""

import os
import threading

from graph_engineering.application.tasks import (
    RuntimeContext,
    _ISSUED_RUNTIME_CONTEXTS,
)


def runtime_context(
    owner_id: str,
    runtime_kind: str,
    runtime_lineage_id: str,
    actor_id: str,
    occurred_at: str,
    lease_ttl_ns: int,
) -> RuntimeContext:
    runtime = object.__new__(RuntimeContext)
    for field, value in (
        ("owner_id", owner_id), ("runtime_kind", runtime_kind),
        ("runtime_lineage_id", runtime_lineage_id), ("actor_id", actor_id),
        ("occurred_at", occurred_at), ("lease_ttl_ns", lease_ttl_ns),
    ):
        object.__setattr__(runtime, field, value)
    runtime._validate()
    _ISSUED_RUNTIME_CONTEXTS[id(runtime)] = (
        runtime, os.getpid(), threading.get_ident(), lambda: None,
    )
    return runtime
