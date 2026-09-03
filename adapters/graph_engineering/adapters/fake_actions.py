"""Deterministic test-double target; never a production external adapter."""

from __future__ import annotations

import copy
from collections.abc import Mapping


class FakeTargetTimeout(TimeoutError):
    pass


class DeterministicFakeObserver:
    """Separate read-only test-double port over the fake target's backing state."""

    is_test_double = True
    is_read_only_observer = True

    def __init__(self, target: DeterministicFakeTarget) -> None:
        self._target = target
        self.target_id = target.target_id
        self.target_digest = target.target_digest
        self.resource_id = target.resource_id
        self.capabilities = ("deterministic-fake-observer-v1", "fresh-target-query")
        self.query_count = 0

    def observe(self) -> dict[str, object]:
        self.query_count += 1
        if self._target.failure_mode == "query-unverifiable":
            raise ValueError("target state is unverifiable")
        return {
            "target_id": self.target_id,
            "target_digest": self.target_digest,
            "resource_id": self.resource_id,
            "fresh": self._target.failure_mode != "stale-query",
            "observation_revision": self.query_count,
            "state": copy.deepcopy(self._target._state),
        }


class DeterministicFakeTarget:
    is_test_double = True

    def __init__(
        self,
        *,
        target_id: str,
        target_digest: str,
        resource_id: str,
        initial_state: Mapping[str, object],
        capabilities: tuple[str, ...] | None = None,
        failure_mode: str | None = None,
    ) -> None:
        self.target_id = target_id
        self.target_digest = target_digest
        self.resource_id = resource_id
        self.capabilities = capabilities or (
            "deterministic-fake-target-v1",
            "fresh-target-query",
            "fake-compensation",
        )
        self.failure_mode = failure_mode
        self._state = copy.deepcopy(dict(initial_state))
        self.call_count = 0
        self.query_count = 0
        self.started_was_durable = False

    def observe(self) -> dict[str, object]:
        self.query_count += 1
        if self.failure_mode == "query-unverifiable":
            raise ValueError("target state is unverifiable")
        return {
            "target_id": self.target_id,
            "target_digest": self.target_digest,
            "resource_id": self.resource_id,
            "fresh": True,
            "observation_revision": self.query_count,
            "state": copy.deepcopy(self._state),
        }

    def observer_port(self) -> DeterministicFakeObserver:
        return DeterministicFakeObserver(self)

    def invoke(self, *, payload: Mapping[str, object], fencing_token: int, started_was_durable: bool) -> dict[str, object]:
        self.call_count += 1
        self.started_was_durable = started_was_durable
        if not started_was_durable:
            raise AssertionError("fake tool observed a call before durable started+claim")
        if type(fencing_token) is not int or fencing_token <= 0:
            raise ValueError("fake target requires a current positive fence")
        if self.failure_mode == "failure-before-effect":
            return {"result": "failed", "effect": "none"}
        if self.failure_mode == "success-without-effect":
            return {"result": "succeeded", "effect": "none"}
        requested = payload.get("set")
        if not isinstance(requested, Mapping):
            raise ValueError("fake action payload is invalid")
        self._state = copy.deepcopy(dict(requested))
        if self.failure_mode == "timeout-after-effect":
            raise FakeTargetTimeout("deterministic timeout after effect")
        if self.failure_mode == "crash-after-effect":
            raise RuntimeError("deterministic crash after effect")
        return {"result": "succeeded", "effect": "applied", "state": copy.deepcopy(self._state)}
