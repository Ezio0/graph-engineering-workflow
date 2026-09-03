"""Explicit dependency index, minimal invalidation, and drift classification."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST


class InvalidationError(ValueError):
    """Invalid dependency graph or invalidation request."""


class DriftClass(str, Enum):
    INTENT = "intent"
    AUTHORITY = "authority"
    CONTROL = "control"
    DEPENDENCY = "dependency"
    METADATA_ONLY = "metadata-only"


@dataclass(frozen=True, slots=True)
class DependencyRecord:
    ref_id: str
    ref_kind: str
    content_digest: str
    input_refs: tuple[str, ...]
    input_digests: Mapping[str, str]
    baseline_digests: Mapping[str, str]
    graph_version: str
    profile_version: str
    policy_version: str
    producer_run_ref: str
    validation_record_refs: tuple[str, ...]
    review_record_refs: tuple[str, ...]
    semantic_tags: tuple[str, ...]
    freshness_policy_ref: str
    status: str
    has_external_effect: bool

    def __post_init__(self) -> None:
        string_fields = (
            self.ref_id, self.ref_kind, self.graph_version,
            self.profile_version, self.policy_version, self.producer_run_ref,
            self.freshness_policy_ref, self.status,
        )
        if any(type(item) is not str or not item for item in string_fields):
            raise InvalidationError("invalid dependency record")
        if type(self.content_digest) is not str or SEMANTIC_DIGEST.fullmatch(self.content_digest) is None:
            raise InvalidationError("invalid dependency content digest")
        for name in ("input_refs", "validation_record_refs", "review_record_refs", "semantic_tags"):
            values = getattr(self, name)
            if (
                type(values) is not tuple
                or any(type(item) is not str or not item for item in values)
                or len(values) != len(set(values))
            ):
                raise InvalidationError(f"invalid {name}")
        frozen_maps: dict[str, Mapping[str, str]] = {}
        for name in ("input_digests", "baseline_digests"):
            raw = getattr(self, name)
            if (
                not isinstance(raw, Mapping)
                or any(
                    type(key) is not str
                    or not key
                    or type(value) is not str
                    or SEMANTIC_DIGEST.fullmatch(value) is None
                    for key, value in raw.items()
                )
            ):
                raise InvalidationError(f"invalid {name}")
            frozen_maps[name] = MappingProxyType(dict(raw))
        if set(frozen_maps["input_digests"]) != set(self.input_refs):
            raise InvalidationError("input refs and digests do not bind the same dependencies")
        object.__setattr__(self, "input_digests", frozen_maps["input_digests"])
        object.__setattr__(self, "baseline_digests", frozen_maps["baseline_digests"])
        if type(self.has_external_effect) is not bool:
            raise InvalidationError("external-effect flag must be boolean")


@dataclass(frozen=True, slots=True)
class InvalidationRecord:
    ref_id: str
    epoch: int
    reason: str
    previous_status: str
    action: str


@dataclass(frozen=True, slots=True, init=False)
class DependencyIndex:
    records: Mapping[str, DependencyRecord]
    descendants: Mapping[str, tuple[str, ...]]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("DependencyIndex must be built from validated records")

    @classmethod
    def build(cls, records: Iterable[DependencyRecord]) -> DependencyIndex:
        values: dict[str, DependencyRecord] = {}
        for record in records:
            if type(record) is not DependencyRecord:
                raise InvalidationError("dependency index requires exact records")
            if record.ref_id in values:
                raise InvalidationError("duplicate dependency identity")
            values[record.ref_id] = record
        for record in values.values():
            unknown = set(record.input_refs) - set(values)
            if unknown:
                raise InvalidationError(f"unknown dependency refs: {','.join(sorted(unknown))}")
            mismatched = sorted(
                ref_id for ref_id, digest in record.input_digests.items()
                if values[ref_id].content_digest != digest
            )
            if mismatched:
                raise InvalidationError(f"input dependency digest mismatch: {','.join(mismatched)}")
        children: dict[str, set[str]] = {ref_id: set() for ref_id in values}
        for record in values.values():
            for source in record.input_refs:
                children[source].add(record.ref_id)
        visiting: set[str] = set()
        visited: set[str] = set()

        def check(ref_id: str) -> None:
            if ref_id in visiting:
                raise InvalidationError("dependency cycle")
            if ref_id in visited:
                return
            visiting.add(ref_id)
            for child in sorted(children[ref_id]):
                check(child)
            visiting.remove(ref_id)
            visited.add(ref_id)

        for ref_id in sorted(values):
            check(ref_id)
        result = object.__new__(DependencyIndex)
        object.__setattr__(result, "records", MappingProxyType(dict(values)))
        object.__setattr__(result, "descendants", MappingProxyType({key: tuple(sorted(item)) for key, item in children.items()}))
        return result

    def _propagate(
        self,
        roots: tuple[str, ...],
        *,
        epoch: int,
        reason: str,
    ) -> tuple[InvalidationRecord, ...]:
        if type(epoch) is not int or epoch < 1 or type(reason) is not str or not reason:
            raise InvalidationError("invalid invalidation identity")
        if len(roots) != len(set(roots)):
            raise InvalidationError("duplicate invalidation roots")
        unknown = set(roots) - set(self.records)
        if unknown:
            raise InvalidationError(f"unknown invalidation refs: {','.join(sorted(unknown))}")
        affected = set(roots)
        pending = list(roots)
        while pending:
            current = pending.pop()
            for child in self.descendants[current]:
                if child not in affected:
                    affected.add(child)
                    pending.append(child)
        records = []
        for ref_id in sorted(affected):
            record = self.records[ref_id]
            action = "reconcile" if record.has_external_effect else "invalidate"
            records.append(InvalidationRecord(ref_id, epoch, reason, record.status, action))
        return tuple(records)

    def invalidate(self, changed_refs: Iterable[str], *, epoch: int, reason: str) -> tuple[InvalidationRecord, ...]:
        return self._propagate(tuple(changed_refs), epoch=epoch, reason=reason)

    def invalidate_changed_inputs(
        self,
        current_digests: Mapping[str, str],
        *,
        epoch: int,
        reason: str,
    ) -> tuple[InvalidationRecord, ...]:
        if (
            not isinstance(current_digests, Mapping)
            or any(
                type(ref_id) is not str
                or not ref_id
                or type(digest) is not str
                or SEMANTIC_DIGEST.fullmatch(digest) is None
                for ref_id, digest in current_digests.items()
            )
        ):
            raise InvalidationError("invalid current input digests")
        unknown = set(current_digests) - set(self.records)
        if unknown:
            raise InvalidationError(f"unknown invalidation refs: {','.join(sorted(unknown))}")
        roots = tuple(sorted(
            ref_id for ref_id, digest in current_digests.items()
            if self.records[ref_id].content_digest != digest
        ))
        return self._propagate(roots, epoch=epoch, reason=reason)

    def invalidate_baselines(
        self,
        current_baseline_digests: Mapping[str, str],
        *,
        epoch: int,
        reason: str,
    ) -> tuple[InvalidationRecord, ...]:
        if (
            not isinstance(current_baseline_digests, Mapping)
            or not current_baseline_digests
            or any(
                type(kind) is not str
                or not kind
                or type(digest) is not str
                or SEMANTIC_DIGEST.fullmatch(digest) is None
                for kind, digest in current_baseline_digests.items()
            )
        ):
            raise InvalidationError("invalid current baseline digests")
        current = dict(current_baseline_digests)
        roots = tuple(sorted(
            ref_id for ref_id, record in self.records.items()
            if dict(record.baseline_digests) != current
        ))
        return self._propagate(roots, epoch=epoch, reason=reason)

    def invalidate_control_versions(
        self,
        *,
        graph_version: str,
        profile_version: str,
        policy_version: str,
        epoch: int,
        reason: str,
    ) -> tuple[InvalidationRecord, ...]:
        if any(type(item) is not str or not item for item in (graph_version, profile_version, policy_version)):
            raise InvalidationError("invalid current control versions")
        roots = tuple(sorted(
            ref_id for ref_id, record in self.records.items()
            if (
                record.graph_version != graph_version
                or record.profile_version != profile_version
                or record.policy_version != policy_version
            )
        ))
        return self._propagate(roots, epoch=epoch, reason=reason)


DRIFT_KINDS = MappingProxyType({
    "baseline": DriftClass.INTENT,
    "project_scope": DriftClass.INTENT,
    "authority": DriftClass.AUTHORITY,
    "graph": DriftClass.CONTROL,
    "profile": DriftClass.CONTROL,
    "policy": DriftClass.CONTROL,
    "artifact": DriftClass.DEPENDENCY,
    "evidence": DriftClass.DEPENDENCY,
})


def classify_drift(kind: str, previous_digest: str, current_digest: str) -> DriftClass:
    if kind not in DRIFT_KINDS:
        raise InvalidationError("unknown drift kind")
    if (
        type(previous_digest) is not str
        or SEMANTIC_DIGEST.fullmatch(previous_digest) is None
        or type(current_digest) is not str
        or SEMANTIC_DIGEST.fullmatch(current_digest) is None
    ):
        raise InvalidationError("drift digests must use the semantic digest grammar")
    if previous_digest == current_digest:
        return DriftClass.METADATA_ONLY
    return DRIFT_KINDS[kind]
