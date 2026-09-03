"""Recursive no-alias immutable JSON views.

The installed engine package and interpreter are the trusted computing base.
Domain immutability prevents data/configuration inputs from replacing trusted
state; it is not a same-process Python-code sandbox.
"""

from __future__ import annotations

import hashlib
import marshal
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import CodeType, MappingProxyType


def code_fingerprint(code: object) -> str:
    """Hash a de-specialized code tree so CPython quickening cannot change it."""

    if type(code) is not CodeType:
        raise TypeError("code fingerprint requires an exact code object")

    def normalize(current: CodeType) -> CodeType:
        constants = tuple(
            normalize(value) if type(value) is CodeType else value
            for value in current.co_consts
        )
        return current.replace(co_consts=constants)

    return hashlib.sha256(marshal.dumps(normalize(code))).hexdigest()


@dataclass(frozen=True, slots=True)
class FrozenMap(Mapping[str, object]):
    """Insertion-order-independent immutable mapping wrapper."""

    _values: Mapping[str, object]

    @classmethod
    def from_dict(cls, values: dict[str, object]) -> FrozenMap:
        return cls(MappingProxyType(dict(values)))

    def __getitem__(self, key: str) -> object:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


def freeze(value: object) -> object:
    """Deep-copy and recursively freeze an exact JSON value."""

    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is list or type(value) is tuple:
        return tuple(freeze(item) for item in value)  # type: ignore[union-attr]
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise TypeError("JSON object keys must be exact strings")
        return FrozenMap.from_dict({key: freeze(item) for key, item in value.items()})
    raise TypeError(f"not an exact JSON value: {type(value).__name__}")


def thaw(value: object) -> object:
    """Create a fresh mutable JSON-compatible copy."""

    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if type(value) is tuple:
        return [thaw(item) for item in value]
    if value is None or type(value) in (bool, int, str):
        return value
    raise TypeError(f"not an immutable JSON value: {type(value).__name__}")
