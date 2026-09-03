"""GEW JCS Input Profile canonicalization."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from graph_engineering.core.contracts.resources import WorkContext


MAX_SAFE_INTEGER = 9_007_199_254_740_991
MIN_SAFE_INTEGER = -MAX_SAFE_INTEGER


def _validate_scalar_text(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError("lone surrogate is not an I-JSON scalar")


def _quote(value: str) -> str:
    _validate_scalar_text(value)
    pieces = ['"']
    short = {"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}
    for character in value:
        code = ord(character)
        if character == '"':
            pieces.append('\\"')
        elif character == "\\":
            pieces.append("\\\\")
        elif character in short:
            pieces.append(short[character])
        elif code <= 0x1F:
            pieces.append(f"\\u{code:04x}")
        else:
            pieces.append(character)
    pieces.append('"')
    return "".join(pieces)


def _key_order(value: str) -> bytes:
    _validate_scalar_text(value)
    return value.encode("utf-16-be")


def _encode(value: object) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        if not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError("integer is outside the GEW safe range")
        return str(value)
    if type(value) is str:
        return _quote(value)
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise TypeError("JSON object keys must be exact strings")
        ordered = sorted(value, key=_key_order)
        return "{" + ",".join(f"{_quote(key)}:{_encode(value[key])}" for key in ordered) + "}"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, memoryview)):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    raise TypeError(f"unsupported JSON value type: {type(value).__name__}")


def canonical_text(value: object) -> str:
    """Return canonical JSON text for the integer-only GEW JCS profile."""

    return _encode(value)


def canonical_bytes(value: object) -> bytes:
    """Return canonical UTF-8 bytes for the integer-only GEW JCS profile."""

    return canonical_text(value).encode("utf-8")


def canonical_byte_length(value: object) -> int:
    """Return exact canonical byte length without materializing the document."""

    if value is None:
        return 4
    if type(value) is bool:
        return 4 if value else 5
    if type(value) is int:
        if not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError("integer is outside the GEW safe range")
        return len(str(value))
    if type(value) is str:
        total = 2
        for character in value:
            _validate_scalar_text(character)
            code = ord(character)
            if character in {'"', "\\", "\b", "\t", "\n", "\f", "\r"}:
                total += 2
            elif code <= 0x1F:
                total += 6
            else:
                total += len(character.encode("utf-8"))
        return total
    if isinstance(value, Mapping):
        return 2 + max(0, len(value) - 1) + sum(
            canonical_byte_length(key) + 1 + canonical_byte_length(item)
            for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, memoryview)):
        return 2 + max(0, len(value) - 1) + sum(canonical_byte_length(item) for item in value)
    raise TypeError(f"unsupported JSON value type: {type(value).__name__}")


def _quoted_chunks(value: str) -> Iterator[bytes]:
    _validate_scalar_text(value)
    yield b'"'
    short = {"\b": b"\\b", "\t": b"\\t", "\n": b"\\n", "\f": b"\\f", "\r": b"\\r"}
    for character in value:
        code = ord(character)
        if character == '"':
            yield b'\\"'
        elif character == "\\":
            yield b"\\\\"
        elif character in short:
            yield short[character]
        elif code <= 0x1F:
            yield f"\\u{code:04x}".encode()
        else:
            yield character.encode("utf-8")
    yield b'"'


def _encoded_chunks(
    value: object,
    context: WorkContext,
    *,
    source_id: str,
    operation_path: tuple[int, ...],
) -> Iterator[bytes]:
    if value is None:
        yield b"null"
        return
    if type(value) is bool:
        yield b"true" if value else b"false"
        return
    if type(value) is int:
        if not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError("integer is outside the GEW safe range")
        yield str(value).encode()
        return
    if type(value) is str:
        yield from _quoted_chunks(value)
        return
    if isinstance(value, Mapping):
        context.acquire_temporary(len(value), source_id=source_id, operation_path=operation_path)
        try:
            ordered = sorted(value, key=_key_order)
        finally:
            context.release_temporary(len(value))
        yield b"{"
        for index, key in enumerate(ordered):
            if index:
                yield b","
            yield from _quoted_chunks(key)
            yield b":"
            yield from _encoded_chunks(value[key], context, source_id=source_id, operation_path=operation_path)
        yield b"}"
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, memoryview)):
        yield b"["
        for index, item in enumerate(value):
            if index:
                yield b","
            yield from _encoded_chunks(item, context, source_id=source_id, operation_path=operation_path)
        yield b"]"
        return
    raise TypeError(f"unsupported JSON value type: {type(value).__name__}")


def canonicalize(
    value: object,
    context: WorkContext,
    *,
    source_id: str,
    operation_path: tuple[int, ...] = (),
) -> bytes:
    """Canonicalize and charge the complete ADR-0003 measure in fixed order."""

    from graph_engineering.core.contracts.resources import bounded_measure

    measured = bounded_measure(value, context, source_id=source_id, operation_path=operation_path)
    for event_id, count in (
        ("canonical.value", measured.nodes),
        ("canonical.member", measured.members),
        ("canonical.item", measured.items),
        ("canonical.string_scalar", measured.string_scalars),
    ):
        context.emit(event_id, count, operation_path=operation_path, source_id=source_id)
    body = bytearray()
    buffer_units = 0
    try:
        for chunk in _encoded_chunks(value, context, source_id=source_id, operation_path=operation_path):
            for byte in chunk:
                context.acquire_temporary(1, source_id=source_id, operation_path=operation_path)
                buffer_units += 1
                context.emit("canonical.output_byte", 1, operation_path=operation_path, source_id=source_id)
                body.append(byte)
        return bytes(body)
    finally:
        context.release_temporary(buffer_units)
