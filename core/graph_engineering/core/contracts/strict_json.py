"""Strict UTF-8/I-JSON parser for the GEW integer-only input profile."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import TYPE_CHECKING

from graph_engineering.core.contracts.canonical import MAX_SAFE_INTEGER, MIN_SAFE_INTEGER

if TYPE_CHECKING:
    from graph_engineering.core.contracts.resources import WorkContext


INTEGER_TOKEN = re.compile(r"0|-?[1-9][0-9]*\Z")


def _integer(token: str) -> int:
    if not INTEGER_TOKEN.fullmatch(token) or token == "-0":
        raise ValueError("non-canonical JSON integer")
    value = int(token)
    if not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        raise ValueError("JSON integer outside GEW safe range")
    return value


def _reject_number(token: str) -> object:
    raise ValueError(f"unsupported JSON number token: {token}")


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _validate_scalars(value: object) -> None:
    if type(value) is str:
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ValueError("lone surrogate is not an I-JSON scalar")
    elif isinstance(value, list):
        for item in value:
            _validate_scalars(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _validate_scalars(key)
            _validate_scalars(item)


def _tokens(text: str) -> Iterator[tuple[str, str | None, int]]:
    index = 0
    while index < len(text):
        character = text[index]
        if character in " \t\r\n":
            index += 1
            continue
        if character in "{}[]:,":
            yield character, None, len(character.encode("utf-8"))
            index += 1
            continue
        if character == '"':
            end = index + 1
            escaped = False
            while end < len(text):
                current = text[end]
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    break
                end += 1
            if end >= len(text):
                raise ValueError("unterminated JSON string")
            raw = text[index:end + 1]
            decoded = json.loads(raw)
            if type(decoded) is not str or any(0xD800 <= ord(item) <= 0xDFFF for item in decoded):
                raise ValueError("invalid I-JSON string token")
            yield "string", raw, len(raw.encode("utf-8"))
            index = end + 1
            continue
        end = index
        while end < len(text) and text[end] not in "{}[]:, \t\r\n":
            end += 1
        if end == index:
            raise ValueError("invalid JSON lexical unit")
        raw_scalar = text[index:end]
        if raw_scalar not in {"true", "false", "null"}:
            _integer(raw_scalar)
        yield "scalar", raw_scalar, len(raw_scalar.encode("utf-8"))
        index = end


def _charge_parse(
    raw_body: bytes,
    text: str,
    context: WorkContext,
    source_id: str,
    operation_path: tuple[int, ...],
) -> int:
    context.check_limit("raw_document_bytes", len(raw_body), source_id=source_id)
    for _ in raw_body:
        context.emit("parse.input_byte", 1, operation_path=operation_path, source_id=source_id)
    stack: list[dict[str, object]] = []
    token_count = 0
    property_count = 0
    item_count = 0
    scalar_count = 0
    unattached_units = 0
    try:
        for token, token_text, raw_token_bytes in _tokens(text):
            if stack and stack[-1]["kind"] == "array" and stack[-1]["expecting"] and token != "]":
                item_count += 1
                context.check_limit("array_items", item_count, source_id=source_id)
                context.acquire_temporary(1, source_id=source_id, operation_path=operation_path)
                stack[-1]["held"] = int(stack[-1]["held"]) + 1
                context.emit("parse.item", 1, operation_path=operation_path, source_id=source_id)
                stack[-1]["expecting"] = False
            token_count += 1
            context.check_limit("parse_tokens", token_count, source_id=source_id)
            context.emit("parse.token", 1, operation_path=operation_path, source_id=source_id)
            if token in "{[":
                context.check_limit("parse_depth", len(stack) + 1, source_id=source_id)
                context.acquire_temporary(1, source_id=source_id, operation_path=operation_path)
                context.emit("parse.container", 1, operation_path=operation_path, source_id=source_id)
                stack.append({"kind": "object" if token == "{" else "array", "expecting": token == "[", "held": 1})
            elif token in "}]":
                if stack:
                    frame = stack.pop()
                    context.release_temporary(int(frame["held"]))
            elif token == ":":
                property_count += 1
                context.check_limit("object_properties", property_count, source_id=source_id)
                context.acquire_temporary(2, source_id=source_id, operation_path=operation_path)
                if stack:
                    stack[-1]["held"] = int(stack[-1]["held"]) + 2
                else:
                    unattached_units += 2
                context.emit("parse.member", 1, operation_path=operation_path, source_id=source_id)
            elif token == "," and stack and stack[-1]["kind"] == "array":
                stack[-1]["expecting"] = True
            elif token == "string" and token_text is not None:
                context.acquire_temporary(raw_token_bytes, source_id=source_id, operation_path=operation_path)
                try:
                    decoded = json.loads(token_text)
                    for _ in decoded:
                        scalar_count += 1
                        context.check_limit("utf8_scalars", scalar_count, source_id=source_id)
                        context.emit("parse.string_scalar", 1, operation_path=operation_path, source_id=source_id)
                finally:
                    context.release_temporary(raw_token_bytes)
    except Exception:
        context.release_temporary(unattached_units + sum(int(frame["held"]) for frame in stack))
        raise
    return unattached_units + sum(int(frame["held"]) for frame in stack)


def parse_json(
    raw: bytes | bytearray | memoryview | str,
    *,
    context: WorkContext | None = None,
    source_id: str | None = None,
    operation_path: tuple[int, ...] = (),
) -> object:
    """Parse strict GEW JSON without coercion, duplicate loss, or normalization."""

    if isinstance(raw, str):
        body = raw.encode("utf-8", errors="strict")
        if context is not None:
            if source_id is None:
                raise ValueError("charged parse requires source_id")
            context.check_limit("raw_document_bytes", len(body), source_id=source_id)
        text = raw
    elif isinstance(raw, (bytes, bytearray, memoryview)):
        body = bytes(raw)
        if context is not None:
            if source_id is None:
                raise ValueError("charged parse requires source_id")
            context.check_limit("raw_document_bytes", len(body), source_id=source_id)
            for _ in body:
                context.emit("parse.input_byte", 1, operation_path=operation_path, source_id=source_id)
        if body.startswith(b"\xef\xbb\xbf"):
            raise ValueError("UTF-8 BOM is forbidden")
        text = body.decode("utf-8", errors="strict")
    else:
        raise TypeError("JSON input must be bytes or string")
    if text.startswith("\ufeff"):
        raise ValueError("Unicode BOM is forbidden")
    if context is not None:
        if source_id is None:
            raise ValueError("charged parse requires source_id")
        held_units = _charge_parse(body if isinstance(raw, str) else b"", text, context, source_id, operation_path)
    else:
        held_units = 0
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object,
            parse_int=_integer,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    finally:
        if context is not None:
            context.release_temporary(held_units)
    _validate_scalars(value)
    return value
