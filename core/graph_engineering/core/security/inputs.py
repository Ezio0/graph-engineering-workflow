"""Fail-closed path, argv, and untrusted prompt envelopes."""

from __future__ import annotations

import os
import pathlib
import stat
from collections.abc import Mapping
from dataclasses import dataclass

from graph_engineering.core.contracts.digest import semantic_digest_charged
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.security._common import (
    IDENTITY_PROJECTION,
    exact_mapping,
    require_digest,
    require_id,
    unsigned_digest,
)
from graph_engineering.core.security.attestation import SecurityRuntimeManifest


INPUT_POLICY_SCHEMA = "urn:gew:schema:input-safety-policy:1.0.0"
INPUT_POLICY_CONTRACT = "urn:gew:contract:input-safety-policy"


class InputSafetyError(ValueError):
    """A path, command, or prompt boundary is unsafe."""


@dataclass(frozen=True, slots=True, init=False)
class InputSafetyPolicy:
    policy_id: str
    max_arguments: int
    max_argument_chars: int
    allow_symlinks: bool
    allow_shell: bool
    policy_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("InputSafetyPolicy must be loaded from validated configuration")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
        runtime: SecurityRuntimeManifest,
    ) -> InputSafetyPolicy:
        if (
            type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
            or type(runtime) is not SecurityRuntimeManifest
        ):
            raise InputSafetyError("input policy requires attested contracts")
        if schema_registry.validate(INPUT_POLICY_SCHEMA, value, context):
            raise InputSafetyError("input policy schema validation failed")
        fields = {"schema_version", "policy_id", "max_arguments", "max_argument_chars", "allow_symlinks", "allow_shell", "policy_digest"}
        try:
            exact_mapping(value, fields, "input policy")
            if value.get("schema_version") != "1.0.0":
                raise ValueError("input policy version is invalid")
            policy_id = require_id(value.get("policy_id"), "policy ID")
            max_arguments = value.get("max_arguments")
            max_chars = value.get("max_argument_chars")
            allow_symlinks = value.get("allow_symlinks")
            allow_shell = value.get("allow_shell")
            expected_digest = require_digest(value.get("policy_digest"), "policy digest")
            if type(max_arguments) is not int or max_arguments <= 0 or type(max_chars) is not int or max_chars <= 0:
                raise ValueError("input policy limits are invalid")
            if type(allow_symlinks) is not bool or type(allow_shell) is not bool:
                raise ValueError("input policy booleans are invalid")
            if allow_symlinks or allow_shell:
                raise ValueError("v1 input policy cannot weaken no-follow or no-shell safety")
            actual = semantic_digest_charged(
                {key: item for key, item in value.items() if key != "policy_digest"},
                context,
                contract_type=INPUT_POLICY_CONTRACT,
                projection_id=IDENTITY_PROJECTION,
                schema_id=INPUT_POLICY_SCHEMA,
                operation_path=context.child_path(()),
            )
            if actual != expected_digest:
                raise ValueError("input policy digest mismatch")
            runtime.require_policy("input-safety", policy_id, expected_digest)
        except (TypeError, ValueError) as error:
            raise InputSafetyError(str(error)) from error
        result = object.__new__(InputSafetyPolicy)
        for name, item in (
            ("policy_id", policy_id),
            ("max_arguments", max_arguments),
            ("max_argument_chars", max_chars),
            ("allow_symlinks", allow_symlinks),
            ("allow_shell", allow_shell),
            ("policy_digest", expected_digest),
        ):
            object.__setattr__(result, name, item)
        return result


@dataclass(frozen=True, slots=True, init=False)
class PathBinding:
    root: str
    relative_path: str
    device: int | None
    inode: int | None
    _descriptor: int

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("PathBinding is emitted only by PathResolver")

    def verify_current(self) -> None:
        try:
            metadata = os.fstat(self._descriptor)
        except OSError as error:
            raise InputSafetyError("path descriptor is no longer valid") from error
        if metadata.st_dev != self.device or metadata.st_ino != self.inode:
            raise InputSafetyError("path descriptor binding changed")

    def read_bytes(self) -> bytes:
        """Read through the already-bound descriptor, never through the path name."""

        self.verify_current()
        try:
            with os.fdopen(os.dup(self._descriptor), "rb", closefd=True) as stream:
                return stream.read()
        except OSError as error:
            raise InputSafetyError("bound path cannot be read") from error

    def close(self) -> None:
        descriptor = self._descriptor
        if descriptor < 0:
            return
        object.__setattr__(self, "_descriptor", -1)
        try:
            os.close(descriptor)
        except OSError:
            return

    def __enter__(self) -> PathBinding:
        self.verify_current()
        return self

    def __exit__(self, *args: object) -> None:
        del args
        self.close()

    def __del__(self) -> None:
        descriptor = getattr(self, "_descriptor", -1)
        if type(descriptor) is int and descriptor >= 0:
            object.__setattr__(self, "_descriptor", -1)
            try:
                os.close(descriptor)
            except OSError:
                pass


class PathResolver:
    @staticmethod
    def resolve(
        root: pathlib.Path,
        candidate: str,
        *,
        policy: InputSafetyPolicy,
        must_exist: bool = True,
    ) -> PathBinding:
        if (
            type(policy) is not InputSafetyPolicy
            or type(candidate) is not str
            or not candidate
            or "\x00" in candidate
            or must_exist is not True
        ):
            raise InputSafetyError("path request is invalid")
        if type(root) is not pathlib.PosixPath or not root.is_absolute() or not root.exists() or root.is_symlink():
            raise InputSafetyError("path root is not an attested directory")
        raw_parts = candidate.split("/")
        pure = pathlib.PurePosixPath(candidate)
        if "\\" in candidate or pure.is_absolute() or any(part in {"", ".", ".."} for part in raw_parts):
            raise InputSafetyError("path escapes the configured root")
        try:
            root_metadata = root.lstat()
            if not stat.S_ISDIR(root_metadata.st_mode):
                raise InputSafetyError("path root is not a directory")
            descriptor = os.open(
                root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                opened_root = os.fstat(descriptor)
                if (
                    opened_root.st_dev != root_metadata.st_dev
                    or opened_root.st_ino != root_metadata.st_ino
                ):
                    raise InputSafetyError("path root changed during binding")
                for index, part in enumerate(pure.parts):
                    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                    if index < len(pure.parts) - 1:
                        flags |= os.O_DIRECTORY
                    next_descriptor = os.open(part, flags, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = next_descriptor
                metadata = os.fstat(descriptor)
            except BaseException:
                os.close(descriptor)
                raise
        except (FileNotFoundError, NotADirectoryError, OSError) as error:
            raise InputSafetyError("path does not exist or crosses a symlink") from error
        result = object.__new__(PathBinding)
        for name, item in (
            ("root", os.fspath(root)),
            ("relative_path", pure.as_posix()),
            ("device", metadata.st_dev),
            ("inode", metadata.st_ino),
            ("_descriptor", descriptor),
        ):
            object.__setattr__(result, name, item)
        return result


@dataclass(frozen=True, slots=True, init=False)
class CommandEnvelope:
    executable_ref: str
    argv: tuple[str, ...]
    shell: bool
    stdin_digest: str | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("CommandEnvelope must be validated")

    @classmethod
    def from_dict(cls, value: Mapping[str, object], *, policy: InputSafetyPolicy) -> CommandEnvelope:
        try:
            exact_mapping(value, {"schema_version", "executable_ref", "argv", "shell", "stdin_digest"}, "command envelope")
            if value.get("schema_version") != "1.0.0" or type(policy) is not InputSafetyPolicy:
                raise ValueError("command envelope context is invalid")
            executable_ref = require_id(value.get("executable_ref"), "executable ref")
            argv = value.get("argv")
            shell = value.get("shell")
            stdin_digest = value.get("stdin_digest")
            if type(argv) is not list or not argv or len(argv) > policy.max_arguments:
                raise ValueError("command argv is invalid")
            if any(type(item) is not str or not item or "\x00" in item or len(item) > policy.max_argument_chars for item in argv):
                raise ValueError("command argument is invalid")
            if type(shell) is not bool or shell or policy.allow_shell:
                if shell is not False:
                    raise ValueError("shell execution is disabled")
            if stdin_digest is not None:
                stdin_digest = require_digest(stdin_digest, "stdin digest")
        except (TypeError, ValueError) as error:
            raise InputSafetyError(str(error)) from error
        result = object.__new__(CommandEnvelope)
        for name, item in (("executable_ref", executable_ref), ("argv", tuple(argv)), ("shell", shell), ("stdin_digest", stdin_digest)):
            object.__setattr__(result, name, item)
        return result


@dataclass(frozen=True, slots=True, init=False)
class PromptEnvelope:
    content_ref: str
    content_digest: str
    trust: str
    instructions_allowed: bool

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("PromptEnvelope must be validated")

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> PromptEnvelope:
        try:
            exact_mapping(value, {"schema_version", "content_ref", "content_digest", "trust", "instructions_allowed"}, "prompt envelope")
            if value.get("schema_version") != "1.0.0":
                raise ValueError("prompt schema version is invalid")
            content_ref = require_id(value.get("content_ref"), "prompt content ref")
            digest = require_digest(value.get("content_digest"), "prompt content digest")
            trust = value.get("trust")
            instructions = value.get("instructions_allowed")
            if trust != "untrusted" or instructions is not False:
                raise ValueError("prompt content is data and cannot authorize instructions")
        except (TypeError, ValueError) as error:
            raise InputSafetyError(str(error)) from error
        result = object.__new__(PromptEnvelope)
        for name, item in (("content_ref", content_ref), ("content_digest", digest), ("trust", trust), ("instructions_allowed", instructions)):
            object.__setattr__(result, name, item)
        return result
