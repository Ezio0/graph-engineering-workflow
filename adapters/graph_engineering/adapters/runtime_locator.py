"""Owner-only canonical executable locator verification."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import stat
import importlib.metadata
from dataclasses import dataclass, field

from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST
from graph_engineering.core.runtime import RuntimeResourceGuard


class ExecutableLocatorError(RuntimeError):
    """Stable rejection for an unsafe or incompatible executable locator."""


_FIELDS = frozenset({
    "schema_version",
    "executable",
    "package_origin",
    "executable_digest",
    "release_manifest_digest",
    "expected_core_version",
    "distribution_name",
    "distribution_version",
    "distribution_origin",
})
_VERSION = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?")
_RAW_DIGEST = re.compile(r"sha256-raw-v1:[0-9a-f]{64}")
_LOCATOR_ISSUER = object()


@dataclass(frozen=True, slots=True, init=False)
class VerifiedExecutable:
    executable: str
    package_origin: str
    executable_digest: str
    release_manifest_digest: str
    expected_core_version: str
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("verified executables are locator-issued")

    def require_verified(self) -> None:
        if self._issuer is not _LOCATOR_ISSUER:
            raise ExecutableLocatorError("verified executable is missing or forged")


_RUNNING_DISTRIBUTION_ISSUER = object()


@dataclass(frozen=True, slots=True, init=False)
class RunningDistributionIdentity:
    executable: str
    package_origin: str
    distribution_name: str
    distribution_version: str
    distribution_origin: str
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("running distribution identities are probe-issued")


class RunningDistributionProbe:
    __slots__ = ()

    def probe(self, distribution_name: str) -> RunningDistributionIdentity:
        try:
            distribution = importlib.metadata.distribution(distribution_name)
            executable = pathlib.Path(os.path.abspath(os.sys.argv[0])).resolve(strict=True)
            package_origin = pathlib.Path(os.sys.prefix).resolve(strict=True)
            distribution_origin = pathlib.Path(distribution.locate_file("")).resolve(strict=True)
        except Exception as error:
            raise ExecutableLocatorError("running distribution metadata is unavailable") from error
        metadata_name = distribution.metadata.get("Name")
        if (
            metadata_name != distribution_name
            or not executable.is_relative_to(package_origin)
            or not distribution_origin.is_relative_to(package_origin)
        ):
            raise ExecutableLocatorError("running distribution origin is unrelated")
        identity = object.__new__(RunningDistributionIdentity)
        for name, value in (
            ("executable", str(executable)), ("package_origin", str(package_origin)),
            ("distribution_name", metadata_name),
            ("distribution_version", distribution.version),
            ("distribution_origin", str(distribution_origin)),
            ("_issuer", _RUNNING_DISTRIBUTION_ISSUER),
        ):
            object.__setattr__(identity, name, value)
        return identity


def _canonical_absolute(value: object, label: str) -> pathlib.Path:
    if type(value) is not str or not value or "\x00" in value:
        raise ExecutableLocatorError(f"{label} is invalid")
    path = pathlib.Path(value)
    if not path.is_absolute() or str(path.resolve(strict=True)) != value:
        raise ExecutableLocatorError(f"{label} is not an absolute canonical path")
    return path


def _regular_owner_mode(info: os.stat_result, label: str, *, executable: bool = False) -> None:
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ExecutableLocatorError(f"{label} is not a single-link regular file")
    if info.st_uid != os.geteuid():
        raise ExecutableLocatorError(f"{label} has the wrong owner")
    if info.st_mode & 0o077:
        raise ExecutableLocatorError(f"{label} mode is not owner-only")
    if executable and not info.st_mode & stat.S_IXUSR:
        raise ExecutableLocatorError(f"{label} is not owner executable")


class ExecutableLocator:
    """Read and verify an installation locator without following its final path."""

    __slots__ = ("_guard", "_running_distribution")

    def __init__(
        self, guard: RuntimeResourceGuard, running_distribution: RunningDistributionIdentity,
    ) -> None:
        if type(guard) is not RuntimeResourceGuard:
            raise ExecutableLocatorError("runtime resource guard is missing or forged")
        self._guard = guard
        if (
            type(running_distribution) is not RunningDistributionIdentity
            or running_distribution._issuer is not _RUNNING_DISTRIBUTION_ISSUER
        ):
            raise ExecutableLocatorError("running distribution identity is missing or forged")
        self._running_distribution = running_distribution

    def resolve(self, locator_path: pathlib.Path) -> VerifiedExecutable:
        path = pathlib.Path(locator_path)
        if path.is_symlink():
            raise ExecutableLocatorError("locator symlink is forbidden")
        if not path.is_absolute():
            raise ExecutableLocatorError("locator path is not absolute")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            if path.is_symlink():
                raise ExecutableLocatorError("locator symlink is forbidden") from error
            raise ExecutableLocatorError("locator cannot be opened safely") from error
        try:
            before = os.fstat(descriptor)
            _regular_owner_mode(before, "locator")
            try:
                self._guard.validate_bytes(before.st_size, source_id="runtime-executable-locator")
            except Exception as error:
                raise ExecutableLocatorError("locator exceeds the size policy") from error
            payload = os.read(descriptor, self._guard.policy.max_record_bytes + 1)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise ExecutableLocatorError("locator changed during verification")
        finally:
            os.close(descriptor)
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ExecutableLocatorError("locator is not valid JSON") from error
        if not isinstance(document, dict) or set(document) != _FIELDS:
            raise ExecutableLocatorError("locator record is not exact")
        try:
            document = self._guard.validate(
                document, source_id="runtime-executable-locator-record"
            )
        except Exception as error:
            raise ExecutableLocatorError("locator exceeds the resource policy") from error
        if _VERSION.fullmatch(str(document["schema_version"])) is None:
            raise ExecutableLocatorError("locator schema version is invalid")
        if _VERSION.fullmatch(str(document["expected_core_version"])) is None:
            raise ExecutableLocatorError("expected core version is invalid")
        executable = _canonical_absolute(document["executable"], "executable")
        origin = _canonical_absolute(document["package_origin"], "package origin")
        running = self._running_distribution
        if pathlib.Path(running.executable) != executable:
            raise ExecutableLocatorError("locator does not bind the running executable")
        if pathlib.Path(running.package_origin) != origin or not executable.is_relative_to(origin):
            raise ExecutableLocatorError("executable is outside the package origin")
        expected_distribution = (
            document["distribution_name"], document["distribution_version"],
            document["distribution_origin"],
        )
        actual_distribution = (
            running.distribution_name, running.distribution_version,
            running.distribution_origin,
        )
        if actual_distribution != expected_distribution:
            raise ExecutableLocatorError("running distribution metadata does not match the locator")
        if document["expected_core_version"] != running.distribution_version:
            raise ExecutableLocatorError("running distribution version does not match core version")
        distribution_origin = _canonical_absolute(
            document["distribution_origin"], "distribution origin"
        )
        if not distribution_origin.is_relative_to(origin):
            raise ExecutableLocatorError("distribution origin is outside the package origin")
        executable_info = executable.lstat()
        _regular_owner_mode(executable_info, "executable", executable=True)
        origin_info = origin.lstat()
        if not stat.S_ISDIR(origin_info.st_mode) or origin_info.st_uid != os.geteuid():
            raise ExecutableLocatorError("package origin is not an owner directory")
        if origin_info.st_mode & 0o077:
            raise ExecutableLocatorError("package origin mode is not owner-only")
        expected_digest = document["executable_digest"]
        if type(expected_digest) is not str or _RAW_DIGEST.fullmatch(expected_digest) is None:
            raise ExecutableLocatorError("executable digest is invalid")
        executable_descriptor = os.open(
            executable,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            executable_before = os.fstat(executable_descriptor)
            _regular_owner_mode(executable_before, "executable", executable=True)
            try:
                self._guard.validate_bytes(
                    executable_before.st_size,
                    source_id="runtime-canonical-executable",
                    executable=True,
                )
            except Exception as error:
                raise ExecutableLocatorError("executable exceeds the size policy") from error
            digest = hashlib.sha256()
            remaining = executable_before.st_size
            while remaining:
                chunk = os.read(executable_descriptor, remaining)
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            executable_after = os.fstat(executable_descriptor)
            if (
                executable_before.st_dev, executable_before.st_ino, executable_before.st_size,
                executable_before.st_mtime_ns,
            ) != (
                executable_after.st_dev, executable_after.st_ino, executable_after.st_size,
                executable_after.st_mtime_ns,
            ):
                raise ExecutableLocatorError("executable changed during verification")
        finally:
            os.close(executable_descriptor)
        actual_digest = "sha256-raw-v1:" + digest.hexdigest()
        if actual_digest != expected_digest:
            raise ExecutableLocatorError("executable digest mismatch")
        release_digest = document["release_manifest_digest"]
        if type(release_digest) is not str or SEMANTIC_DIGEST.fullmatch(release_digest) is None:
            raise ExecutableLocatorError("release manifest digest is invalid")
        verified = object.__new__(VerifiedExecutable)
        for field_name, field_value in (
            ("executable", str(executable)), ("package_origin", str(origin)),
            ("executable_digest", actual_digest), ("release_manifest_digest", release_digest),
            ("expected_core_version", str(document["expected_core_version"])),
            ("_issuer", _LOCATOR_ISSUER),
        ):
            object.__setattr__(verified, field_name, field_value)
        return verified
