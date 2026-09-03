"""Platform adapter for immutable benchmark environment fingerprint inputs."""

from __future__ import annotations

import hashlib
import json
import locale
import os
import pathlib
import platform
import re
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.adapters.command_native import CommandRegistry
from graph_engineering.core.contracts.immutable import thaw


_ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]*")


@dataclass(frozen=True, slots=True)
class PerformanceEnvironmentInputs:
    """One immutable platform-observed fingerprint projection."""

    fingerprint_fields: Mapping[str, str | int]


@dataclass(frozen=True, slots=True)
class PerformanceSourceControlInputs:
    """Exact source-checkout installation control supplied by the platform adapter."""

    control_root: str


def capture_performance_source_control_inputs() -> PerformanceSourceControlInputs:
    configured = sys._xoptions.get("gew_installation_control_root")
    environment = dict(os.environ).get("GEW_INSTALLATION_CONTROL_ROOT")
    if (
        type(configured) is not str
        or type(environment) is not str
        or configured != environment
        or not configured
    ):
        raise ValueError("performance source installation control is not exact")
    return PerformanceSourceControlInputs(configured)


class PerformanceDisposableRoot:
    """One descriptor-scoped private benchmark root with approved source states."""

    __slots__ = ("_temporary", "root", "work", "fixture", "source", "_sources", "_closed")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("performance roots are adapter-issued")

    @classmethod
    def create(
        cls,
        *,
        fixture_bytes: bytes,
        source_documents: Mapping[str, bytes],
        baseline_identity: str,
    ) -> "PerformanceDisposableRoot":
        if (
            type(fixture_bytes) is not bytes
            or type(source_documents) is not dict
            or not source_documents
            or any(type(key) is not str or type(value) is not bytes for key, value in source_documents.items())
            or baseline_identity not in source_documents
        ):
            raise ValueError("performance disposable root inputs are not exact")
        temporary = tempfile.TemporaryDirectory(prefix="gew-performance-")
        root = pathlib.Path(temporary.name).resolve(strict=True)
        root.chmod(0o700)
        work = root / "work"
        work.mkdir(mode=0o700)
        fixture = root / "fixture.json"
        source = root / "source-state.json"
        fixture.write_bytes(fixture_bytes)
        source.write_bytes(source_documents[baseline_identity])
        fixture.chmod(0o400)
        source.chmod(0o600)
        issued = object.__new__(cls)
        issued._temporary = temporary
        issued.root = root
        issued.work = work
        issued.fixture = fixture
        issued.source = source
        issued._sources = MappingProxyType(dict(source_documents))
        issued._closed = False
        return issued

    def _require_open(self) -> None:
        if self._closed:
            raise ValueError("performance disposable root is closed")
        metadata = os.lstat(self.root)
        if not pathlib.Path(self.root).is_dir() or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise ValueError("performance disposable root identity changed")

    def current_source_identity(self) -> str:
        self._require_open()
        body = self.source.read_bytes()
        matches = tuple(key for key, value in self._sources.items() if value == body)
        if len(matches) != 1:
            raise ValueError("performance source state is not approved")
        return matches[0]

    def transition(self, expected: str, target: str) -> None:
        self._require_open()
        if self.current_source_identity() != expected or target not in self._sources:
            raise ValueError("performance source transition is not approved")
        temporary = self.root / ".source-state.next"
        temporary.write_bytes(self._sources[target])
        temporary.chmod(0o600)
        os.replace(temporary, self.source)

    def tree_digest(self) -> str:
        self._require_open()
        rows: list[tuple[str, int, str]] = []
        for path in sorted(self.root.rglob("*"), key=lambda item: item.relative_to(self.root).as_posix()):
            relative = path.relative_to(self.root).as_posix()
            metadata = os.lstat(path)
            if path.is_symlink():
                raise ValueError("performance disposable root contains a symlink")
            if path.is_file():
                rows.append((relative, metadata.st_mode & 0o777, hashlib.sha256(path.read_bytes()).hexdigest()))
            elif path.is_dir():
                rows.append((relative + "/", metadata.st_mode & 0o777, ""))
            else:
                raise ValueError("performance disposable root contains a special member")
        encoded = json.dumps(rows, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._temporary.cleanup()


def performance_command_registry_document(
    binding: object,
    root: PerformanceDisposableRoot,
) -> dict[str, object]:
    """Instantiate one installed benchmark command binding for a private root."""

    if type(root) is not PerformanceDisposableRoot:
        raise ValueError("performance command root is foreign")
    root._require_open()
    document = thaw(binding)
    expected = {
        "schema_version", "binding_id", "command_id", "adapter_id", "child_source",
        "child_resource", "child_raw_sha256", "fixture_parameter",
        "parameter_projection", "side_effect_class", "idempotency_class",
        "root_mode", "binding_digest",
    }
    if type(document) is not dict or set(document) != expected:
        raise ValueError("performance command binding is not exact")
    executable = pathlib.Path(sys.executable).resolve(strict=True)
    child = pathlib.Path(__file__).resolve().with_name("performance_correctness.py")
    if (
        document["schema_version"] != "1.0.0"
        or document["adapter_id"] != "project-command-v1"
        or document["parameter_projection"] != {"mode": "correct"}
        or document["side_effect_class"] != "benchmark-read-only"
        or document["idempotency_class"] != "idempotent"
        or document["root_mode"] != "factory-private-disposable"
        or hashlib.sha256(child.read_bytes()).hexdigest() != document["child_raw_sha256"]
    ):
        raise ValueError("performance command binding changed")
    registry: dict[str, object] = {
        "schema_version": "1.0.0",
        "registry_id": "performance-command-registry-v1",
        "entries": [{
            "command_id": document["command_id"],
            "adapter_id": document["adapter_id"],
            "executable": os.fspath(executable),
            "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "allowed_root": os.fspath(root.root),
            "cwd_relative": "work",
            "argv_prefix": ["-I", "-S", "-B", os.fspath(child), os.fspath(root.fixture)],
            "parameter_order": ["mode"],
            "parameter_values": {"mode": ["correct"]},
            "static_environment": {"LANG": "C", "LC_ALL": "C"},
            "secret_environment": {},
            "side_effect_class": document["side_effect_class"],
            "idempotency_class": document["idempotency_class"],
        }],
    }
    registry["registry_digest"] = CommandRegistry.digest_document(registry)
    CommandRegistry.from_dict(registry)
    return registry


def capture_performance_environment_inputs(
    safe_environment_names: tuple[str, ...],
) -> PerformanceEnvironmentInputs:
    """Capture only config-selected environment names and platform facts."""

    if (
        type(safe_environment_names) is not tuple
        or not safe_environment_names
        or safe_environment_names != tuple(sorted(set(safe_environment_names)))
        or any(
            type(name) is not str or _ENVIRONMENT_NAME.fullmatch(name) is None
            for name in safe_environment_names
        )
    ):
        raise ValueError("benchmark environment allowlist is not exact")
    executable = pathlib.Path(sys.executable).resolve(strict=True)
    environment = dict(os.environ)
    values: dict[str, str | int] = {
        "cpu-identity": platform.processor() or platform.machine(),
        "locale": locale.setlocale(locale.LC_ALL, None),
        "logical-cpu-count": os.cpu_count() or 0,
        "machine": platform.machine(),
        "os-family": platform.system(),
        "os-release": platform.release(),
        "python-cache-tag": sys.implementation.cache_tag or "",
        "python-executable": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "python-implementation": platform.python_implementation(),
        "python-version": platform.python_version(),
        "static-environment": "|".join(
            f"{name}={environment.get(name, '')}" for name in safe_environment_names
        ),
        "timezone": "|".join(time.tzname),
    }
    if any(type(value) not in (str, int) for value in values.values()):
        raise ValueError("benchmark environment projection is invalid")
    return PerformanceEnvironmentInputs(MappingProxyType(values))
