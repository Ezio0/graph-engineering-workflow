"""Descriptor-checked native Git identity and read-only target observation."""

from __future__ import annotations

import hashlib
import hmac
import os
import pathlib
import re
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass

from graph_engineering.core.action_adapters import (
    ActionAdapterRegistryEntry,
    ActionInvocation,
    ActionReceipt,
)
from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest


IDENTITY_PROJECTION = "urn:gew:digest-projection:identity:1.0.0"
_ID = re.compile(r"[a-z][a-z0-9]*(?:[._:/-][a-z0-9]+)*")
_HEX = re.compile(r"[0-9a-f]{64}")
_OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_REF = re.compile(r"refs/[A-Za-z0-9][A-Za-z0-9._/-]*")
_issued_observations: dict[int, object] = {}


class GitAdapterRejection(ValueError):
    """The native Git target could not be proven inside the approved boundary."""


def _record(value: object, fields: frozenset[str], label: str) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise GitAdapterRejection(f"{label} record is not exact")
    return value


def _identity(value: object, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise GitAdapterRejection(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or SEMANTIC_DIGEST.fullmatch(value) is None:
        raise GitAdapterRejection(f"{label} is invalid")
    return value


def _semantic(name: str, value: Mapping[str, object]) -> str:
    return semantic_digest(
        value,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=IDENTITY_PROJECTION,
        schema_id=f"urn:gew:schema:{name}:1.0.0",
    )


def _self_digest(value: Mapping[str, object], field: str, name: str) -> str:
    expected = _digest(value[field], field)
    actual = _semantic(name, {key: item for key, item in value.items() if key != field})
    if not hmac.compare_digest(expected, actual):
        raise GitAdapterRejection(f"{name} digest mismatch")
    return expected


@dataclass(frozen=True, slots=True)
class GitAdapterConfiguration:
    schema_version: str
    configuration_id: str
    adapter_id: str
    executable: str
    executable_sha256: str
    max_output_bytes: int
    timeout_seconds: int
    configuration_digest: str

    FIELDS = frozenset({
        "schema_version", "configuration_id", "adapter_id", "executable",
        "executable_sha256", "max_output_bytes", "timeout_seconds",
        "configuration_digest",
    })

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _semantic(
            "git-adapter-configuration",
            {key: item for key, item in value.items() if key != "configuration_digest"},
        )

    @classmethod
    def from_dict(cls, value: object) -> GitAdapterConfiguration:
        row = _record(value, cls.FIELDS, "Git adapter configuration")
        executable = row["executable"]
        executable_digest = row["executable_sha256"]
        maximum = row["max_output_bytes"]
        timeout = row["timeout_seconds"]
        if (
            row["schema_version"] != "1.0.0"
            or type(executable) is not str
            or not pathlib.PurePath(executable).is_absolute()
            or type(executable_digest) is not str
            or _HEX.fullmatch(executable_digest) is None
            or type(maximum) is not int
            or maximum <= 0
            or type(timeout) is not int
            or timeout <= 0
        ):
            raise GitAdapterRejection("Git adapter configuration value is invalid")
        return cls(
            "1.0.0",
            _identity(row["configuration_id"], "configuration ID"),
            _identity(row["adapter_id"], "adapter ID"),
            executable,
            executable_digest,
            maximum,
            timeout,
            _self_digest(row, "configuration_digest", "git-adapter-configuration"),
        )


@dataclass(frozen=True, slots=True)
class GitTargetPlan:
    schema_version: str
    plan_id: str
    target_id: str
    target_digest: str
    allowed_root: str
    relative_path: str
    plan_digest: str

    FIELDS = frozenset({
        "schema_version", "plan_id", "target_id", "target_digest", "allowed_root",
        "relative_path", "plan_digest",
    })

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _semantic(
            "git-target-plan",
            {key: item for key, item in value.items() if key != "plan_digest"},
        )

    @classmethod
    def from_dict(cls, value: object) -> GitTargetPlan:
        row = _record(value, cls.FIELDS, "Git target plan")
        root = row["allowed_root"]
        relative = row["relative_path"]
        if (
            row["schema_version"] != "1.0.0"
            or type(root) is not str
            or not pathlib.PurePath(root).is_absolute()
            or type(relative) is not str
            or not relative
            or "\\" in relative
        ):
            raise GitAdapterRejection("Git target plan path is invalid")
        pure = pathlib.PurePosixPath(relative)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in relative.split("/")):
            raise GitAdapterRejection("Git target plan escapes its allowed root")
        return cls(
            "1.0.0",
            _identity(row["plan_id"], "plan ID"),
            _identity(row["target_id"], "target ID"),
            _digest(row["target_digest"], "target digest"),
            root,
            pure.as_posix(),
            _self_digest(row, "plan_digest", "git-target-plan"),
        )


@dataclass(frozen=True, slots=True)
class GitIdentityObservation:
    schema_version: str
    plan_id: str
    plan_digest: str
    target_id: str
    target_digest: str
    worktree_path: str
    worktree_device: int
    worktree_inode: int
    common_dir_path: str
    common_dir_device: int
    common_dir_inode: int
    head_ref: str
    head_oid: str | None
    fresh: bool
    observation_revision: int
    observation_digest: str

    FIELDS = frozenset({
        "schema_version", "plan_id", "plan_digest", "target_id", "target_digest",
        "worktree_path", "worktree_device", "worktree_inode", "common_dir_path",
        "common_dir_device", "common_dir_inode", "head_ref", "head_oid", "fresh",
        "observation_revision", "observation_digest",
    })

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _semantic(
            "git-identity-observation",
            {key: item for key, item in value.items() if key != "observation_digest"},
        )

    @classmethod
    def from_dict(cls, value: object) -> GitIdentityObservation:
        row = _record(value, cls.FIELDS, "Git identity observation")
        integers = (
            row["worktree_device"], row["worktree_inode"], row["common_dir_device"],
            row["common_dir_inode"], row["observation_revision"],
        )
        head_oid = row["head_oid"]
        if (
            row["schema_version"] != "1.0.0"
            or row["fresh"] is not True
            or any(type(item) is not int or item <= 0 for item in integers)
            or type(row["worktree_path"]) is not str
            or not pathlib.PurePath(row["worktree_path"]).is_absolute()
            or type(row["common_dir_path"]) is not str
            or not pathlib.PurePath(row["common_dir_path"]).is_absolute()
            or type(row["head_ref"]) is not str
            or not row["head_ref"]
            or (head_oid is not None and (type(head_oid) is not str or _OBJECT_ID.fullmatch(head_oid) is None))
        ):
            raise GitAdapterRejection("Git identity observation value is invalid")
        return cls(
            "1.0.0",
            _identity(row["plan_id"], "plan ID"),
            _digest(row["plan_digest"], "plan digest"),
            _identity(row["target_id"], "target ID"),
            _digest(row["target_digest"], "target digest"),
            row["worktree_path"],
            row["worktree_device"],
            row["worktree_inode"],
            row["common_dir_path"],
            row["common_dir_device"],
            row["common_dir_inode"],
            row["head_ref"],
            head_oid,
            True,
            row["observation_revision"],
            _self_digest(row, "observation_digest", "git-identity-observation"),
        )

    def require_plan(self, plan: GitTargetPlan) -> None:
        if type(plan) is not GitTargetPlan:
            raise GitAdapterRejection("Git target plan is missing or forged")
        expected_worktree = os.path.realpath(os.path.join(plan.allowed_root, plan.relative_path))
        if (
            self.plan_id != plan.plan_id
            or self.plan_digest != plan.plan_digest
            or self.target_id != plan.target_id
            or self.target_digest != plan.target_digest
            or self.worktree_path != expected_worktree
        ):
            raise GitAdapterRejection("Git identity observation plan binding changed")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "plan_digest": self.plan_digest,
            "target_id": self.target_id,
            "target_digest": self.target_digest,
            "worktree_path": self.worktree_path,
            "worktree_device": self.worktree_device,
            "worktree_inode": self.worktree_inode,
            "common_dir_path": self.common_dir_path,
            "common_dir_device": self.common_dir_device,
            "common_dir_inode": self.common_dir_inode,
            "head_ref": self.head_ref,
            "head_oid": self.head_oid,
            "fresh": self.fresh,
            "observation_revision": self.observation_revision,
            "observation_digest": self.observation_digest,
        }


def _resources_and_fences(
    resources_value: object,
    fences_value: object,
) -> tuple[tuple[str, ...], tuple[Mapping[str, object], ...]]:
    if type(resources_value) is not list or not resources_value:
        raise GitAdapterRejection("Git mutation resources are invalid")
    resources = tuple(_identity(item, "Git mutation resource") for item in resources_value)
    if resources != tuple(sorted(set(resources))):
        raise GitAdapterRejection("Git mutation resources are not canonical")
    if type(fences_value) is not list or len(fences_value) != len(resources):
        raise GitAdapterRejection("Git mutation fences are not exact")
    fences: list[Mapping[str, object]] = []
    for item in fences_value:
        row = _record(item, frozenset({"resource_id", "token"}), "Git mutation fence")
        token = row["token"]
        if type(token) is not int or token <= 0:
            raise GitAdapterRejection("Git mutation fence token is invalid")
        fences.append({
            "resource_id": _identity(row["resource_id"], "Git mutation fence resource"),
            "token": token,
        })
    if tuple(item["resource_id"] for item in fences) != resources:
        raise GitAdapterRejection("Git mutation fences do not exactly cover resources")
    return resources, tuple(fences)


@dataclass(frozen=True, slots=True)
class GitRefMutationPlan:
    schema_version: str
    plan_id: str
    target_plan_id: str
    target_plan_digest: str
    task_id: str
    action_id: str
    prepared_action_digest: str
    authority_digest: str
    invocation_id: str
    invocation_digest: str
    target_id: str
    target_digest: str
    resources: tuple[str, ...]
    lease_id: str
    fencing_tokens: tuple[Mapping[str, object], ...]
    idempotency_key: str
    ref_name: str
    expected_old_oid: str
    new_oid: str
    plan_digest: str

    FIELDS = frozenset({
        "schema_version", "plan_id", "target_plan_id", "target_plan_digest", "task_id",
        "action_id", "prepared_action_digest", "authority_digest", "invocation_id",
        "invocation_digest", "target_id", "target_digest", "resources", "lease_id",
        "fencing_tokens", "idempotency_key", "ref_name", "expected_old_oid", "new_oid",
        "plan_digest",
    })

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _semantic(
            "git-ref-mutation-plan",
            {key: item for key, item in value.items() if key != "plan_digest"},
        )

    @staticmethod
    def payload_document(value: Mapping[str, object]) -> dict[str, object]:
        return {
            "target_plan_id": value["target_plan_id"],
            "target_plan_digest": value["target_plan_digest"],
            "ref_name": value["ref_name"],
            "expected_old_oid": value["expected_old_oid"],
            "new_oid": value["new_oid"],
        }

    @classmethod
    def from_dict(cls, value: object) -> GitRefMutationPlan:
        row = _record(value, cls.FIELDS, "Git ref mutation plan")
        resources, fences = _resources_and_fences(row["resources"], row["fencing_tokens"])
        ref_name = row["ref_name"]
        old_oid = row["expected_old_oid"]
        new_oid = row["new_oid"]
        if (
            row["schema_version"] != "1.0.0"
            or type(ref_name) is not str
            or _REF.fullmatch(ref_name) is None
            or ".." in ref_name
            or ref_name.endswith((".", "/"))
            or "@{" in ref_name
            or type(old_oid) is not str
            or _OBJECT_ID.fullmatch(old_oid) is None
            or type(new_oid) is not str
            or _OBJECT_ID.fullmatch(new_oid) is None
            or len(old_oid) != len(new_oid)
            or old_oid == new_oid
        ):
            raise GitAdapterRejection("Git ref mutation value is invalid")
        return cls(
            "1.0.0",
            _identity(row["plan_id"], "Git mutation plan ID"),
            _identity(row["target_plan_id"], "Git target plan ID"),
            _digest(row["target_plan_digest"], "Git target plan digest"),
            _identity(row["task_id"], "Git mutation task ID"),
            _identity(row["action_id"], "Git mutation action ID"),
            _digest(row["prepared_action_digest"], "Git prepared action digest"),
            _digest(row["authority_digest"], "Git authority digest"),
            _identity(row["invocation_id"], "Git invocation ID"),
            _digest(row["invocation_digest"], "Git invocation digest"),
            _identity(row["target_id"], "Git target ID"),
            _digest(row["target_digest"], "Git target digest"),
            resources,
            _identity(row["lease_id"], "Git lease ID"),
            fences,
            _identity(row["idempotency_key"], "Git idempotency key"),
            ref_name,
            old_oid,
            new_oid,
            _self_digest(row, "plan_digest", "git-ref-mutation-plan"),
        )

    def require_invocation(self, invocation: ActionInvocation) -> None:
        if type(invocation) is not ActionInvocation:
            raise GitAdapterRejection("Git invocation is missing or forged")
        fields = (
            "task_id", "action_id", "prepared_action_digest", "authority_digest",
            "invocation_id", "invocation_digest", "target_id", "target_digest", "resources",
            "lease_id", "fencing_tokens", "idempotency_key",
        )
        if any(getattr(self, field) != getattr(invocation, field) for field in fields):
            raise GitAdapterRejection("Git mutation plan invocation binding changed")
        expected_payload = ActionInvocation.payload_digest_for(self.payload_document({
            "target_plan_id": self.target_plan_id,
            "target_plan_digest": self.target_plan_digest,
            "ref_name": self.ref_name,
            "expected_old_oid": self.expected_old_oid,
            "new_oid": self.new_oid,
        }))
        if not hmac.compare_digest(expected_payload, invocation.payload_digest):
            raise GitAdapterRejection("Git mutation payload binding changed")


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_planned_directory(plan: GitTargetPlan) -> tuple[int, int, str, os.stat_result]:
    try:
        root_metadata = os.lstat(plan.allowed_root)
        if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
            raise GitAdapterRejection("Git allowed root is not a no-follow directory")
        root_descriptor = os.open(plan.allowed_root, _directory_flags())
        descriptor = os.dup(root_descriptor)
        try:
            for part in pathlib.PurePosixPath(plan.relative_path).parts:
                next_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            path = os.path.join(plan.allowed_root, plan.relative_path)
            named = os.lstat(path)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(named.st_mode)
                or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
            ):
                raise GitAdapterRejection("Git planned directory identity changed")
            return root_descriptor, descriptor, os.path.realpath(path), metadata
        except BaseException:
            os.close(descriptor)
            os.close(root_descriptor)
            raise
    except (FileNotFoundError, NotADirectoryError, OSError) as error:
        raise GitAdapterRejection("Git planned directory is missing or crosses a symlink") from error


def _open_exact_directory(path: str) -> tuple[int, os.stat_result]:
    try:
        named = os.lstat(path)
        descriptor = os.open(path, _directory_flags())
        metadata = os.fstat(descriptor)
        if (
            stat.S_ISLNK(named.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or (named.st_dev, named.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise GitAdapterRejection("Git resolved directory identity changed")
        return descriptor, metadata
    except (FileNotFoundError, NotADirectoryError, OSError) as error:
        raise GitAdapterRejection("Git resolved directory is unsafe") from error


class GitNativeAdapter:
    """Built-in read-only Git observer; issued only by ActionAdapterFactory."""

    __slots__ = (
        "_configuration", "_descriptor", "_executable_descriptor",
        "_executable_identity", "_query_count", "_mutation_count",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("native Git adapters are created only by ActionAdapterFactory")

    @classmethod
    def _issue(
        cls,
        configuration: Mapping[str, object],
        *,
        descriptor: ActionAdapterRegistryEntry,
        registry_digest: str,
    ) -> GitNativeAdapter:
        config = GitAdapterConfiguration.from_dict(configuration)
        if (
            type(descriptor) is not ActionAdapterRegistryEntry
            or config.adapter_id != descriptor.adapter_id
            or descriptor.adapter_kind != "git"
            or type(registry_digest) is not str
            or SEMANTIC_DIGEST.fullmatch(registry_digest) is None
        ):
            raise GitAdapterRejection("native Git factory binding changed")
        try:
            named = os.lstat(config.executable)
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            executable_descriptor = os.open(config.executable, flags)
            metadata = os.fstat(executable_descriptor)
            if (
                stat.S_ISLNK(named.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or (named.st_dev, named.st_ino) != (metadata.st_dev, metadata.st_ino)
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise GitAdapterRejection("configured Git executable is unsafe")
            with os.fdopen(os.dup(executable_descriptor), "rb", closefd=True) as stream:
                actual = hashlib.sha256(stream.read()).hexdigest()
            if not hmac.compare_digest(actual, config.executable_sha256):
                raise GitAdapterRejection("configured Git executable digest changed")
        except BaseException:
            if "executable_descriptor" in locals():
                os.close(executable_descriptor)
            raise
        instance = object.__new__(cls)
        instance._configuration = config
        instance._descriptor = descriptor
        instance._executable_descriptor = executable_descriptor
        instance._executable_identity = (metadata.st_dev, metadata.st_ino, metadata.st_size)
        instance._query_count = 0
        instance._mutation_count = 0
        return instance

    @property
    def query_count(self) -> int:
        return self._query_count

    @property
    def mutation_count(self) -> int:
        return self._mutation_count

    def _verify_executable(self) -> None:
        metadata = os.fstat(self._executable_descriptor)
        named = os.lstat(self._configuration.executable)
        if (
            (metadata.st_dev, metadata.st_ino, metadata.st_size) != self._executable_identity
            or (named.st_dev, named.st_ino, named.st_size) != self._executable_identity
        ):
            raise GitAdapterRejection("configured Git executable identity changed")

    def _run(self, cwd: str, *arguments: str, allow_missing: bool = False) -> str | None:
        self._verify_executable()
        environment = dict(os.environ)
        for name in tuple(environment):
            if name.startswith("GIT_"):
                del environment[name]
        environment.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "LANG": "C",
            "LC_ALL": "C",
        })
        completed = subprocess.run(
            (self._configuration.executable, *arguments),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
            timeout=self._configuration.timeout_seconds,
            close_fds=True,
            env=environment,
        )
        self._verify_executable()
        if len(completed.stdout) > self._configuration.max_output_bytes:
            raise GitAdapterRejection("Git read-only query output exceeds configured bound")
        if completed.returncode != 0:
            if allow_missing:
                return None
            raise GitAdapterRejection("Git read-only query failed")
        try:
            return completed.stdout.decode("utf-8", errors="strict").rstrip("\n")
        except UnicodeError as error:
            raise GitAdapterRejection("Git read-only query output is not UTF-8") from error

    def observe(
        self,
        plan_document: Mapping[str, object],
        *,
        expected: GitTargetPlan,
    ) -> GitIdentityObservation:
        from graph_engineering.adapters.action_adapters import ActionAdapterFactory
        ActionAdapterFactory.require_attested(self)
        if type(expected) is not GitTargetPlan:
            raise GitAdapterRejection("durable Git target plan is missing or forged")
        plan = GitTargetPlan.from_dict(plan_document)
        if plan != expected:
            raise GitAdapterRejection("Git target plan differs from durable expected binding")
        root_descriptor, worktree_descriptor, planned_path, planned_metadata = _open_planned_directory(plan)
        common_descriptor = -1
        try:
            self._query_count += 1
            worktree = self._run(planned_path, "rev-parse", "--path-format=absolute", "--show-toplevel")
            if worktree is None or os.path.realpath(worktree) != planned_path:
                raise GitAdapterRejection("Git worktree expands beyond the planned target")
            common_value = self._run(planned_path, "rev-parse", "--git-common-dir")
            if common_value is None:
                raise GitAdapterRejection("Git common directory is unavailable")
            common_path = common_value if os.path.isabs(common_value) else os.path.join(planned_path, common_value)
            common_path = os.path.realpath(common_path)
            allowed = os.path.realpath(plan.allowed_root)
            if os.path.commonpath((allowed, common_path)) != allowed:
                raise GitAdapterRejection("Git common directory escapes the allowed root")
            common_descriptor, common_metadata = _open_exact_directory(common_path)
            head_ref = self._run(planned_path, "symbolic-ref", "--quiet", "HEAD")
            if head_ref is None:
                raise GitAdapterRejection("Git symbolic HEAD is unavailable")
            head_oid = self._run(planned_path, "rev-parse", "--verify", "HEAD", allow_missing=True)
            named_after = os.lstat(planned_path)
            descriptor_after = os.fstat(worktree_descriptor)
            if (
                (named_after.st_dev, named_after.st_ino) != (planned_metadata.st_dev, planned_metadata.st_ino)
                or (descriptor_after.st_dev, descriptor_after.st_ino)
                != (planned_metadata.st_dev, planned_metadata.st_ino)
            ):
                raise GitAdapterRejection("Git worktree identity changed during query")
            body: dict[str, object] = {
                "schema_version": "1.0.0",
                "plan_id": plan.plan_id,
                "plan_digest": plan.plan_digest,
                "target_id": plan.target_id,
                "target_digest": plan.target_digest,
                "worktree_path": planned_path,
                "worktree_device": planned_metadata.st_dev,
                "worktree_inode": planned_metadata.st_ino,
                "common_dir_path": common_path,
                "common_dir_device": common_metadata.st_dev,
                "common_dir_inode": common_metadata.st_ino,
                "head_ref": head_ref,
                "head_oid": head_oid,
                "fresh": True,
                "observation_revision": self._query_count,
            }
            body["observation_digest"] = GitIdentityObservation.digest_document(body)
            observation = GitIdentityObservation.from_dict(body)
            _issued_observations[id(observation)] = observation
            return observation
        finally:
            if common_descriptor >= 0:
                os.close(common_descriptor)
            os.close(worktree_descriptor)
            os.close(root_descriptor)

    def update_ref(
        self,
        invocation_document: Mapping[str, object],
        *,
        expected: ActionInvocation,
        target_plan_document: Mapping[str, object],
        expected_target: GitTargetPlan,
        mutation_plan_document: Mapping[str, object],
        before: GitIdentityObservation,
    ) -> tuple[ActionReceipt, GitIdentityObservation]:
        from graph_engineering.adapters.action_adapters import ActionAdapterFactory

        ActionAdapterFactory.require_attested(self)
        if type(expected) is not ActionInvocation:
            raise GitAdapterRejection("Git mutation expected invocation is missing or forged")
        try:
            candidate = ActionInvocation.from_dict(invocation_document)
        except ValueError as error:
            raise GitAdapterRejection("Git mutation invocation rejected") from error
        if (
            candidate != expected
            or candidate.adapter_id != self._descriptor.adapter_id
            or candidate.operation_id != "git.update-ref"
        ):
            raise GitAdapterRejection("Git mutation invocation binding changed")
        target = GitTargetPlan.from_dict(target_plan_document)
        if type(expected_target) is not GitTargetPlan or target != expected_target:
            raise GitAdapterRejection("Git mutation target binding changed")
        plan = GitRefMutationPlan.from_dict(mutation_plan_document)
        plan.require_invocation(candidate)
        if (
            plan.target_plan_id != target.plan_id
            or plan.target_plan_digest != target.plan_digest
            or _issued_observations.get(id(before)) is not before
            or before.fresh is not True
        ):
            raise GitAdapterRejection("Git mutation has no trusted fresh pre-observation")
        before.require_plan(target)
        if before.head_ref != plan.ref_name or before.head_oid != plan.expected_old_oid:
            raise GitAdapterRejection("Git expected ref differs from fresh target state")
        # Object existence and commit type are proven before the compare-and-swap.
        verified_new = self._run(
            before.worktree_path,
            "rev-parse",
            "--verify",
            f"{plan.new_oid}^{{commit}}",
        )
        if verified_new != plan.new_oid:
            raise GitAdapterRejection("Git proposed ref object is not an exact commit")
        root_descriptor, worktree_descriptor, planned_path, metadata = _open_planned_directory(target)
        try:
            self._run(
                planned_path,
                "update-ref",
                plan.ref_name,
                plan.new_oid,
                plan.expected_old_oid,
            )
            named_after = os.lstat(planned_path)
            descriptor_after = os.fstat(worktree_descriptor)
            if (
                (named_after.st_dev, named_after.st_ino) != (metadata.st_dev, metadata.st_ino)
                or (descriptor_after.st_dev, descriptor_after.st_ino) != (metadata.st_dev, metadata.st_ino)
            ):
                raise GitAdapterRejection("Git target identity changed during ref mutation")
            self._mutation_count += 1
        finally:
            os.close(worktree_descriptor)
            os.close(root_descriptor)
        after = self.observe(target_plan_document, expected=target)
        if after.head_ref != plan.ref_name or after.head_oid != plan.new_oid:
            raise GitAdapterRejection("Git ref mutation postcondition is not exact")
        result_digest = _semantic("git-ref-mutation-result", {
            "plan_digest": plan.plan_digest,
            "expected_old_oid": plan.expected_old_oid,
            "new_oid": plan.new_oid,
            "observation_digest": after.observation_digest,
        })
        receipt_body: dict[str, object] = {
            "schema_version": "1.0.0",
            "receipt_id": f"receipt-{candidate.invocation_id}",
            "invocation_id": candidate.invocation_id,
            "invocation_digest": candidate.invocation_digest,
            "task_id": candidate.task_id,
            "action_id": candidate.action_id,
            "prepared_action_digest": candidate.prepared_action_digest,
            "authority_digest": candidate.authority_digest,
            "adapter_id": candidate.adapter_id,
            "operation_id": candidate.operation_id,
            "target_id": candidate.target_id,
            "target_digest": candidate.target_digest,
            "resources": list(candidate.resources),
            "lease_id": candidate.lease_id,
            "fencing_tokens": [dict(item) for item in candidate.fencing_tokens],
            "idempotency_class": candidate.idempotency_class,
            "idempotency_key": candidate.idempotency_key,
            "result": "succeeded",
            "result_digest": result_digest,
            "receipt_source": "git-native-v1",
        }
        receipt_body["receipt_digest"] = ActionReceipt.digest_document(receipt_body)
        receipt = ActionReceipt.from_dict(receipt_body)
        receipt.require_invocation(candidate)
        return receipt, after

    def close(self) -> None:
        descriptor = self._executable_descriptor
        if descriptor >= 0:
            self._executable_descriptor = -1
            os.close(descriptor)

    def __del__(self) -> None:
        descriptor = getattr(self, "_executable_descriptor", -1)
        if type(descriptor) is int and descriptor >= 0:
            self._executable_descriptor = -1
            try:
                os.close(descriptor)
            except OSError:
                pass
