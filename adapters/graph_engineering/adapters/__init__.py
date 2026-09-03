"""Runtime and external-system adapters with installed build provenance."""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.metadata
import os
import pathlib
import stat
import tomllib


_DISTRIBUTION_NAME = "graph-engineering-workflow"
_PROVENANCE_RESOURCE = "graph_engineering/pyproject.toml"
_ADAPTER_PACKAGE_RESOURCE = "graph_engineering/adapters/__init__.py"


class AdapterInstallationError(RuntimeError):
    """The installed adapter build provenance cannot be proven from RECORD."""


def _validate_installed_build_provenance() -> None:
    from graph_engineering import _validated_archive_resource

    archive_manifest = _validated_archive_resource(_PROVENANCE_RESOURCE)
    if archive_manifest is not None:
        expected_module = _validated_archive_resource(_ADAPTER_PACKAGE_RESOURCE)
        loader = globals().get("__loader__")
        origin = globals().get("__file__")
        get_data = getattr(loader, "get_data", None)
        if (
            expected_module is None
            or type(origin) is not str
            or not callable(get_data)
        ):
            raise AdapterInstallationError(
                "installed action adapter archive origin is unavailable"
            )
        try:
            loaded_module = get_data(origin)
        except OSError as error:
            raise AdapterInstallationError(
                "installed action adapter archive origin is unavailable"
            ) from error
        if type(loaded_module) is not bytes or not hmac.compare_digest(
            hashlib.sha256(loaded_module).digest(),
            hashlib.sha256(expected_module).digest(),
        ):
            raise AdapterInstallationError(
                "installed action adapter archive origin changed"
            )
        try:
            distribution = importlib.metadata.distribution(_DISTRIBUTION_NAME)
            manifest = tomllib.loads(archive_manifest.decode("utf-8", errors="strict"))
            project = manifest["project"]
        except (
            importlib.metadata.PackageNotFoundError,
            KeyError,
            TypeError,
            UnicodeError,
            tomllib.TOMLDecodeError,
        ) as error:
            raise AdapterInstallationError(
                "installed action adapter provenance resource is malformed"
            ) from error
        if (
            type(project) is not dict
            or project.get("name") != _DISTRIBUTION_NAME
            or project.get("version") != distribution.version
        ):
            raise AdapterInstallationError(
                "installed action adapter provenance distribution binding changed"
            )
        return
    module_path = pathlib.Path(__file__).resolve(strict=True)
    try:
        distribution = importlib.metadata.distribution(_DISTRIBUTION_NAME)
    except importlib.metadata.PackageNotFoundError:
        return
    distribution_root = pathlib.Path(distribution.locate_file("")).resolve(strict=True)
    if not module_path.is_relative_to(distribution_root):
        return
    files = distribution.files
    matches = [] if files is None else [
        item for item in files
        if pathlib.PurePosixPath(str(item)).as_posix() == _PROVENANCE_RESOURCE
    ]
    if not matches:
        raise AdapterInstallationError("installed action adapter provenance resource is unavailable")
    if len(matches) != 1:
        raise AdapterInstallationError("installed action adapter provenance resource is not unique")
    resource = pathlib.Path(distribution.locate_file(matches[0]))
    try:
        named = os.lstat(resource)
        if stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode):
            raise AdapterInstallationError(
                "installed action adapter provenance resource is unsafe"
            )
        body = resource.read_bytes()
    except OSError as error:
        raise AdapterInstallationError(
            "installed action adapter provenance resource is unavailable"
        ) from error
    recorded_hash = matches[0].hash
    if recorded_hash is None or recorded_hash.mode != "sha256":
        raise AdapterInstallationError(
            "installed action adapter provenance RECORD hash is missing"
        )
    encoded = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
    if not hmac.compare_digest(encoded, recorded_hash.value):
        raise AdapterInstallationError(
            "installed action adapter provenance RECORD hash changed"
        )
    try:
        manifest = tomllib.loads(body.decode("utf-8", errors="strict"))
        project = manifest["project"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise AdapterInstallationError(
            "installed action adapter provenance resource is malformed"
        ) from error
    if (
        type(project) is not dict
        or project.get("name") != _DISTRIBUTION_NAME
        or project.get("version") != distribution.version
    ):
        raise AdapterInstallationError(
            "installed action adapter provenance distribution binding changed"
        )


_validate_installed_build_provenance()
