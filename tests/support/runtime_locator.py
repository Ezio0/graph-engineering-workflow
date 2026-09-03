"""Test-only issuer for path-independent runtime contract fixtures."""

from graph_engineering.adapters.runtime_locator import VerifiedExecutable, _LOCATOR_ISSUER


def verified_executable(
    executable: str,
    package_origin: str,
    executable_digest: str,
    release_manifest_digest: str,
    expected_core_version: str,
) -> VerifiedExecutable:
    verified = object.__new__(VerifiedExecutable)
    for field, value in (
        ("executable", executable), ("package_origin", package_origin),
        ("executable_digest", executable_digest),
        ("release_manifest_digest", release_manifest_digest),
        ("expected_core_version", expected_core_version), ("_issuer", _LOCATOR_ISSUER),
    ):
        object.__setattr__(verified, field, value)
    return verified
