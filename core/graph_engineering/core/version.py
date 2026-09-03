"""Installed distribution version lookup."""

from importlib.metadata import version


def installed_version() -> str:
    """Return the version of the installed distribution."""

    return version("graph-engineering-workflow")

