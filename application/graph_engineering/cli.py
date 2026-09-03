"""Stable installed command-line module."""

from graph_engineering.application.cli import installed_version, main

__all__ = ["installed_version", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
