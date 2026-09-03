"""Build the project wheel without ambient indexes or dependencies."""

from __future__ import annotations

import pathlib
import sys

import build_backend


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        raise SystemExit("usage: build_wheel.py OUTPUT_DIRECTORY")
    output = pathlib.Path(arguments[0]).resolve()
    print(build_backend.build_wheel(str(output)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

