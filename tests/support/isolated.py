"""Isolated filesystem fixture helpers shared by local tests."""

from __future__ import annotations

import contextlib
import pathlib
import tempfile
from collections.abc import Iterator


@contextlib.contextmanager
def isolated_root(prefix: str = "gew-test-") -> Iterator[pathlib.Path]:
    """Yield a new disposable root and remove it after the case."""

    with tempfile.TemporaryDirectory(prefix=prefix) as directory:
        yield pathlib.Path(directory)
