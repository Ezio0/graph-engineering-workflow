"""Repository-owned persisted wall-clock high-water for lease expiry decisions."""

from __future__ import annotations

import time

from .connection import ManagedConnection
from .errors import RepositoryIntegrityError


_CLOCK_KEY = "clock_high_water_ns"


def trusted_now(connection: ManagedConnection) -> int:
    """Return non-decreasing time and persist every newly observed high-water."""

    observed = time.time_ns()
    if type(observed) is not int or observed < 0:
        raise RepositoryIntegrityError("repository clock returned an invalid value")
    row = connection.execute(
        "SELECT value FROM repository_meta WHERE key=?", (_CLOCK_KEY,),
    ).fetchone()
    try:
        previous = 0 if row is None else int(row[0])
    except (TypeError, ValueError) as error:
        raise RepositoryIntegrityError("repository clock high-water is invalid") from error
    if previous < 0 or (row is not None and str(previous) != row[0]):
        raise RepositoryIntegrityError("repository clock high-water is non-canonical")
    current = max(previous, observed)
    if current != previous:
        connection.execute(
            "INSERT INTO repository_meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (_CLOCK_KEY, str(current)),
        )
    return current


def strict_trusted_now(connection: ManagedConnection) -> int:
    """Persist current wall time and reject rollback below its repository high-water."""

    observed = time.time_ns()
    if type(observed) is not int or observed < 0:
        raise RepositoryIntegrityError("repository clock returned an invalid value")
    row = connection.execute(
        "SELECT value FROM repository_meta WHERE key=?", (_CLOCK_KEY,),
    ).fetchone()
    try:
        previous = 0 if row is None else int(row[0])
    except (TypeError, ValueError) as error:
        raise RepositoryIntegrityError("repository clock high-water is invalid") from error
    if previous < 0 or (row is not None and str(previous) != row[0]):
        raise RepositoryIntegrityError("repository clock high-water is non-canonical")
    if observed < previous:
        raise RepositoryIntegrityError("repository clock rolled back")
    if observed != previous:
        connection.execute(
            "INSERT INTO repository_meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (_CLOCK_KEY, str(observed)),
        )
    return observed
