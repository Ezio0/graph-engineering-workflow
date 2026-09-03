"""Test-only issued access to TaskApplication's sealed maintenance query boundary."""

from __future__ import annotations

from collections.abc import Mapping

from graph_engineering.application.tasks import TaskApplication, TaskView


def trusted_show(application: TaskApplication, task_id: str) -> TaskView:
    """Issue one test-harness maintenance read without opening a production facade."""

    return application._TaskApplication__show(task_id)  # type: ignore[attr-defined]


def trusted_search(
    application: TaskApplication,
    filters: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], ...]:
    """Issue a catalog read for legacy integration fixture assertions only."""

    return application._catalog.query_catalog({} if filters is None else dict(filters))  # type: ignore[attr-defined]


def trusted_list(application: TaskApplication) -> tuple[dict[str, object], ...]:
    """Issue an unfiltered catalog read for legacy integration fixture assertions only."""

    return trusted_search(application)
