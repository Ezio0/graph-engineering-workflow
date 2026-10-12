"""Read-only release application routes; no installation mutation port."""
from __future__ import annotations
from pathlib import Path

from graph_engineering.adapters.release_installation import LocalReleaseVerifier,ReadOnlyDoctor,_fresh_context
from graph_engineering.core.release_installation import ReleaseInstallationError,diagnostic,bootstrap_diagnostic


def release_check(bundle: Path, manifest: Path) -> tuple[dict[str, object], int]:
    """Return a bounded diagnostic and the stable CLI exit route."""
    context=None;observation=None
    try:
        context=_fresh_context()
        observation=LocalReleaseVerifier().check(bundle,manifest)
        return observation.to_dict(),0
    except ReleaseInstallationError as error:
        if context is None or error.code == 'trust_rejected':
            return bootstrap_diagnostic('check'),4
        code=error.code
        status='blocked' if code in ('platform_unavailable','clock_unavailable','phase_unavailable','recovery_blocked') else 'rejected'
        exit_code=2 if code=='input_invalid' else (3 if status=='blocked' else 4)
        return diagnostic(status,'check',code,[],[],context,max_bytes=context.profile.limits['result_bytes']),exit_code
    except (OSError,ValueError,TypeError,RuntimeError,KeyError):
        return bootstrap_diagnostic('check'),4
    finally:
        if observation is not None:observation.close()


def doctor(existing: Path | None=None) -> tuple[dict[str, object], int]:
    return ReadOnlyDoctor().inspect(existing),3
