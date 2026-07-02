#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from . import __version__, bloodhound, console
from .cracking import (
    extract_unique_hashes,
    parse_potfile,
    reveal_credentials,
    run_hashcat,
)

HOME = Path.home()
TMP_DIR = HOME / ".revealhashed"
DEFAULT_POTFILE = HOME / ".local" / "share" / "hashcat" / "hashcat.potfile"

logging.basicConfig(format="%(name)s %(levelname)s: %(message)s", stream=sys.stderr)
logging.getLogger("impacket").setLevel(logging.WARNING)
logging.getLogger("impacket.examples.secretsdump").setLevel(logging.WARNING)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="revealhashed"
    )
    parser.add_argument("-r", "--reset", action="store_true",
                        help="Delete old session data in ~/.revealhashed")

    subparsers = parser.add_subparsers(dest="command")

    conn = argparse.ArgumentParser(add_help=False)
    conn.add_argument("-debug", action="store_true", help="Turn DEBUG output on")
    conn.add_argument("-hashes", metavar="LMHASH:NTHASH", help="NTLM hashes to authenticate with")
    conn.add_argument("-no-pass", action="store_true", help="Don't prompt for a password")
    conn.add_argument("-k", action="store_true", help="Use Kerberos authentication")
    conn.add_argument("-aesKey", metavar="HEXKEY", help="AES key for Kerberos authentication")
    conn.add_argument("-dc-ip", metavar="IP", dest="dc_ip", help="IP address of the domain controller")
    conn.add_argument("-codec", help="Encoding used for output decoding")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-e", "--enabled-only", action="store_true",
                        help="Only show enabled accounts")
    common.add_argument("-nd", "--no-domain", action="store_true",
                        help="Strip the domain from displayed usernames (output only)")
    common.add_argument("-csv", action="store_true", help="Also save output as CSV")
    common.add_argument("-bh", action="store_true",
                        help="Mark cracked users as owned in BloodHound")
    common.add_argument("--dburi", default="bolt://localhost:7687",
                        help="BloodHound Neo4j URI (default: bolt://localhost:7687)")
    common.add_argument("--dbuser", default="neo4j",
                        help="BloodHound Neo4j username (default: neo4j)")
    common.add_argument("--dbpassword", default="1234",
                        help="BloodHound Neo4j password (default: 1234)")

    dump = subparsers.add_parser(
        "dump", parents=[conn, common],
        help="Dump NTDS from a DC and reveal credentials.",
    )
    dump.add_argument("target", help="[[domain/]username[:password]@]<host>")
    dump.add_argument("-m", "--method", choices=["ntdsutil", "drsuapi", "vss"],
                      default="ntdsutil",
                      help="NTDS dump method (default: ntdsutil)")
    dump.add_argument("-history", action="store_true", help="Dump password history")
    dump.add_argument("-just-dc-user", metavar="USER", dest="just_dc_user",
                      help="Only extract this user's data")
    dump.add_argument("-w", "--wordlists", nargs="+", required=True,
                      metavar="WORDLIST", help="Wordlists to use with hashcat")


    reveal = subparsers.add_parser(
        "reveal", parents=[common],
        help="Reveal credentials from an existing NTDS dump.",
    )
    reveal.add_argument("-ntds", help="Path to a secretsdump .ntds file")
    reveal.add_argument("-nxc", action="store_true",
                        help="Pick a .ntds file from ~/.nxc/logs/ntds")
    reveal.add_argument("-w", "--wordlists", nargs="+", required=False,
                        metavar="WORDLIST", help="Wordlists to use with hashcat")

    return parser

def reset_tmp_dir() -> None:
    if TMP_DIR.exists():
        console.error(f"Deleting old session data in {TMP_DIR}")
        shutil.rmtree(TMP_DIR)
    else:
        console.info("No previous session data found.")


def create_session_dir() -> Path:
    stamp = datetime.now().strftime("%d%m_%H%M%S")
    session_path = TMP_DIR / f"rh_{stamp}"
    session_path.mkdir(parents=True, exist_ok=True)
    return session_path

def _run_pipeline(ntds_source: Path, session_dir: Path, args: argparse.Namespace) -> None:
    hashes_path = session_dir / "rh2cracked.txt"
    individual_path = session_dir / "individual.ntds"

    extract_unique_hashes(ntds_source, hashes_path, individual_path)

    run_hashcat(hashes_path, args.wordlists)
    if DEFAULT_POTFILE.exists():
        shutil.copy(DEFAULT_POTFILE, session_dir)
    cracked = parse_potfile(DEFAULT_POTFILE)
    records = reveal_credentials(
        individual_path,
        cracked,
        session_dir,
        enabled_only=args.enabled_only,
        no_domain=args.no_domain,
        to_csv=args.csv,
    )

    if getattr(args, "bh", False):
        password = args.dbpassword
        if not password:
            from getpass import getpass
            password = getpass("BloodHound Neo4j password: ")
        bloodhound.mark_owned(
            records,
            uri=args.dburi,
            user=args.dbuser,
            password=password,
        )

def _cmd_dump(args: argparse.Namespace) -> None:
    from .dumping import Target, dump_ntds

    session_dir = create_session_dir()
    target = Target.from_options(args)

    start = datetime.now().strftime("%H:%M:%S %d.%m.%Y")
    console.info(f"Starting NTDS dump ({args.method}) at {start}")
    try:
        ntds_source = dump_ntds(
            args.method, target, session_dir,
            history=args.history, just_user=args.just_dc_user,
        )
    except Exception as exc:
        console.error(f"NTDS dump failed: {exc}")
        return
    end = datetime.now().strftime("%H:%M:%S %d.%m.%Y")
    console.info(f"NTDS successfully dumped at {end}")

    _run_pipeline(ntds_source, session_dir, args)


def _select_nxc_ntds() -> Optional[Path]:
    nxc_dir = HOME / ".nxc" / "logs" / "ntds"
    ntds_files = sorted(nxc_dir.glob("*.ntds"))
    if not ntds_files:
        console.error(f"No .ntds files found in {nxc_dir}")
        return None

    console.info(f"Found {len(ntds_files)} .ntds files in {nxc_dir}")
    for index, path in enumerate(ntds_files):
        print(f"[{index}] {path.name}")

    while True:
        try:
            selection = int(console.prompt("Select file by index: "))
            if 0 <= selection < len(ntds_files):
                return ntds_files[selection]
            console.error("Invalid selection. Try again.")
        except ValueError:
            console.error("Please enter a valid number.")


def _cmd_reveal(args: argparse.Namespace) -> None:
    if args.nxc:
        ntds_path = _select_nxc_ntds()
        if ntds_path is None:
            sys.exit(1)
    elif args.ntds:
        ntds_path = Path(args.ntds)
    else:
        console.error("Please specify either -ntds or -nxc")
        sys.exit(1)

    if not args.wordlists:
        console.error("No wordlists provided. Use -w to specify at least one wordlist.")
        return

    if not ntds_path.exists():
        console.error(f"NTDS file not found: {ntds_path}")
        return

    session_dir = create_session_dir()
    _run_pipeline(ntds_path, session_dir, args)

def main(argv: Optional[List[str]] = None) -> None:
    console.banner(__version__)

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command and not args.reset:
        parser.print_help()
        sys.exit(0)

    if getattr(args, "debug", False):
        imp_log = logging.getLogger("impacket")
        imp_log.setLevel(logging.DEBUG)
        for _h in imp_log.handlers:
            _h.setLevel(logging.DEBUG)

    if args.reset:
        reset_tmp_dir()
        return

    TMP_DIR.mkdir(parents=True, exist_ok=True)

    if args.command == "dump":
        _cmd_dump(args)
    elif args.command == "reveal":
        _cmd_reveal(args)


if __name__ == "__main__":
    main()
