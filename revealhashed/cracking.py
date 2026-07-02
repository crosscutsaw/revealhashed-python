from __future__ import annotations

import csv
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from . import console

EMPTY_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
NO_PASSWORD = "<no password>"

NTDS_LINE_RE = re.compile(r"^[^:\n]+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}")
_STATUS_RE = re.compile(r"\(status=(\w+)\)", re.IGNORECASE)


@dataclass
class CredentialRecord:
    account: str
    domain: str
    password: str
    status: str
    is_computer: bool
    display_name: str


def extract_unique_hashes(
    ntds_path: Path,
    hashes_out: Path,
    individual_out: Optional[Path] = None,
) -> None:
    console.info(f"Extracting unique NT hashes from: {ntds_path}")
    seen: set[str] = set()

    ind_handle = open(individual_out, "w") if individual_out else None
    try:
        with open(ntds_path, "r", errors="replace") as infile, \
                open(hashes_out, "w") as hashfile:
            for line in infile:
                stripped = line.strip()
                if not NTDS_LINE_RE.match(stripped):
                    continue
                if ind_handle:
                    ind_handle.write(line)

                parts = stripped.split(":")
                if len(parts) < 4:
                    continue
                nt_hash = parts[3]
                if re.fullmatch(r"[0-9a-fA-F]{32}", nt_hash) and nt_hash not in seen:
                    seen.add(nt_hash)
                    hashfile.write(nt_hash + "\n")
    except FileNotFoundError:
        console.error(f"File not found: {ntds_path}")
        raise
    finally:
        if ind_handle:
            ind_handle.close()


def run_hashcat(hashes_file: Path, wordlists: List[str]) -> None:
    start = datetime.now().strftime("%H:%M:%S %d.%m.%Y")
    print()
    console.info(f"Starting hashcat session at {start}")

    cmd = ["hashcat", "-m", "1000", str(hashes_file), *map(str, wordlists), "--quiet"]
    try:
        subprocess.run(cmd, check=False)
    except FileNotFoundError:
        console.error("hashcat not found in PATH. Install hashcat and try again.")
        raise

    end = datetime.now().strftime("%H:%M:%S %d.%m.%Y")
    console.info(f"Ended hashcat session at {end}")


def parse_potfile(potfile_path: Path) -> Dict[str, str]:
    cracked: Dict[str, str] = {}
    if not potfile_path.exists():
        return cracked
    with open(potfile_path, "r", errors="replace") as handle:
        for line in handle:
            hash_val, sep, password = line.rstrip("\n").partition(":")
            if sep:
                cracked[hash_val.lower()] = password
    return cracked


def _split_user_field(user_field: str) -> tuple[str, str]:
    if "\\" in user_field:
        domain, account = user_field.split("\\", 1)
        return domain, account
    return "", user_field


def reveal_credentials(
    individual_ntds_path: Path,
    cracked_hashes: Dict[str, str],
    session_dir: Path,
    enabled_only: bool = False,
    no_domain: bool = False,
    to_csv: bool = False,
) -> List[CredentialRecord]:
    print()
    console.info("Revealed credentials:")
    records: List[CredentialRecord] = []
    grouped: Dict[str, List[CredentialRecord]] = defaultdict(list)

    with open(individual_ntds_path, "r", errors="replace") as handle:
        for line in handle:
            parts = line.strip().split(":")
            if len(parts) < 4:
                continue

            user_field = parts[0]
            nt_hash = parts[3].lower()

            status_match = _STATUS_RE.search(line)
            status = status_match.group(1).lower() if status_match else "enabled"

            is_blank = nt_hash == EMPTY_NT_HASH
            if nt_hash not in cracked_hashes and not is_blank:
                continue
            if enabled_only and status != "enabled":
                continue

            password = NO_PASSWORD if is_blank else cracked_hashes[nt_hash]

            domain, account = _split_user_field(user_field)
            is_computer = account.endswith("$")
            bare_account = account.rstrip("$") if is_computer else account

            display_name = account if no_domain else user_field

            record = CredentialRecord(
                account=bare_account,
                domain=domain,
                password=password,
                status=status,
                is_computer=is_computer,
                display_name=display_name,
            )
            records.append(record)
            grouped[password].append(record)

    records.sort(
        key=lambda r: (r.password != NO_PASSWORD, r.password.lower(), r.display_name.lower())
    )

    _print_records(records)
    _write_txt(records, session_dir)
    if to_csv:
        _write_csv(records, session_dir)

    return records


def _format_line(record: CredentialRecord) -> str:
    if record.password == NO_PASSWORD:
        password = f"{console.BOLD_ORANGE}{NO_PASSWORD}{console.RESET}"
    else:
        password = f"{console.BOLD_WHITE}{record.password}{console.RESET}"
    suffix = f" {console.BOLD_RED}<disabled>{console.RESET}" if record.status == "disabled" else ""
    return f"{record.display_name:<40} {password}{suffix}"


def _print_records(records: List[CredentialRecord]) -> None:
    for record in records:
        print(_format_line(record))


def _write_txt(records: List[CredentialRecord], session_dir: Path) -> None:
    output = session_dir / "revealhashed.txt"
    with open(output, "w") as handle:
        for record in records:
            suffix = " <disabled>" if record.status == "disabled" else ""
            handle.write(f"{record.display_name:<40} {record.password}{suffix}\n")
    print()
    console.info(f"Output saved to {output}")


def _write_csv(records: List[CredentialRecord], session_dir: Path) -> None:
    output = session_dir / "revealhashed.csv"
    with open(output, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Username", "Password", "Status"])
        for record in records:
            status = "disabled" if record.status == "disabled" else ""
            writer.writerow([record.display_name, record.password, status])
    console.info(f"Output saved to {output}")
