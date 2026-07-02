from __future__ import annotations

import os
import sys

_COLOR_ENABLED = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _code(value: str) -> str:
    return value if _COLOR_ENABLED else ""


BOLD_BLUE = _code("\033[1;34m")
BOLD_GREEN = _code("\033[1;32m")
BOLD_ORANGE = _code("\033[1;33m")
BOLD_RED = _code("\033[1;31m")
BOLD_WHITE = _code("\033[1;37m")
RESET = _code("\033[0m")


def info(message: str) -> None:
    # positive / progress
    print(f"{BOLD_GREEN}[+]{RESET} {message}")


def warn(message: str) -> None:
    # non fatal
    print(f"{BOLD_ORANGE}[*]{RESET} {message}")


def error(message: str) -> None:
    # fatal
    print(f"{BOLD_RED}[!]{RESET} {message}")


def miss(message: str) -> None:
    # nf
    print(f"{BOLD_RED}[-]{RESET} {message}")


def prompt(message: str) -> str:
    # prompt
    return input(f"{BOLD_GREEN}[>]{RESET} {message}")


def banner(version: str) -> None:
    print(f"\n{BOLD_BLUE}revealhashed v{version}{RESET}\n")
