"""Terminal UI helpers for PrimitiveMail installer."""

import os
import sys
import subprocess
import time
import threading

BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[38;2;74;222;128m"
RED = "\033[38;2;248;113;113m"
YELLOW = "\033[38;2;250;204;21m"
BLUE = "\033[38;2;96;165;250m"
MUTED = "\033[38;2;113;113;122m"
NC = "\033[0m"


def info(msg: str) -> None:
    print(f"{MUTED}.{NC} {msg}")


def success(msg: str) -> None:
    print(f"{GREEN}+{NC} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}!{NC} {msg}")


def error(msg: str) -> None:
    print(f"{RED}x{NC} {msg}")


def step(msg: str) -> None:
    print(f"{BLUE}>{NC} {BOLD}{msg}{NC}")


def _get_tty_input(prompt_text: str) -> str:
    """Read a line from /dev/tty (works under curl|bash where stdin is the pipe).
    Falls back to sys.stdin if /dev/tty is unavailable."""
    try:
        tty = open("/dev/tty", "r")
        sys.stderr.write(prompt_text)
        sys.stderr.flush()
        line = tty.readline().rstrip("\n")
        tty.close()
        return line
    except OSError:
        return input(prompt_text)


def prompt_value(prompt_text: str, default: str, no_prompt: bool) -> str:
    if no_prompt:
        return default
    display_default = f" {DIM}({default}){NC}" if default else ""
    raw = _get_tty_input(f"  {prompt_text}{display_default}: ")
    return raw if raw else default


def prompt_yn(prompt_text: str, default: str, no_prompt: bool) -> bool:
    if no_prompt:
        return default == "y"
    hint = "Y/n" if default == "y" else "y/N"
    raw = _get_tty_input(f"  {prompt_text} {DIM}({hint}){NC}: ")
    choice = raw.strip().lower() if raw.strip() else default
    return choice == "y"


def prompt_choice(prompt_text: str, max_val: int, default: int, no_prompt: bool) -> int:
    if no_prompt:
        return default
    raw = _get_tty_input(f"  {prompt_text} {DIM}(default {default}){NC}: ")
    raw = raw.strip()
    if raw.isdigit():
        val = int(raw)
        if 1 <= val <= max_val:
            return val
    return default


def run_with_progress(cmd: list, label: str, verbose: bool = False) -> None:
    """Run a command with a braille spinner. On failure, print last 20 lines and exit."""
    if verbose:
        result = subprocess.run(cmd)
        if result.returncode != 0:
            error(f"{label} failed")
            sys.exit(1)
        success(f"{label} complete")
        return

    spin_chars = "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f"
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    stop = threading.Event()
    elapsed = [0]

    def spinner():
        i = 0
        ticks = 0
        while not stop.is_set():
            c = spin_chars[i % len(spin_chars)]
            sys.stderr.write(f"\r  {MUTED}{c}{NC} {label} {DIM}({elapsed[0]}s){NC}  ")
            sys.stderr.flush()
            stop.wait(0.1)
            ticks += 1
            elapsed[0] = ticks // 10
            i += 1

    t = threading.Thread(target=spinner, daemon=True)
    t.start()

    output, _ = process.communicate()
    stop.set()
    t.join()

    sys.stderr.write("\r\033[K")
    sys.stderr.flush()

    if process.returncode == 0:
        success(f"{label} complete ({elapsed[0]}s)")
    else:
        error(f"{label} failed")
        print()
        lines = output.decode("utf-8", errors="replace").splitlines()
        for line in lines[-20:]:
            print(f"  {line}")
        sys.exit(1)
