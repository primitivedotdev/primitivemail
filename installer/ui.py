"""Terminal UI helpers for PrimitiveMail installer."""

import json as _json
import sys
import subprocess
import threading
import time

BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[38;2;74;222;128m"
RED = "\033[38;2;248;113;113m"
YELLOW = "\033[38;2;250;204;21m"
BLUE = "\033[38;2;96;165;250m"
MUTED = "\033[38;2;113;113;122m"
NC = "\033[0m"

# JSON mode: stdout is reserved for NDJSON events. Human-readable output
# (info, success, warn, error, step, and any bare print() from display
# helpers) gets redirected to stderr by swapping sys.stdout at enable time.
# NDJSON events go through the saved original stdout in json_event().
JSON_MODE = False
_JSON_STDOUT = None  # original sys.stdout, captured at enable time


def enable_json_mode() -> None:
    """Flip to JSON output mode. Redirects sys.stdout to sys.stderr so every
    existing print() call (including ones we don't control) goes to stderr;
    NDJSON events are written directly to the preserved original stdout."""
    global JSON_MODE, _JSON_STDOUT
    JSON_MODE = True
    _JSON_STDOUT = sys.stdout
    sys.stdout = sys.stderr


def _human_out(msg: str) -> None:
    print(msg)


def line(msg: str = "") -> None:
    """Emit a decorative line. Goes to stderr in JSON mode via the stdout swap."""
    print(msg)


def json_event(event: str, **fields) -> None:
    """Emit a single NDJSON event to the preserved stdout when JSON_MODE is on."""
    if not JSON_MODE or _JSON_STDOUT is None:
        return
    payload = {"event": event, **fields}
    _JSON_STDOUT.write(_json.dumps(payload, separators=(",", ":")) + "\n")
    _JSON_STDOUT.flush()


class HeartbeatTicker:
    """Emits `step_progress` NDJSON events every `interval` seconds while active.

    Use as a context manager around a long-running step so agents consuming
    the `--json` stream see periodic proof-of-life rather than silence between
    `step/start` and `step/ok`. No-op when JSON_MODE is off.

    The event has shape {"event":"step_progress","name":"<step>","elapsed_sec":N}.
    `name` matches the enclosing `step/start` event; `elapsed_sec` is seconds
    since the ticker was started, monotonic, int.
    """

    def __init__(self, name: str, interval: float = 15.0):
        self._name = name
        self._interval = interval
        self._stop = threading.Event()
        self._thread: "threading.Thread | None" = None
        self._started_at: "float | None" = None

    def __enter__(self) -> "HeartbeatTicker":
        if not JSON_MODE:
            return self
        self._started_at = time.monotonic()
        self._stop.clear()
        self._thread = threading.Thread(target=self._tick, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        if self._thread is None:
            return
        # Signal stop and wait bounded — if emit is in-flight, let it finish
        # so the terminal step event (emitted by the caller) never precedes
        # a heartbeat that was already queued.
        self._stop.set()
        self._thread.join(timeout=2.0)
        self._thread = None

    def _tick(self) -> None:
        # First heartbeat fires at t=interval, not t=0 — fast steps emit zero.
        while not self._stop.wait(self._interval):
            elapsed = int(time.monotonic() - (self._started_at or 0))
            json_event("step_progress", name=self._name, elapsed_sec=elapsed)


def info(msg: str) -> None:
    _human_out(f"{MUTED}.{NC} {msg}")


def success(msg: str) -> None:
    _human_out(f"{GREEN}+{NC} {msg}")


def warn(msg: str) -> None:
    _human_out(f"{YELLOW}!{NC} {msg}")


def error(msg: str) -> None:
    # No automatic json_event here — callers decide whether an error is
    # terminal-with-a-JSON-event or recoverable. Terminal exit sites should
    # emit `json_event("step", ..., status="fail")` and/or `json_event("error", ...)`
    # explicitly before calling sys.exit(). Keeping this human-only avoids
    # stray `event: error` lines in successful runs.
    _human_out(f"{RED}x{NC} {msg}")


def step(msg: str) -> None:
    _human_out(f"{BLUE}>{NC} {BOLD}{msg}{NC}")


def _get_tty_input(prompt_text: str) -> str:
    """Read a line from /dev/tty (works under curl|bash where stdin is the pipe).
    Falls back to sys.stdin if /dev/tty is unavailable."""
    try:
        with open("/dev/tty", "r") as tty:
            sys.stderr.write(prompt_text)
            sys.stderr.flush()
            return tty.readline().rstrip("\n")
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


def run_with_progress(
    cmd: list,
    label: str,
    verbose: bool = False,
    cwd: str = None,
    step_name: str = "",
) -> None:
    """Run a command with a braille spinner. On failure, print last 20 lines and exit.

    `label` is human-readable (e.g. "Building"). `step_name` is the JSON-mode
    event name (e.g. "build") that matches the public contract used by the
    enclosing step-start/step-ok pair; pass it so the fail event is keyed
    consistently and agents filtering on step="build" don't miss it.
    """
    # JSON mode takes precedence over --verbose: we need a clean NDJSON stdout,
    # and subprocesses inherit fd 1 regardless of Python's sys.stdout swap — so
    # letting subprocess.run() run unrestricted would write docker build output
    # straight to the real stdout and corrupt the event stream.
    if JSON_MODE:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd)
        output, _ = process.communicate()
        if process.returncode == 0:
            success(f"{label} complete")
        else:
            lines = output.decode("utf-8", errors="replace").splitlines()
            tail = "\n".join(lines[-20:])
            # Close the outer step-start event first so agents consuming the
            # NDJSON stream see a terminal fail before the error detail.
            fail_step = step_name or label.lower()
            json_event("step", name=fail_step, status="fail")
            json_event("error", step=fail_step, message=f"{label} failed", tail=tail)
            error(f"{label} failed")
            sys.exit(1)
        return

    if verbose:
        result = subprocess.run(cmd, cwd=cwd)
        if result.returncode != 0:
            error(f"{label} failed")
            sys.exit(1)
        success(f"{label} complete")
        return

    spin_chars = "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f"
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd)

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
