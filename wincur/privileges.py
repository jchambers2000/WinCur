"""Administrator detection and explicit UAC helper launching."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import uuid
from pathlib import Path


def is_administrator() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def pending_output_path(prefix: str) -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "WinCur" / "pending"
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{prefix}-{uuid.uuid4().hex}.json"


def launch_elevated_helper(arguments: list[str]) -> tuple[bool, str]:
    """Launch a fixed WinCur helper mode through UAC. No shell is involved."""
    if os.name != "nt":
        return False, "Elevation is supported only on Windows."
    frozen = bool(getattr(sys, "frozen", False))
    if frozen:
        executable = str(Path(sys.executable).resolve())
        parameters = subprocess.list2cmdline(arguments)
        working_directory = str(Path(executable).parent)
    else:
        entry = str(Path(__file__).resolve().parent.parent / "main.py")
        if not Path(entry).is_file():
            return False, "The WinCur helper entry point is missing. Reinstall or repair the application."
        executable = sys.executable
        parameters = subprocess.list2cmdline([entry, *arguments])
        working_directory = str(Path(entry).parent)
    try:
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, parameters, working_directory, 0)
    except (AttributeError, OSError) as exc:
        return False, str(exc)
    if result <= 32:
        # ERROR_CANCELLED commonly appears as 1223, but ShellExecute may return a generic code.
        return False, "The UAC request was denied, cancelled, or could not be started."
    return True, "The elevated helper was started."
