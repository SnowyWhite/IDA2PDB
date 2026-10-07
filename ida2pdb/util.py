"""Process, file and path helpers shared by the CLI, the builder and the plugin."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from .errors import ExportError


def distinct_paths(inputs, outputs):
    """Refuse an output that would overwrite an input or another output."""
    paths = {Path(p).resolve() for p in inputs if p is not None}
    for output in outputs:
        if output is None:
            continue
        path = Path(output).resolve()
        if path in paths:
            raise ExportError(f"output path would overwrite another input/output: {path}")
        paths.add(path)


def run(command, *, env=None, cwd=None, timeout=300, check=True, cancel_event=None):
    """Run a program to completion and capture its output.

    The program is killed when cancel_event is set or the timeout expires, so
    that neither a cancelled plugin export nor a hung tool leaves a process
    behind. With check, a non-zero exit is an ExportError that carries the end
    of the program's output.
    """
    if cancel_event is not None and cancel_event.is_set():
        raise ExportError("export cancelled")
    try:
        with subprocess.Popen([str(a) for a in command], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, encoding="utf-8", errors="replace", env=env, cwd=cwd,
                              creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0) as process:
            deadline = time.monotonic() + timeout
            try:
                while True:
                    if cancel_event is not None and cancel_event.is_set():
                        raise ExportError("export cancelled")
                    if time.monotonic() >= deadline:
                        raise ExportError(f"{command[0]} exceeded the {timeout}s timeout")
                    # Poll in short slices; communicate() may be resumed after
                    # a timeout without losing output.
                    try:
                        stdout, stderr = process.communicate(timeout=min(0.2, max(0.001, deadline - time.monotonic())))
                        break
                    except subprocess.TimeoutExpired:
                        pass
            except BaseException:
                process.kill()
                process.communicate()
                raise
    except OSError as e:
        raise ExportError(f"cannot run {command[0]}: {e}") from e
    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    if check and result.returncode:
        raise ExportError(f"{Path(command[0]).name} failed ({result.returncode}):\n"
                          + (result.stdout + result.stderr).strip()[-12000:])
    return result


def write_json(path, value):
    """Write JSON atomically: readers see the old file or the new one, never a part."""
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(value, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
