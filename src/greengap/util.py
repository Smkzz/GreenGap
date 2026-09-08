"""Shared path, subprocess, and deterministic serialization helpers."""

from __future__ import annotations

import json
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import unicodedata
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any

MAX_CONFIG_BYTES = 1 * 1024 * 1024
MAX_JUNIT_BYTES = 8 * 1024 * 1024
MAX_JUNIT_CASES = 100_000
MAX_MATRIX_ROWS = 256
MAX_WORKFLOW_FILES = 1_024
MAX_WORKSPACE_FILES = 100_000
MAX_WORKSPACE_FILE_BYTES = 8 * 1024 * 1024
MAX_WORKSPACE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_COLLECTION_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_COLLECTION_SECONDS = 300.0
MAX_PROCESS_TREE_NODES = 4_096
MAX_PROCESS_TREE_BYTES = 256 * 1024
MAX_CHANGED_FILES = 3_000
MAX_CHANGED_FILE_BYTES = 4 * 1024 * 1024
MAX_PATH_INVENTORY_BYTES = 64 * 1024 * 1024
MAX_PATH_INVENTORY_ITEMS = MAX_WORKSPACE_FILES


class PathSafetyError(ValueError):
    """A path is outside the repository or crosses a symlink boundary."""


class PathInventoryLimitError(ValueError):
    """Repository path enumeration exceeded a bounded evidence budget."""


def as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def terminal_safe_text(value: str) -> str:
    """Escape control and Unicode format characters before human output."""

    safe: list[str] = []
    for character in value:
        if unicodedata.category(character).startswith("C"):
            codepoint = ord(character)
            if codepoint <= 0xFF:
                safe.append(f"\\x{codepoint:02x}")
            else:
                safe.append(f"\\u{codepoint:04x}")
        else:
            safe.append(character)
    return "".join(safe)


def relpath(root: Path, path: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError:
        relative = path
    value = relative.as_posix()
    return value[2:] if value.startswith("./") else value


def safe_resolve(root: Path, value: str | Path, base: Path | None = None) -> Path:
    """Resolve a repository path without crossing symlinks or the root boundary."""

    root_absolute = Path(os.path.abspath(root))
    root_real = root_absolute.resolve(strict=False)
    raw = Path(value)
    if not raw.is_absolute():
        raw = (base or root_absolute) / raw
    lexical = Path(os.path.abspath(raw))
    try:
        relative = lexical.relative_to(root_absolute)
    except ValueError as exc:
        raise PathSafetyError(f"path escapes repository root: {value}") from exc

    current = root_absolute
    for part in relative.parts:
        current /= part
        try:
            if current.is_symlink():
                raise PathSafetyError(f"path crosses symlink: {current}")
        except OSError as exc:
            raise PathSafetyError(f"could not inspect path: {current}: {exc}") from exc

    resolved = lexical.resolve(strict=False)
    try:
        resolved.relative_to(root_real)
    except ValueError as exc:
        raise PathSafetyError(f"resolved path escapes repository root: {value}") from exc
    return resolved


def normalize_repo_path(root: Path, value: str | Path, base: Path | None = None) -> str:
    return relpath(root, safe_resolve(root, value, base))


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
    )


def read_limited_bytes(path: Path, limit: int) -> bytes:
    """Read regular-file bytes or stable symlink metadata without following links."""

    for parent in path.parents:
        try:
            if stat.S_ISLNK(parent.lstat().st_mode):
                raise ValueError(f"path crosses symlink: {parent}")
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ValueError(f"could not inspect {parent}: {exc}") from exc
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError(f"could not inspect {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode):
        try:
            target = os.readlink(path)
        except OSError as exc:
            raise ValueError(f"could not read symlink {path}: {exc}") from exc
        encoded = os.fsencode(target)
        if len(encoded) + len(b"SYMLINK\0") > limit:
            raise ValueError(f"symlink target exceeds size limit: {path}")
        try:
            if _file_identity(info) != _file_identity(path.lstat()):
                raise ValueError(f"symlink changed during inspection: {path}")
        except OSError as exc:
            raise ValueError(f"could not recheck symlink {path}: {exc}") from exc
        return b"SYMLINK\0" + encoded
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"unsupported non-regular file: {path}")
    if info.st_size > limit:
        raise ValueError(f"file exceeds size limit: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened_info = os.fstat(descriptor)
        if _file_identity(info) != _file_identity(opened_info):
            raise ValueError(f"file changed during inspection: {path}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            data = handle.read(limit + 1)
            closed_info = os.fstat(handle.fileno())
        if _file_identity(info) != _file_identity(closed_info):
            raise ValueError(f"file changed during inspection: {path}")
        if _file_identity(info) != _file_identity(path.lstat()):
            raise ValueError(f"file path changed during inspection: {path}")
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"could not read {path}: {exc}") from exc
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
    if len(data) > limit:
        raise ValueError(f"file exceeds size limit: {path}")
    return data


def read_limited_text(path: Path, limit: int) -> str:
    return read_limited_bytes(path, limit).decode("utf-8", errors="strict")


def is_transient_path(path: str | Path) -> bool:
    transient = {
        ".git",
        ".tox",
        ".nox",
        ".venv",
        "venv",
        "node_modules",
        "build",
        "dist",
        ".eggs",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".cache",
        "htmlcov",
        "coverage",
        "reports/raw",
        "qualification/clones",
        "qualification/envs",
    }
    parts = Path(str(path).replace("\\", "/")).parts
    lowered = {part.lower() for part in parts}
    if lowered & transient:
        return True
    normalized = "/".join(part.lower() for part in parts)
    if normalized.startswith("qualification/stage0f"):
        return True
    return any(normalized == item or normalized.startswith(item + "/") for item in transient)


def process_group_options() -> dict[str, Any]:
    """Start a child in a process group that can be terminated as one unit."""

    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True, "preexec_fn": _set_parent_death_signal}


def _set_parent_death_signal() -> None:
    """Ask POSIX children to terminate if the analyzer parent disappears."""

    if os.name != "posix" or not sys.platform.startswith("linux"):
        return
    try:
        import ctypes

        libc = ctypes.CDLL(None)
        prctl = getattr(libc, "prctl", None)
        if prctl is None:
            raise OSError("Linux prctl is unavailable")
        prctl.argtypes = [ctypes.c_int, ctypes.c_ulong]
        prctl.restype = ctypes.c_int
        result = prctl(1, getattr(signal, "SIGKILL", 9))  # PR_SET_PDEATHSIG
        if result != 0:
            raise OSError("Linux prctl(PR_SET_PDEATHSIG) failed")
    except Exception as exc:
        raise OSError("could not configure Linux parent-death cleanup") from exc


def _process_children(parent_pid: int) -> tuple[int, ...]:
    proc_children = Path("/proc") / str(parent_pid) / "task" / str(parent_pid) / "children"
    if proc_children.is_file():
        try:
            with proc_children.open("rb") as handle:
                raw = handle.read(MAX_PROCESS_TREE_BYTES + 1)
        except OSError:
            return ()
        if len(raw) > MAX_PROCESS_TREE_BYTES:
            return ()
        children: list[int] = []
        for token in raw.split():
            try:
                children.append(int(token))
            except ValueError:
                continue
        return tuple(children)
    return ()


def _descendant_process_ids(root_pid: int) -> tuple[int, ...]:
    """Collect a bounded POSIX process tree before its root is terminated."""

    pending = [root_pid]
    seen = {root_pid}
    descendants: list[int] = []
    while pending and len(seen) <= MAX_PROCESS_TREE_NODES:
        parent_pid = pending.pop()
        for child_pid in _process_children(parent_pid):
            if child_pid in seen:
                continue
            seen.add(child_pid)
            descendants.append(child_pid)
            pending.append(child_pid)
            if len(seen) > MAX_PROCESS_TREE_NODES:
                break
    return tuple(descendants[:MAX_PROCESS_TREE_NODES])


def _pid_is_alive(pid: int) -> bool:
    proc_status = Path("/proc") / str(pid) / "stat"
    if proc_status.is_file():
        try:
            fields = proc_status.read_text(encoding="utf-8", errors="replace").split()
        except OSError:
            fields = []
        if len(fields) > 2 and fields[2] == "Z":
            return False
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def terminate_process_tree(
    process: subprocess.Popen[Any], known_descendants: Sequence[int] = ()
) -> bool:
    """Terminate a process and descendants, including descendants in new groups.

    The caller must have started ``process`` with :func:`process_group_options`.
    On POSIX, the descendant snapshot is taken before the root process is killed
    because a nested collector may have started a separate process session.
    """

    root_pid = process.pid
    descendant_ids = set(known_descendants)
    descendant_ids.update(_descendant_process_ids(root_pid))
    descendants = tuple(descendant_ids)
    if os.name == "nt":
        for pid in (root_pid, *reversed(descendants)):
            if pid != root_pid and not _pid_is_alive(pid):
                continue
            with suppress(OSError, subprocess.TimeoutExpired):
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=5,
                )
    else:
        sigterm = getattr(signal, "SIGTERM", 15)
        sigkill = getattr(signal, "SIGKILL", 9)
        killpg = getattr(os, "killpg", None)
        for pid in reversed(descendants):
            with suppress(OSError, ProcessLookupError):
                os.kill(pid, sigterm)
        try:
            if callable(killpg):
                killpg(root_pid, sigterm)
            else:
                process.terminate()
        except (OSError, ProcessLookupError):
            with suppress(OSError):
                process.terminate()
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1.0)
        for pid in reversed(descendants):
            with suppress(OSError, ProcessLookupError):
                os.kill(pid, sigkill)
        with suppress(OSError, ProcessLookupError):
            if callable(killpg):
                killpg(root_pid, sigkill)
    with suppress(subprocess.TimeoutExpired):
        process.wait(timeout=2.0)
    return process.poll() is not None and not any(_pid_is_alive(pid) for pid in descendants)


def run_process_tree(
    args: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    """Run a command with a timeout that also reaps its descendant tree."""

    process = subprocess.Popen(
        list(args),
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **process_group_options(),
    )
    known_descendants: set[int] = set(_descendant_process_ids(process.pid))
    monitor_stop = threading.Event()
    monitor_lock = threading.Lock()

    def monitor_tree() -> None:
        while not monitor_stop.is_set():
            discovered = _descendant_process_ids(process.pid)
            if discovered:
                with monitor_lock:
                    known_descendants.update(discovered)
            monitor_stop.wait(0.05)

    monitor = threading.Thread(target=monitor_tree, name="greengap-process-tree", daemon=True)
    monitor.start()
    windows_job: Any | None = None
    windows_job_closer: Any | None = None
    if os.name == "nt":
        # Reuse the collector's kill-on-close Job Object so descendants that
        # start a new process group cannot escape the outer qualification gate.
        from .pytest_adapter import _close_windows_job, _create_windows_job

        windows_job = _create_windows_job(process)
        windows_job_closer = _close_windows_job
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        monitor_stop.set()
        monitor.join(timeout=1.0)
        with monitor_lock:
            tracked = tuple(known_descendants)
        if windows_job is not None and windows_job_closer is not None:
            windows_job_closer(windows_job)
            windows_job = None
        else:
            terminate_process_tree(process, tracked)
        stdout, stderr = process.communicate(timeout=5.0)
        raise subprocess.TimeoutExpired(args, timeout, output=stdout, stderr=stderr) from exc
    finally:
        monitor_stop.set()
        monitor.join(timeout=1.0)
        if windows_job is not None and windows_job_closer is not None:
            windows_job_closer(windows_job)
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def bounded_command_output(
    args: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    max_bytes: int = MAX_PATH_INVENTORY_BYTES,
) -> tuple[bytes, bool, bool, int | None] | None:
    """Capture a subprocess byte stream without an unbounded pipe buffer."""

    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    try:
        process = subprocess.Popen(
            list(args),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None

    output = bytearray()
    output_limited = False

    def drain() -> None:
        nonlocal output_limited
        stream = process.stdout
        if stream is None:
            return
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            remaining = max_bytes - len(output)
            if len(chunk) > remaining:
                if remaining > 0:
                    output.extend(chunk[:remaining])
                output_limited = True
                with suppress(OSError):
                    process.kill()
                return
            output.extend(chunk)

    reader = threading.Thread(target=drain, name="greengap-bounded-output", daemon=True)
    reader.start()
    reader.join(max(timeout, 0.01))
    timed_out = reader.is_alive()
    if timed_out:
        with suppress(OSError):
            process.kill()
        reader.join(1.0)
    try:
        returncode = process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        with suppress(OSError):
            process.kill()
        returncode = None
    if process.stdout is not None:
        process.stdout.close()
    return bytes(output), output_limited, timed_out, returncode


def bounded_git_paths(
    root: Path,
    timeout: float,
    *,
    max_items: int | None = None,
) -> tuple[tuple[str, ...], str | None] | None:
    """Enumerate Git paths with byte and item limits.

    ``None`` means Git could not provide an inventory and callers may use a
    filesystem fallback.  A non-None error means Git was usable but the
    inventory itself was incomplete and must remain fail-closed.
    """

    item_limit = MAX_PATH_INVENTORY_ITEMS if max_items is None else max_items
    result = bounded_command_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        timeout=timeout,
    )
    if result is None:
        return None
    raw, output_limited, timed_out, returncode = result
    if timed_out or returncode != 0:
        return None

    paths: list[str] = []
    inventory_items = 0
    for item in raw.split(b"\0"):
        if not item:
            continue
        inventory_items += 1
        if inventory_items > item_limit:
            return tuple(paths), f"path inventory exceeds limit of {item_limit} files"
        path = os.fsdecode(item)
        if not is_transient_path(path):
            paths.append(path)
    if output_limited or (raw and not raw.endswith(b"\0")):
        return tuple(paths), f"path inventory exceeds byte limit of {MAX_PATH_INVENTORY_BYTES}"
    return tuple(paths), None


def git_workspace_clean(root: Path, timeout: float = 10.0) -> bool | None:
    """Return whether checkout-clean semantics would preserve this workspace."""

    for command in (
        ["git", "diff", "--quiet", "--no-ext-diff", "HEAD"],
        ["git", "diff", "--cached", "--quiet", "--no-ext-diff", "HEAD"],
    ):
        try:
            clean_result = subprocess.run(
                command,
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if clean_result.returncode == 1:
            return False
        if clean_result.returncode != 0:
            return None

    output_result = bounded_command_output(
        ["git", "ls-files", "--others", "--ignored", "--exclude-standard", "-z"],
        cwd=root,
        timeout=timeout,
    )
    if output_result is None:
        return None
    raw, output_limited, timed_out, returncode = output_result
    if timed_out or output_limited or returncode != 0:
        return None
    return not any(item for item in raw.split(b"\0") if item)


def bounded_filesystem_paths(
    root: Path,
    *,
    max_items: int | None = None,
) -> tuple[tuple[str, ...], str | None]:
    """Walk regular and symlink files without unbounded path accumulation."""

    item_limit = MAX_PATH_INVENTORY_ITEMS if max_items is None else max_items
    directories: list[Path] = [root]
    paths: list[str] = []
    inspected_directories = 0
    while directories:
        directory = directories.pop()
        inspected_directories += 1
        if inspected_directories > item_limit:
            return tuple(sorted(paths)), f"path inventory exceeds directory limit of {item_limit}"
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    relative = Path(os.path.relpath(entry.path, root))
                    if is_transient_path(relative):
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            directories.append(Path(entry.path))
                            continue
                        if entry.is_symlink() and entry.is_dir(follow_symlinks=True):
                            continue
                        if not entry.is_file(follow_symlinks=False) and not entry.is_symlink():
                            continue
                    except OSError:
                        return tuple(sorted(paths)), "filesystem path enumeration failed"
                    if len(paths) >= item_limit:
                        return tuple(sorted(paths)), f"path inventory exceeds limit of {item_limit} files"
                    paths.append(relative.as_posix())
        except OSError:
            return tuple(sorted(paths)), "filesystem path enumeration failed"
    return tuple(sorted(paths)), None


def run_command(
    args: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def json_dump(value: Any) -> str:
    # Escaping non-ASCII characters keeps JSON output usable on legacy Windows
    # consoles whose active code page cannot encode arbitrary repository paths.
    return json.dumps(
        value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False
    ) + "\n"


def split_patterns(value: Any, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default
    if isinstance(value, str):
        parts = tuple(part for part in re.split(r"[\s,]+", value.strip()) if part)
        return parts or default
    if isinstance(value, list | tuple):
        parts = tuple(str(part) for part in value if str(part))
        return parts or default
    return default
