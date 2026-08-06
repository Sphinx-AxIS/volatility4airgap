"""A bounded pool of Volatility subprocesses.

One process per plugin, for fault isolation: a segmentation fault inside yara or
capstone kills one plugin rather than the run. That also makes parallelism a
scheduling concern instead of a structural one.

**Child output goes to files, never pipes.** The original CORE-Respond runner
called a blocking ``proc.stdout.read()`` before ``proc.wait(timeout=...)``, so a
hung plugin blocked in ``read()`` and the timeout could never fire. With no pipe
there is no buffer to fill, no reader thread, and nothing to block on — polling
``proc.poll()`` against a deadline enforces the timeout reliably. The bug cannot
be reintroduced here because there is no ``read()`` to get stuck in.

Plain ``subprocess`` rather than ``multiprocessing``: on Windows the latter uses
spawn semantics that re-import ``__main__`` and expect ``freeze_support()``, which
is fragile inside an embedded interpreter. The parent only starts processes and
waits, so a scheduler over ``Popen`` handles is simpler and has no such failure
mode.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

POLL_INTERVAL = 0.05


@dataclass(frozen=True)
class Task:
    key: str
    label: str
    command: list[str]
    stdout_path: Path
    stderr_path: Path


@dataclass
class TaskResult:
    task: Task
    returncode: int | None = None
    duration: float = 0.0
    timed_out: bool = False
    error: str | None = None
    output_bytes: int = 0

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.error is None

    @property
    def status(self) -> str:
        if self.timed_out:
            return "timeout"
        if self.error:
            return "error"
        return "ok" if self.returncode == 0 else f"exit {self.returncode}"


@dataclass
class _Running:
    task: Task
    process: subprocess.Popen
    started: float
    handles: list = field(default_factory=list)


def resolve_jobs(requested: str | int) -> int:
    """``--jobs N`` or ``auto``. Default is 1; auto stays deliberately modest.

    Every plugin streams the same multi-gigabyte image. On NVMe with enough RAM
    the page cache absorbs that and more workers help; on a USB-attached evidence
    drive they contend and can run slower than one. Capping auto at 4 keeps the
    default from being actively harmful on slow media.
    """
    if isinstance(requested, int):
        value = requested
    elif str(requested).strip().lower() == "auto":
        value = min(max((os.cpu_count() or 2) - 1, 1), 4)
    else:
        value = int(requested)

    if value < 1:
        raise ValueError("--jobs must be at least 1")
    return value


def run_tasks(
    tasks: Sequence[Task],
    *,
    jobs: int = 1,
    timeout: float = 3600.0,
    env: dict | None = None,
    on_start: Callable[[Task], None] | None = None,
    on_finish: Callable[[TaskResult], None] | None = None,
) -> list[TaskResult]:
    """Run tasks with at most ``jobs`` in flight, returning results in task order."""
    pending = list(tasks)
    running: list[_Running] = []
    results: dict[str, TaskResult] = {}

    def launch(task: Task) -> None:
        task.stdout_path.parent.mkdir(parents=True, exist_ok=True)
        task.stderr_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            out = open(task.stdout_path, "wb")
            err = open(task.stderr_path, "wb")
        except OSError as exc:
            results[task.key] = TaskResult(task, error=f"cannot open output: {exc}")
            return

        try:
            process = subprocess.Popen(task.command, stdout=out, stderr=err, env=env)
        except OSError as exc:
            out.close()
            err.close()
            results[task.key] = TaskResult(task, error=f"cannot start: {exc}")
            return

        if on_start is not None:
            on_start(task)
        running.append(_Running(task, process, time.monotonic(), [out, err]))

    def finish(entry: _Running, *, timed_out: bool) -> None:
        for handle in entry.handles:
            try:
                handle.close()
            except OSError:
                pass

        try:
            size = entry.task.stdout_path.stat().st_size
        except OSError:
            size = 0

        result = TaskResult(
            entry.task,
            returncode=entry.process.returncode,
            duration=time.monotonic() - entry.started,
            timed_out=timed_out,
            output_bytes=size,
        )
        results[entry.task.key] = result
        if on_finish is not None:
            on_finish(result)

    while pending or running:
        while pending and len(running) < jobs:
            launch(pending.pop(0))

        if not running:
            continue

        time.sleep(POLL_INTERVAL)
        now = time.monotonic()

        for entry in list(running):
            if entry.process.poll() is not None:
                running.remove(entry)
                finish(entry, timed_out=False)
            elif now - entry.started > timeout:
                entry.process.kill()
                try:
                    entry.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                running.remove(entry)
                finish(entry, timed_out=True)

    return [results[task.key] for task in tasks if task.key in results]
