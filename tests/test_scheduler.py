"""Tests for the bounded subprocess pool.

The headline test is ``test_a_chatty_hung_child_still_times_out``. The original
CORE-Respond runner blocked in ``proc.stdout.read()`` before ``proc.wait(timeout=)``,
so a plugin that produced output and then hung could never be killed. Redirecting
to files removes the pipe and with it the deadlock; this proves it.
"""

from __future__ import annotations

import sys
import time

import pytest

from app import scheduler


def python_task(key, tmp_path, code, *, label=None) -> scheduler.Task:
    return scheduler.Task(
        key=key,
        label=label or key,
        command=[sys.executable, "-c", code],
        stdout_path=tmp_path / f"{key}.out",
        stderr_path=tmp_path / "logs" / f"{key}.log",
    )


class TestBasicExecution:
    def test_captures_stdout_to_a_file(self, tmp_path) -> None:
        task = python_task("a", tmp_path, "print('hello output')")
        (result,) = scheduler.run_tasks([task])

        assert result.ok
        assert "hello output" in task.stdout_path.read_text()
        assert result.output_bytes > 0

    def test_captures_stderr_separately(self, tmp_path) -> None:
        task = python_task("a", tmp_path, "import sys; sys.stderr.write('a problem')")
        (result,) = scheduler.run_tasks([task])

        assert "a problem" in task.stderr_path.read_text()
        assert task.stdout_path.read_bytes() == b""

    def test_reports_a_nonzero_exit(self, tmp_path) -> None:
        task = python_task("a", tmp_path, "raise SystemExit(3)")
        (result,) = scheduler.run_tasks([task])

        assert not result.ok
        assert result.returncode == 3
        assert result.status == "exit 3"

    def test_results_follow_task_order(self, tmp_path) -> None:
        tasks = [
            python_task("slow", tmp_path, "import time; time.sleep(0.3); print(1)"),
            python_task("fast", tmp_path, "print(2)"),
        ]
        results = scheduler.run_tasks(tasks, jobs=2)

        assert [r.task.key for r in results] == ["slow", "fast"]

    def test_a_command_that_cannot_start_is_reported(self, tmp_path) -> None:
        task = scheduler.Task(
            key="missing",
            label="missing",
            command=[str(tmp_path / "does-not-exist")],
            stdout_path=tmp_path / "o",
            stderr_path=tmp_path / "e",
        )
        (result,) = scheduler.run_tasks([task])

        assert not result.ok
        assert result.status == "error"
        assert "cannot start" in result.error


class TestTimeout:
    def test_a_silent_hung_child_is_killed(self, tmp_path) -> None:
        task = python_task("hang", tmp_path, "import time; time.sleep(60)")
        (result,) = scheduler.run_tasks([task], timeout=0.5)

        assert result.timed_out
        assert not result.ok
        assert result.status == "timeout"

    def test_a_chatty_hung_child_still_times_out(self, tmp_path) -> None:
        """The exact shape of the original bug.

        The child writes far more than a pipe buffer holds, then hangs. Reading
        its stdout before waiting would block forever and the timeout would never
        fire. Writing to a file cannot block, so the deadline is enforced.
        """
        code = (
            "import sys, time\n"
            "sys.stdout.write('x' * 2_000_000)\n"  # well past any pipe buffer
            "sys.stdout.flush()\n"
            "time.sleep(60)\n"
        )
        task = python_task("chatty", tmp_path, code)

        started = time.monotonic()
        (result,) = scheduler.run_tasks([task], timeout=1.0)
        elapsed = time.monotonic() - started

        assert result.timed_out, "a chatty child must still be killed"
        assert elapsed < 20, f"timeout did not fire promptly ({elapsed:.1f}s)"
        # The output it did produce is still on disk, not lost in a pipe.
        assert task.stdout_path.stat().st_size >= 2_000_000

    def test_a_timeout_does_not_stop_other_tasks(self, tmp_path) -> None:
        tasks = [
            python_task("hang", tmp_path, "import time; time.sleep(60)"),
            python_task("good", tmp_path, "print('fine')"),
        ]
        results = scheduler.run_tasks(tasks, jobs=2, timeout=1.0)

        assert results[0].timed_out
        assert results[1].ok


class TestParallelism:
    def test_jobs_greater_than_one_overlaps_work(self, tmp_path) -> None:
        code = "import time; time.sleep(0.4)"
        tasks = [python_task(f"t{i}", tmp_path, code) for i in range(4)]

        started = time.monotonic()
        scheduler.run_tasks(tasks, jobs=4)
        parallel = time.monotonic() - started

        started = time.monotonic()
        scheduler.run_tasks(tasks, jobs=1)
        serial = time.monotonic() - started

        assert parallel < serial / 2, f"parallel {parallel:.2f}s vs serial {serial:.2f}s"

    def test_never_exceeds_the_job_limit(self, tmp_path) -> None:
        """Each child records its own start and end; overlap must respect the cap."""
        marker = tmp_path / "concurrent"
        marker.mkdir()
        code = (
            "import os, time, uuid, pathlib\n"
            f"d = pathlib.Path({str(marker)!r})\n"
            "p = d / str(uuid.uuid4())\n"
            "p.write_text('')\n"
            "time.sleep(0.25)\n"
            "peak = len(list(d.iterdir()))\n"
            "p.unlink()\n"
            f"(d.parent / 'peaks').open('a').write(str(peak) + chr(10))\n"
        )
        tasks = [python_task(f"t{i}", tmp_path, code) for i in range(6)]
        scheduler.run_tasks(tasks, jobs=2)

        peaks = [int(x) for x in (tmp_path / "peaks").read_text().split()]
        assert max(peaks) <= 2, f"observed {max(peaks)} concurrent, limit was 2"

    def test_serial_by_default(self, tmp_path) -> None:
        marker = tmp_path / "concurrent"
        marker.mkdir()
        code = (
            "import time, uuid, pathlib\n"
            f"d = pathlib.Path({str(marker)!r})\n"
            "p = d / str(uuid.uuid4()); p.write_text('')\n"
            "time.sleep(0.15)\n"
            "peak = len(list(d.iterdir())); p.unlink()\n"
            f"(d.parent / 'peaks').open('a').write(str(peak) + chr(10))\n"
        )
        tasks = [python_task(f"t{i}", tmp_path, code) for i in range(3)]
        scheduler.run_tasks(tasks)

        peaks = [int(x) for x in (tmp_path / "peaks").read_text().split()]
        assert max(peaks) == 1


class TestResolveJobs:
    def test_default_is_serial(self) -> None:
        assert scheduler.resolve_jobs(1) == 1
        assert scheduler.resolve_jobs("1") == 1

    def test_auto_is_bounded(self) -> None:
        """Auto must stay modest: every plugin streams the same image."""
        value = scheduler.resolve_jobs("auto")
        assert 1 <= value <= 4

    def test_accepts_an_explicit_count(self) -> None:
        assert scheduler.resolve_jobs("8") == 8

    @pytest.mark.parametrize("bad", [0, -1, "0"])
    def test_rejects_less_than_one(self, bad) -> None:
        with pytest.raises(ValueError):
            scheduler.resolve_jobs(bad)

    def test_rejects_nonsense(self) -> None:
        with pytest.raises(ValueError):
            scheduler.resolve_jobs("plenty")


class TestCallbacks:
    def test_on_finish_fires_once_per_task(self, tmp_path) -> None:
        seen = []
        tasks = [python_task(f"t{i}", tmp_path, "print(1)") for i in range(3)]
        scheduler.run_tasks(tasks, jobs=2, on_finish=seen.append)

        assert len(seen) == 3
        assert {r.task.key for r in seen} == {"t0", "t1", "t2"}
