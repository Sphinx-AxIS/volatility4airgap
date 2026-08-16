"""Tests for turning findings into targeted Volatility runs.

The argv assertions here are the regression test for a hazard the codebase has
already met once: an option taking nargs='+' swallows whatever follows it. See
TestSwapLayers in test_engine.py for the first instance.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import analysis, engine as engine_mod, followup, rules


def finding(pid: int, *, severity: str = "high", actions=("inspect_vads",),
            rule_id: str = "R-1", offset: int | None = None) -> rules.Finding:
    process = analysis.Process(pid=pid, offset=offset, name=f"p{pid}.exe")
    return rules.Finding(
        finding_id=f"PROC-{pid:04d}",
        rule_id=rule_id,
        severity=severity,
        title="A finding",
        process=process,
        actions=tuple(actions),
    )


@pytest.fixture
def lib(tmp_path) -> engine_mod.LibraryEngine:
    python = tmp_path / "python.exe"
    python.write_bytes(b"MZ")
    return engine_mod.LibraryEngine(python)


class TestActionTable:
    def test_every_action_expands_to_at_least_one_step(self) -> None:
        assert all(steps for steps in followup.ACTIONS.values())

    def test_no_step_uses_a_plugin_that_cannot_filter_by_pid(self) -> None:
        """NetScan and ThrdScan take no --pid; correlation reads the triage JSON."""
        unfilterable = {"windows.netscan.NetScan", "windows.thrdscan.ThrdScan",
                        "windows.netstat.NetStat"}
        used = {step.plugin for steps in followup.ACTIONS.values() for step in steps}

        assert not used & unfilterable

    def test_only_dump_steps_are_marked_as_needing_dump(self) -> None:
        for name, steps in followup.ACTIONS.items():
            for step in steps:
                assert step.requires_dump == ("--dump" in step.extra)
                assert step.requires_dump == name.startswith("dump_")


class TestPlanning:
    def test_a_finding_becomes_tasks(self) -> None:
        plan = followup.plan([finding(4180, actions=("inspect_vads",))])

        assert len(plan.tasks) == 1
        assert plan.tasks[0].plugin == "windows.vadinfo.VadInfo"
        assert plan.tasks[0].plugin_args == ["--pid", "4180"]

    def test_two_rules_on_one_process_do_not_duplicate_work(self) -> None:
        """Both rules want the VADs; the process is examined once."""
        plan = followup.plan([
            finding(4180, rule_id="R-1", actions=("inspect_vads",)),
            finding(4180, rule_id="R-2", actions=("inspect_vads", "inspect_threads")),
        ])

        plugins = [t.plugin for t in plan.tasks]
        assert plugins.count("windows.vadinfo.VadInfo") == 1
        assert plan.elevated == 1

    def test_entities_are_taken_most_severe_first(self) -> None:
        plan = followup.plan(
            [finding(100, severity="medium"), finding(200, severity="critical")],
            max_followups=1,
        )

        assert {t.entity["pid"] for t in plan.tasks} == {200}

    def test_the_cap_is_reported_not_silent(self) -> None:
        plan = followup.plan([finding(pid) for pid in range(1, 21)], max_followups=3)

        assert plan.elevated == 20
        assert plan.planned == 3
        assert any("--max-followups 20" in n for n in plan.notices)

    def test_pid_reuse_gets_separate_directories(self) -> None:
        """Two processes that shared a PID must not share an evidence folder."""
        plan = followup.plan([
            finding(4180, offset=0xB000, rule_id="R-1"),
            finding(4180, offset=0xC000, rule_id="R-2"),
        ])

        assert len({t.directory for t in plan.tasks}) == 2

    def test_one_process_gets_a_plain_directory_name(self) -> None:
        plan = followup.plan([finding(4180, offset=0xB000)])
        assert plan.tasks[0].directory == "followup/PID-4180"


class TestDumpPolicy:
    def test_dumps_are_planned_but_not_executed_by_default(self) -> None:
        plan = followup.plan([finding(4180, actions=("dump_process",))])

        assert len(plan.tasks) == 1
        assert plan.tasks[0].skipped_reason == "requires --dump"
        assert plan.pending == []

    def test_the_reason_and_the_quarantine_risk_are_stated(self) -> None:
        plan = followup.plan([finding(4180, actions=("dump_process", "dump_vads"))])
        notices = " ".join(plan.notices)

        assert "--dump" in notices
        assert "quarantined" in notices

    def test_dump_runs_when_asked_for(self) -> None:
        plan = followup.plan(
            [finding(4180, actions=("dump_process",))], allow_dump=True
        )

        assert plan.tasks[0].skipped_reason is None
        assert plan.tasks[0].plugin_args == ["--dump", "--pid", "4180"]

    def test_the_shipped_pack_recommends_no_dump_actions_yet(self) -> None:
        """v1 ships read-only. This fails loudly if a dump action is added."""
        pack = rules.load(rules.DEFAULT_PACK, known_actions=set(followup.ACTIONS))
        recommended = {a for rule in pack.rules for a in rule.actions}

        assert not {a for a in recommended if a.startswith("dump_")}


class TestTaskConstruction:
    @pytest.fixture
    def tasks(self, lib, tmp_path):
        plan = followup.plan([finding(4180, actions=("inspect_vads",))])
        return followup.build_tasks(
            plan,
            image=tmp_path / "memory.raw",
            output_dir=tmp_path / "out",
            engine=lib,
            symbols_dir=tmp_path / "symbols",
            cache_dir=tmp_path / "cache",
        )

    def test_output_dir_precedes_the_plugin(self, tasks) -> None:
        argv = tasks[0].command
        assert argv.index("-o") < argv.index("windows.vadinfo.VadInfo")

    def test_pid_follows_the_plugin_and_ends_the_argv(self, tasks) -> None:
        """--pid is nargs='+'; a trailing token would be eaten as another PID."""
        assert tasks[0].command[-3:] == ["windows.vadinfo.VadInfo", "--pid", "4180"]

    def test_output_lands_in_the_entity_directory(self, tasks, tmp_path) -> None:
        expected = tmp_path / "out" / "followup" / "PID-4180"
        assert tasks[0].stdout_path == expected / "windows.vadinfo.VadInfo.json"
        assert tasks[0].stderr_path.parent == expected / "logs"

    def test_dumps_are_directed_at_the_entity_directory(self, lib, tmp_path) -> None:
        """Without -o, --dump writes to the working directory of the subprocess."""
        plan = followup.plan(
            [finding(4180, actions=("dump_vads",))], allow_dump=True
        )
        tasks = followup.build_tasks(
            plan, image=tmp_path / "m.raw", output_dir=tmp_path / "out",
            engine=lib, symbols_dir=tmp_path / "s", cache_dir=tmp_path / "c",
        )
        argv = tasks[0].command

        assert argv[argv.index("-o") + 1].endswith("followup/PID-4180")

    def test_skipped_tasks_produce_no_command(self, lib, tmp_path) -> None:
        plan = followup.plan([finding(4180, actions=("dump_process",))])
        tasks = followup.build_tasks(
            plan, image=tmp_path / "m.raw", output_dir=tmp_path / "out",
            engine=lib, symbols_dir=tmp_path / "s", cache_dir=tmp_path / "c",
        )

        assert tasks == []

    def test_task_keys_are_unique(self, lib, tmp_path) -> None:
        """The scheduler indexes results by key; a collision loses one."""
        plan = followup.plan([
            finding(4180, actions=("inspect_context", "inspect_modules")),
            finding(7224, actions=("inspect_context", "inspect_modules")),
        ])
        tasks = followup.build_tasks(
            plan, image=tmp_path / "m.raw", output_dir=tmp_path / "out",
            engine=lib, symbols_dir=tmp_path / "s", cache_dir=tmp_path / "c",
        )

        keys = [t.key for t in tasks]
        assert len(keys) == len(set(keys))


class TestNextSteps:
    def test_the_plan_is_written_whether_or_not_it_ran(self, tmp_path) -> None:
        plan = followup.plan([finding(4180, actions=("inspect_vads",))])
        path = followup.write(tmp_path, plan)
        document = json.loads(path.read_text())

        assert document["tasks"][0]["executed"] is False
        assert document["entities_elevated"] == 1

    def test_execution_is_recorded_against_the_same_document(self, tmp_path) -> None:
        """One file describes both what was decided and what happened."""
        from app import scheduler

        plan = followup.plan([finding(4180, actions=("inspect_vads",))])
        task = scheduler.Task("k", "l", ["true"], tmp_path / "o", tmp_path / "e")
        followup.record_results(
            plan, [scheduler.TaskResult(task, returncode=0, duration=1.25)]
        )
        document = json.loads(followup.write(tmp_path, plan).read_text())

        assert document["tasks"][0]["executed"] is True
        assert document["tasks"][0]["status"] == "ok"
        assert document["tasks"][0]["seconds"] == 1.25

    def test_a_failed_task_is_named_not_hidden(self, tmp_path) -> None:
        from app import scheduler

        plan = followup.plan([finding(4180, actions=("inspect_vads",))])
        task = scheduler.Task("k", "l", ["false"], tmp_path / "o", tmp_path / "e")
        followup.record_results(
            plan, [scheduler.TaskResult(task, returncode=1, duration=0.1)]
        )
        document = json.loads(followup.write(tmp_path, plan).read_text())

        assert document["tasks"][0]["status"] == "exit 1"

    def test_the_output_path_is_recorded_for_each_task(self, tmp_path) -> None:
        plan = followup.plan([finding(4180, actions=("inspect_vads",))])
        document = json.loads(followup.write(tmp_path, plan).read_text())

        assert document["tasks"][0]["output"] == (
            "followup/PID-4180/windows.vadinfo.VadInfo.json"
        )
