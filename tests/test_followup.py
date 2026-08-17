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
            rule_id: str = "R-1", offset: int | None = None,
            regions: tuple[int, ...] = ()) -> rules.Finding:
    process = analysis.Process(pid=pid, offset=offset, name=f"p{pid}.exe")
    if regions:
        # Volatility renders Hex columns as integers in JSON.
        process.seen_in["windows.malware.malfind.Malfind"] = [
            {"PID": pid, "Start VPN": start, "End VPN": start + 0x1000}
            for start in regions
        ]
    return rules.Finding(
        finding_id=f"PROC-{pid:04d}",
        rule_id=rule_id,
        severity=severity,
        title="A finding",
        entity=process,
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
    """Rules may recommend a dump; the tool still never performs one unbidden.

    The guarantee that matters is not "no rule asks" but "the tool does not act".
    A recommendation the analyst can act on is the point; writing malicious code
    to their workstation without being told to is not.
    """

    def test_dumps_are_suggested_not_executed_by_default(self) -> None:
        plan = followup.plan([finding(4180, actions=("dump_process",))])

        assert len(plan.tasks) == 1
        task = plan.tasks[0]
        assert task.suggested is True
        assert task.state == "suggested"
        assert plan.pending == []
        assert plan.suggested == [task]

    def test_a_suggestion_is_not_a_skip(self) -> None:
        """A skip means the tool could not act; a suggestion means it chose not
        to. Conflating them makes a policy decision read as a coverage gap."""
        plan = followup.plan([finding(4180, actions=("dump_process",))])

        assert plan.tasks[0].skipped_reason is None
        assert plan.tasks[0].suggested_reason is not None

    def test_the_reason_and_the_quarantine_risk_are_stated(self) -> None:
        plan = followup.plan([finding(4180, actions=("dump_process", "dump_vads"))])
        notices = " ".join(plan.notices)

        assert "--dump" in notices
        assert "quarantine" in notices
        assert "NOT run" in notices

    def test_dump_runs_when_asked_for(self) -> None:
        plan = followup.plan(
            [finding(4180, actions=("dump_process",))], allow_dump=True
        )

        assert plan.tasks[0].suggested is False
        assert plan.tasks[0].skipped_reason is None
        assert plan.tasks[0].plugin_args == ["--dump", "--pid", "4180"]

    def test_no_dump_ever_executes_without_the_flag(self) -> None:
        """The property that actually protects the workstation: whatever the
        rules recommend, nothing runs.

        Every dump task ends up suggested or skipped, never pending. Both states
        appear here — dump_module scopes by --name, which a *process* cannot
        supply, so it is legitimately a skip rather than a suggestion.
        """
        dump_actions = [a for a in followup.ACTIONS if a.startswith("dump_")]
        assert dump_actions  # the guarantee is vacuous if there are none

        plan = followup.plan([finding(4180, actions=tuple(dump_actions))])

        assert plan.pending == []
        assert all(t.suggested or t.skipped_reason for t in plan.tasks)
        assert all(t.state in {"suggested", "skipped"} for t in plan.tasks)

    def test_the_shipped_pack_recommends_dumps_only_where_justified(self) -> None:
        """A bare malfind region is why PROC-INJECT is medium. Suggesting a dump
        for every one of them would undo that distinction."""
        pack = rules.load(rules.DEFAULT_PACK, known_actions=set(followup.ACTIONS))
        by_rule = {
            rule.id: {a for a in rule.actions if a.startswith("dump_")}
            for rule in pack.rules
        }

        assert by_rule["PROC-INJECT-NET"] == {"dump_vads", "dump_process"}
        assert by_rule["PROC-GHOST"] == {"dump_process"}
        assert by_rule["PROC-INJECT"] == set()
        assert by_rule["PROC-HIDDEN"] == set()


class TestRegionScoping:
    """``VadInfo --dump --pid N`` writes every VAD — gigabytes on a real process.
    The region the finding cited is a few pages, and is the thing worth keeping.
    """

    def test_one_task_per_flagged_region(self) -> None:
        plan = followup.plan(
            [finding(4180, actions=("dump_vads",),
                     regions=(0x1A2B3C0000, 0x7FF000))]
        )

        assert len(plan.tasks) == 2
        assert [t.region for t in plan.tasks] == ["0x1a2b3c0000", "0x7ff000"]

    def test_the_address_precedes_the_scope_flag(self) -> None:
        """--pid is a ListRequirement and swallows every token after it, so
        nothing may follow it — including --address."""
        plan = followup.plan(
            [finding(4180, actions=("dump_vads",), regions=(0x1A2B3C0000,))]
        )

        assert plan.tasks[0].plugin_args == [
            "--dump", "--address", "0x1a2b3c0000", "--pid", "4180",
        ]

    def test_duplicate_regions_are_collapsed(self) -> None:
        plan = followup.plan(
            [finding(4180, actions=("dump_vads",),
                     regions=(0x1000, 0x1000, 0x2000))]
        )

        assert [t.region for t in plan.tasks] == ["0x1000", "0x2000"]

    def test_no_regions_falls_back_to_the_whole_process(self) -> None:
        """A dump of everything still beats emitting nothing, and the absent
        region says which was produced."""
        plan = followup.plan([finding(4180, actions=("dump_vads",))])

        assert len(plan.tasks) == 1
        assert plan.tasks[0].region is None
        assert plan.tasks[0].plugin_args == ["--dump", "--pid", "4180"]

    def test_an_unparseable_address_is_ignored_not_fatal(self) -> None:
        process_finding = finding(4180, actions=("dump_vads",))
        process_finding.entity.seen_in["windows.malware.malfind.Malfind"] = [
            {"Start VPN": None}, {"Start VPN": "not-a-number"},
            {"Start VPN": True}, {"Start VPN": 0x4000},
        ]

        plan = followup.plan([process_finding])

        assert [t.region for t in plan.tasks] == ["0x4000"]


class TestSuggestedCommands:
    def test_the_command_is_rendered_for_the_analyst(self, lib, tmp_path) -> None:
        plan = followup.plan(
            [finding(4180, actions=("dump_vads",), regions=(0x1A2B3C0000,))]
        )

        followup.render_suggestions(
            plan, output_dir=tmp_path / "out", engine=lib,
            symbols_dir=tmp_path / "s", cache_dir=tmp_path / "c",
            image=tmp_path / "m.raw",
        )

        command = plan.tasks[0].suggested_command
        assert "windows.vadinfo.VadInfo" in command
        assert "--address 0x1a2b3c0000" in command
        assert command.index("-o ") < command.index("windows.vadinfo.VadInfo")
        assert command.rstrip().endswith("--pid 4180")

    def test_it_matches_what_the_tool_would_have_run(self, lib, tmp_path) -> None:
        """Rendered through engine.command, so the suggestion cannot drift from
        the real argv when option ordering changes."""
        actions = ("dump_vads",)
        suggested = followup.plan([finding(4180, actions=actions)])
        executed = followup.plan([finding(4180, actions=actions)], allow_dump=True)

        followup.render_suggestions(
            suggested, output_dir=tmp_path / "out", engine=lib,
            symbols_dir=tmp_path / "s", cache_dir=tmp_path / "c",
            image=tmp_path / "m.raw",
        )
        tasks = followup.build_tasks(
            executed, image=tmp_path / "m.raw", output_dir=tmp_path / "out",
            engine=lib, symbols_dir=tmp_path / "s", cache_dir=tmp_path / "c",
        )

        rendered = " ".join(
            f'"{a}"' if " " in a else a for a in tasks[0].command
        )
        assert suggested.tasks[0].suggested_command == rendered

    def test_the_output_directory_exists_so_the_command_runs(self, lib, tmp_path) -> None:
        """Volatility exits immediately when -o names a directory that is not
        there. A suggested task never ran, so nothing else creates it, and the
        command would fail the moment it was pasted."""
        plan = followup.plan(
            [finding(4180, actions=("dump_vads",), regions=(0x9000,))]
        )
        out = tmp_path / "out"

        followup.render_suggestions(
            plan, output_dir=out, engine=lib,
            symbols_dir=tmp_path / "s", cache_dir=tmp_path / "c",
        )

        command = plan.tasks[0].suggested_command
        target = Path(command.split(" -o ")[1].split(" windows.")[0].strip('"'))
        assert target.is_dir()
        assert target == out / "followup" / "PID-4180"

    def test_without_an_image_a_placeholder_is_used(self, lib, tmp_path) -> None:
        plan = followup.plan([finding(4180, actions=("dump_process",))])

        followup.render_suggestions(
            plan, output_dir=tmp_path / "out", engine=lib,
            symbols_dir=tmp_path / "s", cache_dir=tmp_path / "c",
        )

        assert followup.IMAGE_PLACEHOLDER in plan.tasks[0].suggested_command

    def test_suggestions_reach_next_steps_json(self, lib, tmp_path) -> None:
        plan = followup.plan(
            [finding(4180, actions=("dump_vads",), regions=(0x9000,))]
        )
        followup.render_suggestions(
            plan, output_dir=tmp_path / "out", engine=lib,
            symbols_dir=tmp_path / "s", cache_dir=tmp_path / "c",
        )

        path = followup.write(tmp_path / "findings", plan)
        entry = json.loads(path.read_text(encoding="utf-8"))["tasks"][0]

        assert entry["state"] == "suggested"
        assert entry["region"] == "0x9000"
        assert "--address 0x9000" in entry["suggested_command"]


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

        # Compare path components, not a string suffix: the separator is native,
        # so a hardcoded "followup/PID-4180" fails on the Windows hosts this tool
        # is built for.
        assert Path(argv[argv.index("-o") + 1]) == tmp_path / "out" / "followup" / "PID-4180"

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


def module_finding(key: str, *, severity: str = "high",
                   actions=("inspect_module",)) -> rules.Finding:
    entity = analysis.Module(key=key, name=f"{key}.sys")
    return rules.Finding(
        finding_id="KERN-0001", rule_id="K-1", severity=severity,
        title="A kernel finding", entity=entity, actions=tuple(actions),
    )


def service_finding(key: str, *, pid: int | None = 900,
                    actions=("inspect_context",)) -> rules.Finding:
    entity = analysis.Service(key=key, name=key, pid=pid)
    return rules.Finding(
        finding_id="SVC-0001", rule_id="S-1", severity="high",
        title="A service finding", entity=entity, actions=tuple(actions),
    )


class TestEntityScopes:
    """A module is selected by --name; a service by the PID hosting it."""

    def test_a_module_is_scoped_by_name(self) -> None:
        plan = followup.plan([module_finding("evilrk")])

        assert plan.tasks[0].plugin_args == ["--name", "evilrk"]
        assert plan.tasks[0].directory == "followup/KERN-evilrk"

    def test_the_normalised_key_is_used_not_the_decorated_name(self) -> None:
        """--name is a substring match, so the stem matches both forms."""
        entity = analysis.Module(key="evilrk", name="\\Driver\\evilrk")
        assert entity.scope_values() == {"name": "evilrk"}

    def test_a_service_is_scoped_by_its_host_pid(self) -> None:
        """The correlation the service entity exists for."""
        plan = followup.plan([service_finding("dhcp", pid=900)])

        assert all(t.plugin_args[-2:] == ["--pid", "900"] for t in plan.tasks)
        assert plan.tasks[0].directory == "followup/SVC-dhcp"

    def test_a_service_with_no_host_is_skipped_not_run_unscoped(self) -> None:
        """Running these plugins unscoped would re-read the whole image."""
        plan = followup.plan([service_finding("ghostsvc", pid=None)])

        assert plan.pending == []
        assert all("no pid to scope by" in t.skipped_reason for t in plan.tasks)
        assert any("could not be followed up" in n for n in plan.notices)

    def test_directory_names_are_filesystem_safe(self) -> None:
        plan = followup.plan([module_finding("<unresolved>")])
        assert plan.tasks[0].directory == "followup/KERN-unresolved"

    def test_entities_of_different_kinds_do_not_collide(self) -> None:
        plan = followup.plan([
            finding(900), module_finding("evilrk"), service_finding("dhcp", pid=900),
        ])

        assert len({t.directory for t in plan.tasks}) == 3
        assert plan.elevated == 3

    def test_module_steps_use_plugins_that_accept_name(self) -> None:
        by_name = {
            step.plugin
            for steps in followup.ACTIONS.values()
            for step in steps
            if step.scope == "name"
        }
        assert by_name == {"windows.modules.Modules", "windows.modscan.ModScan"}


class TestScopedTaskConstruction:
    def test_name_follows_the_plugin(self, lib, tmp_path) -> None:
        plan = followup.plan([module_finding("evilrk")])
        tasks = followup.build_tasks(
            plan, image=tmp_path / "m.raw", output_dir=tmp_path / "out",
            engine=lib, symbols_dir=tmp_path / "s", cache_dir=tmp_path / "c",
        )

        assert tasks[0].command[-3:] == [
            "windows.modules.Modules", "--name", "evilrk"
        ]


class TestPagefilesReachTheFollowUp:
    """Triage's swap layers must reach the targeted runs, or the collected
    evidence is narrower than the findings that asked for it."""

    def test_swap_layers_are_passed_to_every_task(self, lib, tmp_path) -> None:
        plan = followup.plan([finding(4180, actions=("inspect_vads",))])
        tasks = followup.build_tasks(
            plan, image=tmp_path / "m.raw", output_dir=tmp_path / "out",
            engine=lib, symbols_dir=tmp_path / "s", cache_dir=tmp_path / "c",
            pagefiles=[tmp_path / "pagefile.sys"],
        )

        argv = tasks[0].command
        assert "--single-swap-locations" in argv
        assert str(tmp_path / "pagefile.sys") in argv

    def test_the_swap_list_never_swallows_the_plugin(self, lib, tmp_path) -> None:
        """--single-swap-locations takes nargs='*'; see TestSwapLayers."""
        plan = followup.plan([finding(4180, actions=("inspect_vads",))])
        tasks = followup.build_tasks(
            plan, image=tmp_path / "m.raw", output_dir=tmp_path / "out",
            engine=lib, symbols_dir=tmp_path / "s", cache_dir=tmp_path / "c",
            pagefiles=[tmp_path / "pagefile.sys"],
        )
        argv = tasks[0].command

        swap = argv.index("--single-swap-locations")
        assert "windows.vadinfo.VadInfo" in argv[swap + 2:]
        assert argv[-3:] == ["windows.vadinfo.VadInfo", "--pid", "4180"]

    def test_absent_when_the_run_used_none(self, lib, tmp_path) -> None:
        plan = followup.plan([finding(4180, actions=("inspect_vads",))])
        tasks = followup.build_tasks(
            plan, image=tmp_path / "m.raw", output_dir=tmp_path / "out",
            engine=lib, symbols_dir=tmp_path / "s", cache_dir=tmp_path / "c",
        )

        assert "--single-swap-locations" not in tasks[0].command


class TestModuleFollowUpName:
    def test_the_case_preserving_name_reaches_the_argv(self, lib, tmp_path) -> None:
        """The lowercased key would match nothing: --name is case-sensitive."""
        entity = analysis.Module(key="wdf01000", name="Wdf01000.sys",
                                 scope_name="Wdf01000")
        found = rules.Finding("KERN-0001", "K-1", "high", "t", entity,
                              actions=("inspect_module",))
        tasks = followup.build_tasks(
            followup.plan([found]), image=tmp_path / "m.raw",
            output_dir=tmp_path / "out", engine=lib,
            symbols_dir=tmp_path / "s", cache_dir=tmp_path / "c",
        )

        assert tasks[0].command[-1] == "Wdf01000"

    def test_the_directory_still_uses_the_stable_key(self, lib, tmp_path) -> None:
        """Case-folded, so two spellings cannot make two evidence folders."""
        entity = analysis.Module(key="wdf01000", name="Wdf01000.sys",
                                 scope_name="Wdf01000")
        found = rules.Finding("KERN-0001", "K-1", "high", "t", entity,
                              actions=("inspect_module",))

        assert followup.plan([found]).tasks[0].directory == "followup/KERN-wdf01000"

    def test_it_falls_back_to_the_key_when_no_stem_is_known(self) -> None:
        assert analysis.Module(key="evilrk").scope_values() == {"name": "evilrk"}
