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
        assert analysis.BY_PLUGIN["windows.malware.ldrmodules.LdrModules"].pid == "Pid"


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
        for process in analysed.processes:
            assert process.signals <= analysis.VOCABULARY

    def test_every_vocabulary_entry_has_a_source_plugin(self) -> None:
        assert set(analysis.SIGNAL_SOURCE) == analysis.VOCABULARY


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
        assert "--format csv,json" in result.notices[0].message

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
        """The column each extractor reads must be one the plugin emits."""
        import inspect
        import re

        for extractor in analysis.EXTRACTORS:
            source = inspect.getsource(catalogue[extractor.plugin])
            grid = re.search(r"TreeGrid\(\s*(?:columns\s*=\s*)?\[(.*?)\]\s*,",
                             source, re.S)
            assert grid, f"cannot find the TreeGrid for {extractor.plugin}"
            columns = re.findall(r'\(\s*f?"([^"]+)"', grid.group(1))

            wanted = [extractor.pid, extractor.name, extractor.ppid]
            for column in filter(None, wanted):
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
