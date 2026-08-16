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
