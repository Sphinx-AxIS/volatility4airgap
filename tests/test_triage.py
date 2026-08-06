"""Tests for plugin selection and the triage run's bookkeeping.

Includes an end-to-end run driven through a fake engine, which exercises the
scheduler, output naming, empty-output pruning and the manifest without needing
Volatility or a memory image.
"""

from __future__ import annotations

import json
import sys

import pytest

from app import manifest, plugins as catalog, scheduler, triage
from app.engine import VolEngine
from app.symbols import KernelPdb

from .test_symbols import GOLDEN_GUID, GOLDEN_NAME


class TestPluginSelection:
    def test_default_is_the_triage_set(self) -> None:
        names = catalog.resolve(None, all_plugins=False)
        assert names == catalog.triage_names()
        assert catalog.PROBE in names

    def test_every_triage_plugin_is_windows(self) -> None:
        assert all(n.startswith("windows.") for n in catalog.triage_names())

    def test_no_duplicates(self) -> None:
        names = catalog.triage_names()
        assert len(names) == len(set(names))

    def test_explicit_names(self) -> None:
        names = catalog.resolve("windows.pslist.PsList,windows.netscan.NetScan", all_plugins=False)
        assert names == ["windows.pslist.PsList", "windows.netscan.NetScan"]

    def test_a_category_expands(self) -> None:
        names = catalog.resolve("network", all_plugins=False)
        assert names == catalog.by_category("network")
        assert "windows.netscan.NetScan" in names

    def test_categories_and_names_mix(self) -> None:
        names = catalog.resolve("registry,windows.pslist.PsList", all_plugins=False)
        assert "windows.pslist.PsList" in names
        assert "windows.registry.hivelist.HiveList" in names

    def test_duplicates_are_collapsed(self) -> None:
        names = catalog.resolve(
            "windows.pslist.PsList,windows.pslist.PsList", all_plugins=False
        )
        assert names == ["windows.pslist.PsList"]

    def test_blank_entries_ignored(self) -> None:
        assert catalog.resolve("windows.pslist.PsList,, ", all_plugins=False) == [
            "windows.pslist.PsList"
        ]

    def test_probe_is_in_the_set(self) -> None:
        assert catalog.PROBE in catalog.triage_names()


class TestPluginNamesAreReal:
    """Guards against a plugin renamed upstream silently never running."""

    def test_every_curated_name_exists(self) -> None:
        pytest.importorskip("volatility3")
        available = set(catalog.discover_all(windows_only=False))
        missing = [n for n in catalog.triage_names() if n not in available]
        assert not missing, f"plugins not found in this volatility: {missing}"

    def test_discover_all_filters_to_windows(self) -> None:
        pytest.importorskip("volatility3")
        assert all(n.startswith("windows.") for n in catalog.discover_all())

    def test_all_returns_more_than_the_curated_set(self) -> None:
        pytest.importorskip("volatility3")
        assert len(catalog.discover_all()) > len(catalog.triage_names())


class FakeEngine(VolEngine):
    """Emits deterministic output, so the pipeline can be tested without volatility."""

    name = "fake"

    def __init__(self, *, fail: set[str] | None = None, empty: set[str] | None = None,
                 header_only: set[str] | None = None):
        self.fail = fail or set()
        self.empty = empty or set()
        self.header_only = header_only or set()

    def available(self) -> bool:
        return True

    def base_command(self) -> list[str]:
        return [sys.executable, "-c", ""]

    def command(self, image, plugin, renderer, **kwargs) -> list[str]:
        if plugin in self.fail:
            code = "import sys; sys.stderr.write('plugin exploded'); raise SystemExit(1)"
        elif plugin in self.header_only:
            code = "print('PID,Name')"     # exits 0, emits only a header
        elif plugin in self.empty:
            code = "pass"
        elif renderer == "json":
            code = "print('[{\"PID\": 4, \"Name\": \"System\"}]')"
        else:
            code = "print('PID,Name'); print('4,System')"
        return [sys.executable, "-c", code]


def make_plan(tmp_path, plugin_names, formats=("csv", "json"), jobs=1):
    return triage.TriagePlan(
        image=tmp_path / "image.raw",
        output_dir=tmp_path / "out",
        symbols_dir=tmp_path / "symbols",
        cache_dir=tmp_path / "cache",
        plugin_names=list(plugin_names),
        formats=list(formats),
        jobs=jobs,
    )


class TestOutputNaming:
    def test_matches_the_ingest_convention(self, tmp_path) -> None:
        """CORE-Respond's ingest expects windows.pslist.PsList.csv."""
        path = triage.output_path(tmp_path, "windows.pslist.PsList", "csv")
        assert path.name == "windows.pslist.PsList.csv"

    def test_logs_are_kept_separate(self, tmp_path) -> None:
        path = triage.log_path(tmp_path, "windows.pslist.PsList", "csv")
        assert path.parent.name == "logs"


class TestEndToEnd:
    def test_a_clean_run_produces_both_formats(self, tmp_path) -> None:
        plan = make_plan(tmp_path, ["windows.pslist.PsList", "windows.pstree.PsTree"])
        tasks = triage.build_tasks(plan, FakeEngine())
        results = scheduler.run_tasks(tasks, jobs=1)
        outcomes = triage.collect_outcomes(plan, results)

        assert len(outcomes) == 2
        assert all(o.ok for o in outcomes)
        assert (plan.output_dir / "windows.pslist.PsList.csv").is_file()
        assert (plan.output_dir / "windows.pslist.PsList.json").is_file()
        assert "System" in (plan.output_dir / "windows.pslist.PsList.csv").read_text()

    def test_a_failing_plugin_does_not_stop_the_run(self, tmp_path) -> None:
        plan = make_plan(tmp_path, ["windows.pslist.PsList", "windows.netscan.NetScan"])
        engine = FakeEngine(fail={"windows.netscan.NetScan"})
        results = scheduler.run_tasks(triage.build_tasks(plan, engine), jobs=2)
        outcomes = triage.collect_outcomes(plan, results)

        by_name = {o.plugin: o for o in outcomes}
        assert by_name["windows.pslist.PsList"].ok
        assert not by_name["windows.netscan.NetScan"].ok

    def test_the_failure_log_is_kept(self, tmp_path) -> None:
        plan = make_plan(tmp_path, ["windows.netscan.NetScan"], formats=("csv",))
        engine = FakeEngine(fail={"windows.netscan.NetScan"})
        scheduler.run_tasks(triage.build_tasks(plan, engine))

        log = triage.log_path(plan.output_dir, "windows.netscan.NetScan", "csv")
        assert "plugin exploded" in log.read_text()

    def test_empty_outputs_are_pruned(self, tmp_path) -> None:
        """An empty NetScan.csv reads as 'no network activity', which is a lie."""
        plan = make_plan(tmp_path, ["windows.netscan.NetScan"], formats=("csv",))
        engine = FakeEngine(empty={"windows.netscan.NetScan"})
        results = scheduler.run_tasks(triage.build_tasks(plan, engine))
        outcomes = triage.collect_outcomes(plan, results)

        path = triage.output_path(plan.output_dir, "windows.netscan.NetScan", "csv")
        assert path.is_file() and path.stat().st_size == 0

        removed = triage.prune_empty_outputs(plan, outcomes)
        assert removed == 1
        assert not path.exists()
        # The log survives, so nothing diagnostic is lost.
        assert triage.log_path(plan.output_dir, "windows.netscan.NetScan", "csv").exists()

    def test_successful_output_is_never_pruned(self, tmp_path) -> None:
        plan = make_plan(tmp_path, ["windows.pslist.PsList"], formats=("csv",))
        results = scheduler.run_tasks(triage.build_tasks(plan, FakeEngine()))
        outcomes = triage.collect_outcomes(plan, results)

        assert triage.prune_empty_outputs(plan, outcomes) == 0
        assert triage.output_path(plan.output_dir, "windows.pslist.PsList", "csv").is_file()

    def test_parallel_run_produces_the_same_files(self, tmp_path) -> None:
        names = [f"windows.fake{i}.Fake" for i in range(6)]
        plan = make_plan(tmp_path, names, formats=("csv",), jobs=3)
        results = scheduler.run_tasks(triage.build_tasks(plan, FakeEngine()), jobs=3)
        outcomes = triage.collect_outcomes(plan, results)

        assert len(outcomes) == 6
        assert all(o.ok for o in outcomes)


class TestManifest:
    def test_records_plugins_outputs_and_image(self, tmp_path) -> None:
        plan = make_plan(tmp_path, ["windows.pslist.PsList"], formats=("csv",))
        plan.image.parent.mkdir(parents=True, exist_ok=True)
        plan.image.write_bytes(b"\xcc" * 1024)

        results = scheduler.run_tasks(triage.build_tasks(plan, FakeEngine()))
        outcomes = triage.collect_outcomes(plan, results)
        kernel = KernelPdb(GOLDEN_NAME, GOLDEN_GUID, 1)

        path = triage.write_manifest(
            plan, FakeEngine(), outcomes,
            kernels=[kernel], image_sha256="ab" * 32, started_utc=manifest.utc_now(),
        )
        document = json.loads(path.read_text())

        assert document["schema_version"] == manifest.SCHEMA_VERSION
        assert document["image"]["sha256"] == "ab" * 32
        assert document["kernels"][0]["guid"] == GOLDEN_GUID
        assert document["summary"]["total"] == 1
        assert document["summary"]["succeeded"] == 1
        assert any(o["file"].endswith(".csv") for o in document["outputs"])
        assert all(len(o["sha256"]) == 64 for o in document["outputs"])

    def test_counts_failures(self, tmp_path) -> None:
        plan = make_plan(tmp_path, ["a.B", "c.D"], formats=("csv",))
        plan.image.parent.mkdir(parents=True, exist_ok=True)
        plan.image.write_bytes(b"x")

        engine = FakeEngine(fail={"c.D"})
        results = scheduler.run_tasks(triage.build_tasks(plan, engine))
        outcomes = triage.collect_outcomes(plan, results)

        path = triage.write_manifest(
            plan, engine, outcomes, kernels=[], image_sha256=None,
            started_utc=manifest.utc_now(),
        )
        document = json.loads(path.read_text())

        assert document["summary"] == {"total": 2, "succeeded": 1, "failed": 1}
        failed = [p for p in document["plugins"] if p["status"] == "failed"]
        assert failed[0]["plugin"] == "c.D"

    def test_the_manifest_excludes_itself(self, tmp_path) -> None:
        plan = make_plan(tmp_path, ["a.B"], formats=("csv",))
        plan.image.parent.mkdir(parents=True, exist_ok=True)
        plan.image.write_bytes(b"x")
        results = scheduler.run_tasks(triage.build_tasks(plan, FakeEngine()))
        outcomes = triage.collect_outcomes(plan, results)

        path = triage.write_manifest(
            plan, FakeEngine(), outcomes, kernels=[], image_sha256=None,
            started_utc=manifest.utc_now(),
        )
        document = json.loads(path.read_text())
        assert not any(o["file"] == manifest.FILENAME for o in document["outputs"])


class TestProbeDiagnosis:
    def _result(self, tmp_path, stderr_text, *, timed_out=False):
        task = scheduler.Task(
            key="probe", label="probe", command=[],
            stdout_path=tmp_path / "o", stderr_path=tmp_path / "e",
        )
        task.stderr_path.write_text(stderr_text, encoding="utf-8")
        return scheduler.TaskResult(task, returncode=1, timed_out=timed_out)

    def test_points_at_symbols_when_that_is_the_cause(self, tmp_path) -> None:
        result = self._result(tmp_path, "ERROR: Unable to find a suitable symbol table")
        assert "symbols" in triage.probe_diagnosis(result).lower()

    def test_points_at_the_image_when_unidentifiable(self, tmp_path) -> None:
        result = self._result(tmp_path, "unsatisfied requirement plugins.Info.kernel")
        assert "identify the image" in triage.probe_diagnosis(result)

    def test_explains_a_timeout(self, tmp_path) -> None:
        result = self._result(tmp_path, "", timed_out=True)
        assert "timed out" in triage.probe_diagnosis(result)

    def test_falls_back_to_the_last_line(self, tmp_path) -> None:
        result = self._result(tmp_path, "something\nunexpected happened")
        assert "unexpected happened" in triage.probe_diagnosis(result)

    def test_unsatisfied_is_not_mistaken_for_a_symbol_problem(self, tmp_path) -> None:
        """Regression: "unsatisfied" contains "isf".

        A naive substring test sent the analyst back across the air gap for
        symbols they already had, on Volatility's commonest error message.
        """
        for text in (
            "unsatisfied requirement plugins.Info.kernel",
            "Unsatisfied requirement plugins.PsList.kernel.layer_name",
        ):
            result = self._result(tmp_path, text)
            diagnosis = triage.probe_diagnosis(result)
            assert "identify the image" in diagnosis
            assert "could not load symbols" not in diagnosis

    def test_a_genuine_isf_message_still_matches(self, tmp_path) -> None:
        result = self._result(tmp_path, "No ISF found for the required GUID")
        assert "could not load symbols" in triage.probe_diagnosis(result)


class TestDirectoriesAreCreated:
    """A zip stores no empty directories, so the bundle may arrive without them.

    Volatility failed with a bare FileNotFoundError on identifier.cache when the
    cache directory was absent — nothing an analyst could act on.
    """

    def test_creates_cache_and_output(self, tmp_path) -> None:
        plan = make_plan(tmp_path, ["a.B"])
        assert not plan.cache_dir.exists()
        assert not plan.output_dir.exists()

        plan.ensure_directories()

        assert plan.cache_dir.is_dir()
        assert plan.output_dir.is_dir()

    def test_is_idempotent(self, tmp_path) -> None:
        plan = make_plan(tmp_path, ["a.B"])
        plan.ensure_directories()
        plan.ensure_directories()  # must not raise
        assert plan.cache_dir.is_dir()

    def test_creates_nested_paths(self, tmp_path) -> None:
        plan = triage.TriagePlan(
            image=tmp_path / "i.raw",
            output_dir=tmp_path / "deep" / "nested" / "out",
            symbols_dir=tmp_path / "symbols",
            cache_dir=tmp_path / "deep" / "nested" / "cache",
            plugin_names=["a.B"],
            formats=["csv"],
        )
        plan.ensure_directories()
        assert plan.output_dir.is_dir() and plan.cache_dir.is_dir()


class TestFirstRunNotice:
    """An unannounced multi-minute pause reads as a hang."""

    def _probe(self, tmp_path, *, with_pack: bool, warmed: bool):
        plan = make_plan(tmp_path, ["a.B"])
        plan.symbols_dir.mkdir(parents=True, exist_ok=True)
        plan.cache_dir.mkdir(parents=True, exist_ok=True)
        if with_pack:
            (plan.symbols_dir / "windows.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)
        if warmed:
            (plan.cache_dir / "identifier.cache").write_bytes(b"cached")

        lines = []
        triage.run_probe(plan, FakeEngine(), log=lines.append)
        return "\n".join(lines)

    def test_warns_on_a_cold_cache_with_a_pack(self, tmp_path) -> None:
        assert "may take a few minutes" in self._probe(
            tmp_path, with_pack=True, warmed=False
        )

    def test_silent_once_the_cache_is_warm(self, tmp_path) -> None:
        assert "may take a few minutes" not in self._probe(
            tmp_path, with_pack=True, warmed=True
        )

    def test_silent_without_a_pack(self, tmp_path) -> None:
        assert "may take a few minutes" not in self._probe(
            tmp_path, with_pack=False, warmed=False
        )


class TestNoDeprecatedPluginNames:
    """Deprecated aliases still run, then stop working without warning.

    windows.malfind.Malfind moved to windows.malware.malfind.Malfind and the old
    name is due for removal in the first release after 2026-06-07. A curated set
    that names aliases would break silently on a volatility upgrade.
    """

    def test_no_curated_plugin_is_a_deprecated_alias(self) -> None:
        pytest.importorskip("volatility3")
        import volatility3.framework
        import volatility3.plugins

        volatility3.framework.require_interface_version(2, 0, 0)
        volatility3.framework.import_files(volatility3.plugins, True)
        available = volatility3.framework.list_plugins()

        aliases = []
        for name in catalog.triage_names():
            cls = available.get(name)
            assert cls is not None, f"{name} does not exist in this volatility"
            if getattr(getattr(cls, "run", None), "__wrapped__", None) is not None:
                aliases.append(name)

        assert not aliases, f"deprecated plugin aliases in the triage set: {aliases}"

    def test_malware_plugins_use_the_malware_namespace(self) -> None:
        for name in catalog.by_category("malware"):
            assert name.startswith("windows.malware."), name

    def test_malfind_uses_its_canonical_name(self) -> None:
        names = catalog.triage_names()
        assert "windows.malware.malfind.Malfind" in names
        assert "windows.malfind.Malfind" not in names


class TestRowCounting:
    """Exit code 0 with a header-only file is not success worth reporting as such."""

    def test_counts_data_rows_excluding_the_header(self, tmp_path) -> None:
        path = tmp_path / "out.csv"
        path.write_text("PID,Name\n4,System\n8,smss.exe\n", encoding="utf-8")
        assert triage.count_rows(path) == 2

    def test_a_header_only_file_is_zero_rows(self, tmp_path) -> None:
        path = tmp_path / "out.csv"
        path.write_text("PID,Name\n", encoding="utf-8")
        assert triage.count_rows(path) == 0

    def test_a_missing_file_is_zero(self, tmp_path) -> None:
        assert triage.count_rows(tmp_path / "absent.csv") == 0

    def test_outcomes_carry_row_counts(self, tmp_path) -> None:
        plan = make_plan(tmp_path, ["windows.pslist.PsList"], formats=("csv",))
        results = scheduler.run_tasks(triage.build_tasks(plan, FakeEngine()))
        (outcome,) = triage.collect_outcomes(plan, results)
        assert outcome.rows == 1  # FakeEngine emits one data row


class TestEmptyResultDiagnosis:
    """Every plugin succeeding with zero rows means the layer is not mapping."""

    def _run(self, tmp_path, *, vmware_warning: bool):
        plan = make_plan(tmp_path, ["windows.pslist.PsList"], formats=("csv",))
        engine = FakeEngine(header_only={"windows.pslist.PsList"})
        results = scheduler.run_tasks(triage.build_tasks(plan, engine))
        outcomes = triage.collect_outcomes(plan, results)
        if vmware_warning:
            log = triage.log_path(plan.output_dir, "windows.pslist.PsList", "csv")
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(
                "WARNING volatility3.framework.layers.vmware: No metadata file found "
                "alongside VMEM file.",
                encoding="utf-8",
            )
        return triage.layer_warning(plan, outcomes)

    def test_warns_when_everything_is_empty(self, tmp_path) -> None:
        warning = self._run(tmp_path, vmware_warning=False)
        assert warning is not None and "zero rows" in warning

    def test_names_the_vmem_metadata_cause_when_present(self, tmp_path) -> None:
        warning = self._run(tmp_path, vmware_warning=True)
        assert ".raw" in warning and "VMSS" in warning

    def test_silent_when_rows_were_produced(self, tmp_path) -> None:
        plan = make_plan(tmp_path, ["windows.pslist.PsList"], formats=("csv",))
        results = scheduler.run_tasks(triage.build_tasks(plan, FakeEngine()))
        outcomes = triage.collect_outcomes(plan, results)
        assert triage.layer_warning(plan, outcomes) is None
