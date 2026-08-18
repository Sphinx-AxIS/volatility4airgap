"""Tests for rule packs: loading, validation, and evaluation.

Evaluation is pure — a signal set in, findings out — so most of these need no
fixture at all. The pack that ships is checked separately, because a typo there
is a rule that never fires rather than an error anyone sees.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from app import analysis, followup, rules

FIXTURE = Path(__file__).parent / "fixtures" / "triage-sample"

MINIMAL = {
    "schema_version": 1,
    "name": "test",
    "version": "1",
    "rules": [
        {
            "id": "R-1",
            "severity": "high",
            "title": "A rule",
            "signal": "malfind",
            "actions": ["inspect_vads"],
        }
    ],
}


def pack_file(tmp_path: Path, document: dict) -> Path:
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(document))
    return path


def process(pid: int, *signals: str) -> analysis.Process:
    entity = analysis.Process(pid=pid, name=f"p{pid}.exe")
    entity.signals = set(signals)
    return entity


@pytest.fixture
def sample(tmp_path) -> Path:
    destination = tmp_path / "memory"
    shutil.copytree(FIXTURE, destination)
    return destination


class TestMatching:
    def test_a_bare_signal(self) -> None:
        assert rules.matches({"signal": "malfind"}, {"malfind"})
        assert not rules.matches({"signal": "malfind"}, {"hollow"})

    def test_all(self) -> None:
        condition = {"all": [{"signal": "malfind"}, {"signal": "network_external"}]}
        assert rules.matches(condition, {"malfind", "network_external"})
        assert not rules.matches(condition, {"malfind"})

    def test_any(self) -> None:
        condition = {"any": [{"signal": "hollow"}, {"signal": "ghosted"}]}
        assert rules.matches(condition, {"ghosted"})
        assert not rules.matches(condition, {"malfind"})

    def test_none(self) -> None:
        condition = {"none": [{"signal": "exited"}]}
        assert rules.matches(condition, {"malfind"})
        assert not rules.matches(condition, {"exited"})

    def test_at_least(self) -> None:
        condition = {
            "at_least": {
                "count": 3,
                "of": [
                    {"signal": "malfind"},
                    {"signal": "suspicious_thread"},
                    {"signal": "network_external"},
                    {"signal": "unusual_parent"},
                ],
            }
        }
        assert rules.matches(
            condition, {"malfind", "suspicious_thread", "network_external"}
        )
        assert not rules.matches(condition, {"malfind", "suspicious_thread"})

    def test_combinators_nest(self) -> None:
        condition = {
            "all": [
                {"signal": "malfind"},
                {"none": [{"signal": "network_external"}, {"signal": "exited"}]},
            ]
        }
        assert rules.matches(condition, {"malfind"})
        assert not rules.matches(condition, {"malfind", "exited"})


class TestValidation:
    def test_a_good_pack_has_no_problems(self) -> None:
        assert rules.validate(MINIMAL) == []

    def test_unknown_signal_is_rejected_with_a_suggestion(self) -> None:
        document = json.loads(json.dumps(MINIMAL))
        document["rules"][0]["signal"] = "malfound"
        (problem,) = rules.validate(document)

        assert 'unknown signal "malfound"' in problem
        assert 'did you mean "malfind"' in problem
        assert "known signals:" in problem

    def test_unknown_combinator_is_rejected(self) -> None:
        document = json.loads(json.dumps(MINIMAL))
        del document["rules"][0]["signal"]
        document["rules"][0]["most"] = [{"signal": "malfind"}]

        assert any("exactly one of" in p for p in rules.validate(document))

    def test_missing_id(self) -> None:
        document = json.loads(json.dumps(MINIMAL))
        del document["rules"][0]["id"]

        assert any("missing 'id'" in p for p in rules.validate(document))

    def test_duplicate_id(self) -> None:
        document = json.loads(json.dumps(MINIMAL))
        document["rules"].append(dict(document["rules"][0]))

        assert any("duplicate id" in p for p in rules.validate(document))

    def test_bad_severity(self) -> None:
        document = json.loads(json.dumps(MINIMAL))
        document["rules"][0]["severity"] = "catastrophic"

        assert any("severity must be one of" in p for p in rules.validate(document))

    def test_wrong_schema_version(self) -> None:
        document = json.loads(json.dumps(MINIMAL))
        document["schema_version"] = 99

        assert any("schema_version must be 1" in p for p in rules.validate(document))

    def test_at_least_that_can_never_match(self) -> None:
        """count greater than the conditions available is always a mistake."""
        document = json.loads(json.dumps(MINIMAL))
        del document["rules"][0]["signal"]
        document["rules"][0]["at_least"] = {
            "count": 5, "of": [{"signal": "malfind"}]
        }

        assert any("can never match" in p for p in rules.validate(document))

    def test_unknown_action_is_rejected_when_actions_are_known(self) -> None:
        document = json.loads(json.dumps(MINIMAL))
        document["rules"][0]["actions"] = ["inspect_everything"]
        problems = rules.validate(document, known_actions=set(followup.ACTIONS))

        assert any('unknown action "inspect_everything"' in p for p in problems)

    def test_every_problem_is_reported_not_just_the_first(self) -> None:
        document = json.loads(json.dumps(MINIMAL))
        document["rules"][0]["severity"] = "nope"
        document["rules"][0]["signal"] = "nonsense"
        del document["rules"][0]["title"]

        assert len(rules.validate(document)) == 3


class TestLoading:
    def test_loads_and_hashes(self, tmp_path) -> None:
        path = pack_file(tmp_path, MINIMAL)
        pack = rules.load(path)

        assert len(pack.rules) == 1
        assert len(pack.sha256) == 64

    def test_the_digest_changes_with_the_content(self, tmp_path) -> None:
        """Findings cite this, so it must identify the rule text exactly."""
        first = rules.load(pack_file(tmp_path, MINIMAL)).sha256

        document = json.loads(json.dumps(MINIMAL))
        document["rules"][0]["title"] = "A different rule"
        second = rules.load(pack_file(tmp_path, document)).sha256

        assert first != second

    def test_invalid_json_names_the_file(self, tmp_path) -> None:
        path = tmp_path / "rules.json"
        path.write_text("{ not json")

        with pytest.raises(rules.RulePackError, match="not valid JSON"):
            rules.load(path)

    def test_a_missing_file_is_reported(self, tmp_path) -> None:
        with pytest.raises(rules.RulePackError, match="cannot read"):
            rules.load(tmp_path / "absent.json")

    def test_a_bad_pack_raises_with_every_problem(self, tmp_path) -> None:
        document = json.loads(json.dumps(MINIMAL))
        document["rules"][0]["signal"] = "nonsense"

        with pytest.raises(rules.RulePackError, match="1 problem"):
            rules.load(pack_file(tmp_path, document))


class TestShippedPack:
    """The pack that ships is validated here, not only when a run loads it."""

    @pytest.fixture
    def pack(self) -> rules.RulePack:
        return rules.load(rules.DEFAULT_PACK, known_actions=set(followup.ACTIONS))

    def test_it_loads(self, pack) -> None:
        assert len(pack.rules) == 28

    def test_every_signal_is_in_its_entitys_vocabulary(self, pack) -> None:
        for rule in pack.rules:
            unknown = rule.signals() - analysis.VOCABULARY[rule.entity]
            assert not unknown, f"{rule.id} ({rule.entity}) references {unknown}"

    def test_every_entity_type_has_rules(self, pack) -> None:
        covered = {rule.entity for rule in pack.rules}
        assert covered == set(analysis.VOCABULARY)

    def test_finding_id_prefixes_cover_every_entity_type(self) -> None:
        assert set(rules._PREFIX) == set(analysis.VOCABULARY)

    def test_every_action_has_an_implementation(self, pack) -> None:
        """A typo here is a rule that recommends a step nothing can perform."""
        for rule in pack.rules:
            unknown = set(rule.actions) - set(followup.ACTIONS)
            assert not unknown, f"{rule.id} recommends {unknown}"

    def test_every_rule_has_a_note_explaining_itself(self, pack) -> None:
        """JSON has no comments, so the note is the only place reasoning lives."""
        assert all(rule.note for rule in pack.rules)

    def test_ids_are_unique(self, pack) -> None:
        ids = [rule.id for rule in pack.rules]
        assert len(ids) == len(set(ids))


class TestEvaluation:
    @pytest.fixture
    def pack(self) -> rules.RulePack:
        return rules.load(rules.DEFAULT_PACK, known_actions=set(followup.ACTIONS))

    def test_findings_are_ordered_most_severe_first(self, pack, sample) -> None:
        findings = rules.evaluate(pack, analysis.analyse(sample))
        ranks = [rules.SEVERITIES.index(f.severity) for f in findings]

        assert ranks == sorted(ranks)

    def test_finding_ids_are_numbered_within_their_prefix(self, pack, sample) -> None:
        """PROC-0003 is the third process finding, not the third finding."""
        findings = rules.evaluate(pack, analysis.analyse(sample))
        seen = [f.finding_id for f in findings if f.finding_id.startswith("PROC")]

        assert seen == [f"PROC-{n:04d}" for n in range(1, len(seen) + 1)]

    def test_evidence_cites_the_plugin_and_the_row(self, pack, sample) -> None:
        findings = rules.evaluate(pack, analysis.analyse(sample))
        (injected,) = [f for f in findings if f.rule_id == "PROC-INJECT-NET"]

        plugins = {e["plugin"] for e in injected.evidence}
        assert "windows.malware.malfind.Malfind" in plugins
        assert "windows.netscan.NetScan" in plugins
        assert all(e["row"] for e in injected.evidence)

    def test_the_external_address_is_named_in_the_evidence(self, pack, sample) -> None:
        """So the analyst does not have to open the file to find out which."""
        findings = rules.evaluate(pack, analysis.analyse(sample))
        (injected,) = [f for f in findings if f.rule_id == "PROC-INJECT-NET"]
        reasons = " ".join(e["reason"] for e in injected.evidence)

        assert "93.184.216.34:443" in reasons

    def test_a_rule_whose_plugin_is_absent_is_not_evaluated(self, pack, sample) -> None:
        (sample / "windows.malware.hollowprocesses.HollowProcesses.json").unlink()
        result = analysis.analyse(sample)

        assert "PROC-HOLLOW" in rules.not_evaluated(pack, result)
        assert not [
            f for f in rules.evaluate(pack, result) if f.rule_id == "PROC-HOLLOW"
        ]

    def test_a_finding_records_the_rule_that_produced_it(self, pack, sample) -> None:
        findings = rules.evaluate(pack, analysis.analyse(sample))
        document = findings[0].as_dict(rules_sha256=pack.sha256)

        assert document["rule_id"]
        assert document["rules_sha256"] == pack.sha256

    def test_severity_is_never_a_number(self, pack, sample) -> None:
        findings = rules.evaluate(pack, analysis.analyse(sample))
        assert all(f.severity in rules.SEVERITIES for f in findings)


class TestExpectedFindings:
    """The golden test: the whole pipeline over a fixture with known planting."""

    #: PROC-DOTNET-MZ is the newest entry. The planted powershell's malfind
    #: region has always begun with MZ; the fixture now also maps clr.dll into
    #: it, which is what makes that header mean something — a JIT compiles into
    #: private memory but never writes a PE header there. explorer's region
    #: begins with MZ too, but explorer hosts no runtime, so it stays a bare
    #: PROC-INJECT with the header noted in its evidence.
    #:
    #: PROC-SYSTEM-MASQUERADE before it: the fixture has always planted a fake
    #: lsass — parented by powershell, PEB path spoofed, real image at
    #: \Device\Temp\x.exe — but nothing read the image path, so it was only
    #: ever caught indirectly, as one more anomaly in PROC-MULTI-SIGNAL.
    EXPECTED = [
        ("KERN-0001", "KERN-SSDT-HOOK", "critical", "evilrk.sys"),
        ("PROC-0001", "PROC-INJECT-NET", "critical", "powershell.exe (PID 4180)"),
        ("PROC-0002", "PROC-THREAD-INJECT", "critical", "powershell.exe (PID 4180)"),
        ("PROC-0003", "PROC-SYSTEM-MASQUERADE", "critical", "lsass.exe (PID 6000)"),
        ("SVC-0001", "SVC-HOST-INJECTED", "critical", "SysMonSvc (PID 4180)"),
        ("KERN-0002", "KERN-CALLBACK-UNKNOWN", "high", "<unresolved>"),
        ("KERN-0003", "KERN-UNLINKED", "high", "evilrk.sys"),
        ("KERN-0004", "KERN-UNBACKED-DRIVER", "high", "evilrk.sys"),
        ("PROC-0004", "PROC-DOTNET-MZ", "high", "powershell.exe (PID 4180)"),
        ("PROC-0005", "PROC-MULTI-SIGNAL", "high", "powershell.exe (PID 4180)"),
        ("PROC-0006", "PROC-HOLLOW", "high", "svchost.exe (PID 5000)"),
        ("PROC-0007", "PROC-MULTI-SIGNAL", "high", "lsass.exe (PID 6000)"),
        ("PROC-0008", "PROC-HIDDEN", "high", "rundll32.exe (PID 7224)"),
        ("PROC-0009", "PROC-XVIEW", "high", "rundll32.exe (PID 7224)"),
        ("SVC-0002", "SVC-HIDDEN", "high", "GhostSvc"),
        ("SVC-0003", "SVC-USER-PATH", "high", "UpdaterSvc (PID 2100)"),
        ("PROC-0010", "PROC-INJECT", "medium", "explorer.exe (PID 2100)"),
    ]

    def test_matches(self, sample) -> None:
        pack = rules.load(rules.DEFAULT_PACK, known_actions=set(followup.ACTIONS))
        findings = rules.evaluate(pack, analysis.analyse(sample))

        actual = [
            (f.finding_id, f.rule_id, f.severity, f.entity.label) for f in findings
        ]
        assert actual == self.EXPECTED

    def test_the_healthy_processes_produce_nothing(self, sample) -> None:
        """Eight of the thirteen planted processes are ordinary."""
        pack = rules.load(rules.DEFAULT_PACK, known_actions=set(followup.ACTIONS))
        findings = rules.evaluate(pack, analysis.analyse(sample))
        flagged = {
            f.entity.pid for f in findings if f.entity.kind == analysis.PROCESS
        }

        assert flagged & {4, 388, 500, 560, 660, 700, 900, 3300} == set()

    def test_the_healthy_modules_produce_nothing(self, sample) -> None:
        pack = rules.load(rules.DEFAULT_PACK, known_actions=set(followup.ACTIONS))
        findings = rules.evaluate(pack, analysis.analyse(sample))
        flagged = {
            f.entity.key for f in findings if f.entity.kind == analysis.MODULE
        }

        assert flagged & {"ntoskrnl", "tcpip", "ndis", "wmixwdm"} == set()

    def test_a_known_exception_driver_does_not_fire(self, sample) -> None:
        """DriverModule marks the benign disconnects; the rule must honour it."""
        result = analysis.analyse(sample)
        (known,) = [m for m in result.modules if m.key == "wmixwdm"]

        assert "known_exception" in known.signals
        assert "unbacked_driver" not in known.signals

    def test_bare_malfind_does_not_escalate_a_service(self, sample) -> None:
        """explorer has malfind but nothing qualifying it, so UpdaterSvc's only
        finding is its binary path — not a critical host-injection claim."""
        pack = rules.load(rules.DEFAULT_PACK, known_actions=set(followup.ACTIONS))
        findings = rules.evaluate(pack, analysis.analyse(sample))
        updater = [f for f in findings if getattr(f.entity, "key", "") == "updatersvc"]

        assert [f.rule_id for f in updater] == ["SVC-USER-PATH"]


def dotnet_process(pid: int, hexdump: str, *, runtime: str | None = "clr.dll"):
    """A process with one malfind region and, optionally, a mapped runtime.

    Built without the shared fixture so the golden list above stays a
    regression check rather than growing with every scenario.
    """
    entity = analysis.Process(pid=pid, name="app.exe")
    entity.seen_in["windows.malware.malfind.Malfind"] = [{
        "PID": pid, "Process": "app.exe", "Start VPN": 0x2A0000,
        "End VPN": 0x2A0FFF, "Protection": "PAGE_EXECUTE_READWRITE",
        "PrivateMemory": 1, "Hexdump": hexdump, "Notes": None,
    }]
    if runtime:
        entity.seen_in["windows.malware.ldrmodules.LdrModules"] = [{
            "Pid": pid, "Process": "app.exe", "Base": 0x7FF000000000,
            "InLoad": True, "InInit": True, "InMem": True,
            "MappedPath": f"\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\{runtime}",
        }]
    result = analysis.Analysis(processes=[entity])
    analysis.compute_process_signals(entity, result)
    return entity, result


class TestDotNetMalfind:
    """A .NET process trips malfind by design; the annotation says so, and the
    one case that is not the JIT — a region beginning with MZ — is escalated
    rather than explained away with the rest."""

    @pytest.fixture
    def pack(self) -> rules.RulePack:
        return rules.load(rules.DEFAULT_PACK, known_actions=set(followup.ACTIONS))

    def test_jit_output_in_a_dotnet_process_is_annotated_not_suppressed(
        self, pack
    ) -> None:
        _, result = dotnet_process(100, "55 48 8b ec 48 83 ec 20")
        findings = rules.evaluate(pack, result)

        assert [f.rule_id for f in findings] == ["PROC-INJECT"]
        (reason,) = [e["reason"] for e in findings[0].evidence]
        assert "expected in a .NET process" in reason
        assert "no region begins with an MZ header" in reason

    def test_an_mz_region_in_a_dotnet_process_is_the_exception(self, pack) -> None:
        _, result = dotnet_process(100, "4d 5a 90 00 03 00 00 00")
        findings = rules.evaluate(pack, result)

        assert [f.rule_id for f in findings] == ["PROC-DOTNET-MZ"]
        assert findings[0].severity == "high"

    def test_the_finding_names_the_runtime_and_the_region(self, pack) -> None:
        """So the dump command the report suggests can be checked against it."""
        _, result = dotnet_process(100, "4d 5a 90 00 03 00 00 00")
        (finding,) = rules.evaluate(pack, result)
        by_plugin = {e["plugin"].rsplit(".", 1)[-1]: e for e in finding.evidence}

        assert "clr.dll mapped" in by_plugin["LdrModules"]["reason"]
        assert "0x2a0000" in by_plugin["Malfind"]["reason"]
        assert by_plugin["Malfind"]["row"]["Hexdump"].startswith("4d 5a")

    def test_an_mz_region_without_a_runtime_stays_a_bare_malfind(self, pack) -> None:
        """No JIT to explain the region, so nothing to discriminate against;
        the header is noted in the evidence rather than raised."""
        _, result = dotnet_process(100, "4d 5a 90 00 03 00 00 00", runtime=None)
        findings = rules.evaluate(pack, result)

        assert [f.rule_id for f in findings] == ["PROC-INJECT"]
        (reason,) = [e["reason"] for e in findings[0].evidence]
        assert "MZ header at the start of the region (0x2a0000)" in reason
        assert ".NET" not in reason

    def test_a_signal_the_rule_excludes_on_is_not_cited_as_evidence(
        self, pack
    ) -> None:
        """PROC-INJECT excludes on (dotnet_runtime and malfind_mz). A process
        with malfind_mz alone still matches, and that signal must not then
        appear as if it were why."""
        entity, result = dotnet_process(100, "4d 5a 90 00", runtime=None)
        assert "malfind_mz" in entity.signals

        (finding,) = rules.evaluate(pack, result)
        assert [e["plugin"] for e in finding.evidence] == [
            "windows.malware.malfind.Malfind"
        ]

    def test_evidence_signals_leave_out_the_none_clause(self) -> None:
        rule = rules.Rule(
            id="R", severity="high", title="t", actions=(),
            condition={"all": [
                {"signal": "malfind"},
                {"none": [{"all": [{"signal": "dotnet_runtime"},
                                   {"signal": "malfind_mz"}]}]},
            ]},
        )
        assert rule.signals() == {"malfind", "dotnet_runtime", "malfind_mz"}
        assert rule.evidence_signals() == {"malfind"}


class TestOutput:
    @pytest.fixture
    def written(self, sample, tmp_path):
        pack = rules.load(rules.DEFAULT_PACK, known_actions=set(followup.ACTIONS))
        result = analysis.analyse(sample)
        findings = rules.evaluate(pack, result)
        paths = rules.write(tmp_path / "findings", pack, result, findings)
        return paths, pack

    def test_json_records_what_could_not_be_evaluated(self, written) -> None:
        """An empty findings list must not read as full coverage."""
        (json_path, _), _ = written
        document = json.loads(json_path.read_text())

        assert "not_evaluated" in document
        assert "plugins_missing" in document
        assert "windows.netstat.NetStat" in document["plugins_missing"]

    def test_a_readable_report_is_written_too(self, written) -> None:
        """findings.csv is a table; findings.txt is the paragraph above it."""
        (json_path, _), _ = written
        text = (json_path.parent / "findings.txt").read_text()

        assert "FINDINGS" in text
        assert "evilrk.sys" in text
        assert "SysMonSvc" in text

    def test_the_report_names_rules_that_could_not_run(self, sample, tmp_path) -> None:
        """Their absence from the findings above must not read as a clean result."""
        (sample / "windows.malware.hollowprocesses.HollowProcesses.json").unlink()
        pack = rules.load(rules.DEFAULT_PACK, known_actions=set(followup.ACTIONS))
        result = analysis.analyse(sample)
        text = rules.report(pack, result, rules.evaluate(pack, result))

        assert "NOT EVALUATED" in text
        assert "PROC-HOLLOW" in text

    def test_the_report_does_not_repeat_a_title_as_its_own_evidence(
        self, written
    ) -> None:
        (json_path, _), _ = written
        text = (json_path.parent / "findings.txt").read_text()

        assert text.count("Kernel callback owned by no identifiable module") == 1

    def test_json_records_the_rule_pack_digest(self, written) -> None:
        (json_path, _), pack = written
        document = json.loads(json_path.read_text())

        assert document["rule_pack"]["sha256"] == pack.sha256

    def test_csv_has_one_row_per_finding(self, written) -> None:
        import csv as csv_mod

        (_, csv_path), _ = written
        with open(csv_path, encoding="utf-8") as handle:
            rows = list(csv_mod.reader(handle))

        assert rows[0] == list(rules.CSV_COLUMNS)
        assert len(rows) == 18  # header plus seventeen findings
