"""Rule packs: load them, check them, run them.

Rules live outside the code because they change faster than it does, and an
analyst on an air-gapped host cannot rebuild the bundle to add one. A pack is
plain JSON — ``app/`` depends on nothing beyond the standard library, and
PyYAML would be the first exception to that as well as one more item for an
approval authority to consider.

There is no expression language. A condition is structured data over the closed
signal vocabulary in ``analysis.py``, combined with ``all``, ``any``, ``none``
and ``at_least``. That needs no parser and no ``eval``, and it makes a rule
naming a signal that does not exist a load-time error rather than a rule that
sits in the pack forever and never fires.

Severity is one of three labels, never a number. A score invites the reader to
treat 0.82 as meaningfully worse than 0.78 and cannot be defended in a report;
a finding that names its rule and cites the rows that triggered it can be.
"""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .analysis import SIGNAL_SOURCE, VOCABULARY, Analysis, Process

SCHEMA_VERSION = 1
SEVERITIES = ("critical", "high", "medium")
COMBINATORS = ("all", "any", "none", "at_least", "signal")

DEFAULT_PACK = Path(__file__).parent / "rules" / "default.json"


class RulePackError(ValueError):
    """A pack that cannot be trusted to mean what it says."""


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    condition: dict
    actions: tuple[str, ...]
    note: str | None = None

    def signals(self) -> set[str]:
        return _referenced_signals(self.condition)


@dataclass(frozen=True)
class RulePack:
    name: str
    version: str
    path: Path
    sha256: str
    rules: tuple[Rule, ...]


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    severity: str
    title: str
    process: Process
    evidence: list[dict] = field(default_factory=list)
    actions: tuple[str, ...] = ()

    def as_dict(self, *, rules_sha256: str) -> dict:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "rules_sha256": rules_sha256,
            "severity": self.severity,
            "title": self.title,
            "entity": self.process.as_entity(),
            "evidence": self.evidence,
            "recommended_actions": list(self.actions),
        }


# --------------------------------------------------------------------------
# Loading and validation
# --------------------------------------------------------------------------


def _referenced_signals(node) -> set[str]:
    found: set[str] = set()
    if isinstance(node, dict):
        if "signal" in node:
            found.add(node["signal"])
        for key in ("all", "any", "none"):
            for child in node.get(key, []) or []:
                found |= _referenced_signals(child)
        if "at_least" in node:
            for child in (node["at_least"] or {}).get("of", []) or []:
                found |= _referenced_signals(child)
    return found


def _nearest(name: str) -> str:
    """Cheapest useful suggestion: the known signal sharing the most prefix."""
    best = max(
        VOCABULARY,
        key=lambda known: len(_common_prefix(name, known)),
        default="",
    )
    return best if len(_common_prefix(name, best)) >= 3 else ""


def _common_prefix(a: str, b: str) -> str:
    out = []
    for x, y in zip(a, b):
        if x != y:
            break
        out.append(x)
    return "".join(out)


def _validate_condition(node, where: str, problems: list[str]) -> None:
    if not isinstance(node, dict):
        problems.append(f"{where}: condition must be an object, got {type(node).__name__}")
        return

    used = [k for k in COMBINATORS if k in node]
    if len(used) != 1:
        problems.append(
            f"{where}: expected exactly one of {', '.join(COMBINATORS)}, "
            f"found {len(used)}"
        )
        return

    key = used[0]
    if key == "signal":
        name = node["signal"]
        if name not in VOCABULARY:
            hint = _nearest(str(name))
            suggestion = f' — did you mean "{hint}"?' if hint else ""
            problems.append(
                f"{where}: unknown signal \"{name}\"{suggestion}\n"
                f"    known signals: {', '.join(sorted(VOCABULARY))}"
            )
        return

    if key == "at_least":
        spec = node["at_least"]
        if not isinstance(spec, dict) or "count" not in spec or "of" not in spec:
            problems.append(f"{where}: at_least needs both 'count' and 'of'")
            return
        if not isinstance(spec["count"], int) or spec["count"] < 1:
            problems.append(f"{where}: at_least.count must be a positive integer")
        children = spec.get("of") or []
        if len(children) < spec.get("count", 1):
            problems.append(
                f"{where}: at_least.count ({spec['count']}) exceeds the "
                f"{len(children)} condition(s) in 'of' — it can never match"
            )
        for index, child in enumerate(children):
            _validate_condition(child, f"{where}.at_least.of[{index}]", problems)
        return

    children = node[key]
    if not isinstance(children, list) or not children:
        problems.append(f"{where}: '{key}' must be a non-empty list")
        return
    for index, child in enumerate(children):
        _validate_condition(child, f"{where}.{key}[{index}]", problems)


def validate(document: dict, *, known_actions: set[str] | None = None) -> list[str]:
    """Return every problem with a pack, rather than stopping at the first."""
    problems: list[str] = []

    if document.get("schema_version") != SCHEMA_VERSION:
        problems.append(
            f"schema_version must be {SCHEMA_VERSION}, "
            f"got {document.get('schema_version')!r}"
        )

    rules = document.get("rules")
    if not isinstance(rules, list) or not rules:
        problems.append("pack contains no rules")
        return problems

    seen: set[str] = set()
    for index, raw in enumerate(rules):
        if not isinstance(raw, dict):
            problems.append(f"rule {index}: must be an object")
            continue

        rule_id = raw.get("id")
        where = f"rule {index} ({rule_id})" if rule_id else f"rule {index}"

        if not rule_id:
            problems.append(f"{where}: missing 'id'")
        elif rule_id in seen:
            problems.append(f"{where}: duplicate id")
        else:
            seen.add(rule_id)

        if raw.get("severity") not in SEVERITIES:
            problems.append(
                f"{where}: severity must be one of {', '.join(SEVERITIES)}, "
                f"got {raw.get('severity')!r}"
            )
        if not raw.get("title"):
            problems.append(f"{where}: missing 'title'")

        condition = {k: v for k, v in raw.items() if k in COMBINATORS}
        _validate_condition(condition, where, problems)

        actions = raw.get("actions") or []
        if not isinstance(actions, list):
            problems.append(f"{where}: 'actions' must be a list")
        elif known_actions is not None:
            for action in actions:
                if action not in known_actions:
                    problems.append(
                        f"{where}: unknown action \"{action}\"\n"
                        f"    known actions: {', '.join(sorted(known_actions))}"
                    )

    return problems


def load(path: Path, *, known_actions: set[str] | None = None) -> RulePack:
    """Read and validate a pack, or raise with every problem it has."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RulePackError(f"cannot read rule pack {path}: {exc}") from exc

    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RulePackError(f"{path} is not valid JSON: {exc}") from exc

    problems = validate(document, known_actions=known_actions)
    if problems:
        raise RulePackError(
            f"{path} has {len(problems)} problem(s):\n  "
            + "\n  ".join(problems)
        )

    rules = tuple(
        Rule(
            id=raw_rule["id"],
            severity=raw_rule["severity"],
            title=raw_rule["title"],
            note=raw_rule.get("note"),
            condition={k: v for k, v in raw_rule.items() if k in COMBINATORS},
            actions=tuple(raw_rule.get("actions") or ()),
        )
        for raw_rule in document["rules"]
    )

    return RulePack(
        name=document.get("name", path.stem),
        version=str(document.get("version", "")),
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        rules=rules,
    )


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------


def matches(condition: dict, signals: set[str]) -> bool:
    if "signal" in condition:
        return condition["signal"] in signals
    if "all" in condition:
        return all(matches(c, signals) for c in condition["all"])
    if "any" in condition:
        return any(matches(c, signals) for c in condition["any"])
    if "none" in condition:
        return not any(matches(c, signals) for c in condition["none"])
    spec = condition["at_least"]
    hits = sum(1 for c in spec["of"] if matches(c, signals))
    return hits >= spec["count"]


#: How a matched signal is described in a finding's evidence.
REASON = {
    "pslist": "present in the active process list",
    "psscan": "recovered by pool scan",
    "psscan_only": "found by scan, absent from the active list, and not exited",
    "exited": "process has terminated",
    "malfind": "executable private memory not backed by a file",
    "hollow": "process image does not match its backing file",
    "ghosted": "image file marked for deletion while mapped",
    "peb_masquerade": "PEB image path or command line disagrees with the EPROCESS",
    "psxview_hidden": "missing from the active list but visible to another view",
    "suspicious_thread": "thread starts outside any legitimate mapped module",
    "ldrmodules_unlinked": "module present in some PEB lists but not others",
    "network": "holds a network endpoint",
    "network_external": "connected to a routable external address",
    "unusual_parent": "parent process is not the one Windows creates it from",
}


def evidence_for(signal: str, process: Process) -> dict | None:
    """One evidence entry, citing the row that produced the signal."""
    plugin = SIGNAL_SOURCE.get(signal)
    if plugin is None:
        return None

    rows = process.rows(plugin)
    reason = REASON.get(signal, signal)

    # Say which address, rather than making the analyst open the file to find it.
    if signal == "network_external":
        from .analysis import _is_external  # local: presentation detail only

        for row in rows:
            if _is_external(row.get("ForeignAddr")):
                reason = (
                    f"{reason}: {row.get('ForeignAddr')}:{row.get('ForeignPort')}"
                )
                return {"plugin": plugin, "reason": reason, "row": row}

    if signal == "unusual_parent":
        reason = f"{reason} (PPID {process.ppid})"

    return {
        "plugin": plugin,
        "reason": reason,
        "row": rows[0] if rows else None,
    }


def not_evaluated(pack: RulePack, analysis: Analysis) -> dict[str, str]:
    """Rules that could not run, because a plugin they need is absent.

    Reported so a clean findings file cannot be mistaken for full coverage.
    """
    blocked: dict[str, str] = {}
    for rule in pack.rules:
        needed = {SIGNAL_SOURCE[s] for s in rule.signals() if s in SIGNAL_SOURCE}
        absent = sorted(needed & set(analysis.plugins_missing))
        if absent:
            blocked[rule.id] = f"requires {', '.join(absent)}"
    return blocked


def evaluate(pack: RulePack, analysis: Analysis) -> list[Finding]:
    """Run every rule against every process, most severe first."""
    blocked = not_evaluated(pack, analysis)
    findings: list[Finding] = []

    for rule in pack.rules:
        if rule.id in blocked:
            continue
        for process in analysis.processes:
            if not matches(rule.condition, process.signals):
                continue
            evidence = [
                entry
                for entry in (
                    evidence_for(signal, process)
                    for signal in sorted(rule.signals() & process.signals)
                )
                if entry is not None
            ]
            findings.append(
                Finding(
                    finding_id="",
                    rule_id=rule.id,
                    severity=rule.severity,
                    title=rule.title,
                    process=process,
                    evidence=evidence,
                    actions=rule.actions,
                )
            )

    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.process.pid))
    for index, finding in enumerate(findings, start=1):
        finding.finding_id = f"PROC-{index:04d}"
    return findings


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def summarise(findings: list[Finding]) -> dict:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    counts["total"] = len(findings)
    return counts


def document(pack: RulePack, analysis: Analysis, findings: list[Finding]) -> dict:
    """The machine-readable findings file.

    ``not_evaluated`` and ``plugins_missing`` are as important as the findings
    themselves: without them an empty list reads as "nothing was wrong" when it
    may mean "the plugin that would have said so never ran".
    """
    from . import manifest  # local: avoids a cycle through the package __init__

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": manifest.utc_now(),
        "rule_pack": {
            "name": pack.name,
            "version": pack.version,
            "path": str(pack.path),
            "sha256": pack.sha256,
        },
        "summary": summarise(findings),
        "processes_examined": len(analysis.processes),
        "plugins_read": analysis.plugins_read,
        "plugins_missing": analysis.plugins_missing,
        "not_evaluated": not_evaluated(pack, analysis),
        "findings": [f.as_dict(rules_sha256=pack.sha256) for f in findings],
    }


CSV_COLUMNS = (
    "finding_id",
    "severity",
    "rule_id",
    "title",
    "pid",
    "process",
    "offset",
    "evidence",
    "recommended_actions",
)


def write(findings_dir: Path, pack: RulePack, analysis: Analysis,
          findings: list[Finding]) -> tuple[Path, Path]:
    """Write both files. JSON is the machine interface; CSV is for the analyst."""
    findings_dir.mkdir(parents=True, exist_ok=True)

    json_path = findings_dir / "findings.json"
    json_path.write_text(
        json.dumps(document(pack, analysis, findings), indent=2) + "\n",
        encoding="utf-8",
    )

    csv_path = findings_dir / "findings.csv"
    with open(csv_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for finding in findings:
            writer.writerow(
                [
                    finding.finding_id,
                    finding.severity,
                    finding.rule_id,
                    finding.title,
                    finding.process.pid,
                    finding.process.name or "",
                    hex(finding.process.offset) if finding.process.offset else "",
                    "; ".join(e["reason"] for e in finding.evidence),
                    " ".join(finding.actions),
                ]
            )

    return json_path, csv_path
