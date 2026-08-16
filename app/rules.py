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

from .analysis import (
    ALL_SIGNALS,
    PROCESS,
    SIGNAL_SOURCE,
    VOCABULARY,
    Analysis,
    Entity,
)

SCHEMA_VERSION = 1
SEVERITIES = ("critical", "high", "medium")
COMBINATORS = ("all", "any", "none", "at_least", "signal")
ENTITY_TYPES = tuple(VOCABULARY)

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
    #: Which entity type the rule reads. Absent means process, so packs written
    #: before modules and services existed keep working unchanged.
    entity: str = PROCESS

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
    entity: Entity
    evidence: list[dict] = field(default_factory=list)
    actions: tuple[str, ...] = ()

    def as_dict(self, *, rules_sha256: str) -> dict:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "rules_sha256": rules_sha256,
            "severity": self.severity,
            "title": self.title,
            "entity": self.entity.as_entity(),
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


def _nearest(name: str, vocabulary) -> str:
    """Cheapest useful suggestion: the known signal sharing the most prefix.

    Searched across every entity type, not just the rule's own, so naming a
    module signal in a process rule is told what it actually is rather than
    offered the nearest unrelated word.
    """
    best = max(
        vocabulary or ALL_SIGNALS,
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


def _validate_condition(
    node, where: str, problems: list[str], vocabulary: frozenset
) -> None:
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
        if name not in vocabulary:
            # Naming a real signal belonging to another entity type is the most
            # likely mistake, so say so rather than offering a spelling.
            elsewhere = [
                kind for kind, known in VOCABULARY.items() if name in known
            ]
            if elsewhere:
                suggestion = f' — that is a {elsewhere[0]} signal'
            else:
                hint = _nearest(str(name), vocabulary)
                suggestion = f' — did you mean "{hint}"?' if hint else ""
            problems.append(
                f"{where}: unknown signal \"{name}\"{suggestion}\n"
                f"    known signals: {', '.join(sorted(vocabulary))}"
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
            _validate_condition(
                child, f"{where}.at_least.of[{index}]", problems, vocabulary
            )
        return

    children = node[key]
    if not isinstance(children, list) or not children:
        problems.append(f"{where}: '{key}' must be a non-empty list")
        return
    for index, child in enumerate(children):
        _validate_condition(child, f"{where}.{key}[{index}]", problems, vocabulary)


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

        entity = raw.get("entity", PROCESS)
        if entity not in VOCABULARY:
            problems.append(
                f"{where}: unknown entity {entity!r}, "
                f"expected one of {', '.join(ENTITY_TYPES)}"
            )
            continue

        condition = {k: v for k, v in raw.items() if k in COMBINATORS}
        _validate_condition(condition, where, problems, VOCABULARY[entity])

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
            entity=raw_rule.get("entity", PROCESS),
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


#: Finding identifiers say what kind of thing they are about at a glance.
_PREFIX = {"process": "PROC", "module": "KERN", "service": "SVC"}


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
    # Module.
    "loaded": "present in the loaded module list",
    "scanned": "recovered by pool scan",
    "scanned_only": "recovered by pool scan, absent from the loaded module list",
    "unbacked_driver": "driver object whose start address matches no known module",
    "known_exception": "driver upstream recognises as a benign exception",
    "owns_callback": "owns a kernel callback",
    "unresolved_callback": "kernel callback owned by no identifiable module",
    "ssdt_hook": "system-call table entry points outside the kernel",
    "no_disk_path": "loaded module has no backing file path",
    # Service.
    "service_running": "service is running",
    "svcdiff_hidden": "recovered by pool scan but absent from the service "
                      "manager's own list",
    "service_binary_in_user_path": "service binary lives in a user-writable directory",
    "service_no_binary": "service record names no binary",
    "service_host_injected": "the process hosting this service has unbacked "
                             "executable memory",
    "service_host_hidden": "the process hosting this service is hidden from the "
                           "active process list",
}


def evidence_for(signal: str, entity: Entity) -> dict | None:
    """One evidence entry, citing the row that produced the signal."""
    plugin = SIGNAL_SOURCE.get(signal)
    if plugin is None:
        return None

    rows = entity.rows(plugin)
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
        reason = f"{reason} (PPID {getattr(entity, 'ppid', None)})"
    if signal == "service_binary_in_user_path":
        reason = f"{reason}: {getattr(entity, 'binary', None)}"
    if signal in ("service_host_injected", "service_host_hidden"):
        # The evidence lives on the host process, not on the service record.
        reason = f"{reason} (PID {getattr(entity, 'pid', None)})"
        return {"plugin": plugin, "reason": reason, "row": None}

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
        for entity in analysis.entities(rule.entity):
            if not matches(rule.condition, entity.signals):
                continue
            evidence = [
                entry
                for entry in (
                    evidence_for(signal, entity)
                    for signal in sorted(rule.signals() & entity.signals)
                )
                if entry is not None
            ]
            findings.append(
                Finding(
                    finding_id="",
                    rule_id=rule.id,
                    severity=rule.severity,
                    title=rule.title,
                    entity=entity,
                    evidence=evidence,
                    actions=rule.actions,
                )
            )

    findings.sort(
        key=lambda f: (SEVERITIES.index(f.severity), f.entity.kind, f.entity.sort_key)
    )
    # Numbered within each prefix, so PROC-0003 is the third process finding
    # rather than the third finding that happens to be about a process.
    counters: dict[str, int] = {}
    for finding in findings:
        prefix = _PREFIX[finding.entity.kind]
        counters[prefix] = counters.get(prefix, 0) + 1
        finding.finding_id = f"{prefix}-{counters[prefix]:04d}"
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
        "entities_examined": {
            "process": len(analysis.processes),
            "module": len(analysis.modules),
            "service": len(analysis.services),
        },
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
    "entity_type",
    "entity",
    "pid",
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

    (findings_dir / "findings.txt").write_text(
        report(pack, analysis, findings) + "\n", encoding="utf-8"
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
                    finding.entity.kind,
                    finding.entity.label,
                    getattr(finding.entity, "pid", "") or "",
                    "; ".join(e["reason"] for e in finding.evidence),
                    " ".join(finding.actions),
                ]
            )

    return json_path, csv_path


def report(pack: RulePack, analysis: Analysis, findings: list[Finding]) -> str:
    """A findings summary meant to be read rather than parsed.

    findings.csv is a table; this is the paragraph an examiner writes at the top
    of a report. It groups by entity rather than by rule, because the question
    being asked is "what should I look at" and not "which rules fired".
    """
    lines = [
        "FINDINGS",
        "=" * 72,
        f"Rule pack {pack.name} {pack.version} (sha256 {pack.sha256[:12]})",
        f"{len(analysis.processes)} process(es), {len(analysis.modules)} module(s), "
        f"{len(analysis.services)} service(s) examined",
        "",
    ]

    summary = summarise(findings)
    if not findings:
        lines.append("No rules matched.")
    else:
        lines.append(
            "  ".join(f"{summary[s]} {s}" for s in SEVERITIES if summary[s])
        )
    lines.append("")

    grouped: dict[tuple, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault((finding.entity.kind, finding.entity.sort_key), []).append(
            finding
        )

    for group in grouped.values():
        entity = group[0].entity
        worst = min(group, key=lambda f: SEVERITIES.index(f.severity)).severity
        lines.append(f"{entity.label}  [{worst}]")
        for finding in group:
            lines.append(f"    {finding.finding_id}  {finding.title}")
            for item in finding.evidence:
                # A single-signal rule's title already says what the evidence
                # says. Repeating it adds length without adding information.
                if item["reason"].lower().rstrip(".") == finding.title.lower():
                    lines.append(f"        - {item['plugin'].rsplit('.', 1)[-1]}")
                    continue
                plugin = item["plugin"].rsplit(".", 1)[-1]
                lines.append(f"        - {item['reason']}  [{plugin}]")
        actions = sorted({a for f in group for a in f.actions})
        if actions:
            lines.append(f"    next: {', '.join(actions)}")
        lines.append("")

    blocked = not_evaluated(pack, analysis)
    if blocked:
        lines.append("NOT EVALUATED")
        lines.append("-" * 72)
        lines.append(
            "These rules could not run, so their absence from the findings above "
            "means nothing."
        )
        for rule_id, reason in sorted(blocked.items()):
            lines.append(f"  {rule_id}: {reason}")
        lines.append("")

    return "\n".join(lines)
