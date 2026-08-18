"""Findings in, targeted Volatility runs out.

A finding says which process deserves attention. This module says what to
collect about it, and — given the image — collects it.

Two constraints shape the action table. Not every plugin accepts ``--pid``:
NetScan and ThrdScan scan the whole image and offer no filter, so network and
thread-scan correlation is done by reading the triage JSON already on disk
rather than by running anything again. And Handles is one of the slow
whole-image scanners, which is most of the argument for re-running at all —
scoped to one PID it returns in seconds, where the triage run took minutes.

Execution reuses ``scheduler.run_tasks`` unchanged: same timeout, same fault
isolation, same discipline of writing child output to files rather than pipes.
This module only builds ``Task`` objects.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import manifest, scheduler
from .engine import VolEngine, render_command
from .rules import SEVERITIES, Finding

SCHEMA_VERSION = 1
FILENAME = "next-steps.json"


@dataclass(frozen=True)
class Step:
    """One Volatility invocation, scoped to an entity.

    ``scope`` names the flag used to narrow the plugin and the value the entity
    must supply for it. A process supplies ``pid``; a kernel module supplies
    ``name``; a service supplies the ``pid`` of the process hosting it, which is
    what turns "this service is odd" into an examination of the thing running
    it. A step whose scope an entity cannot supply is skipped and said so.
    """

    plugin: str
    scope: str = "pid"
    extra: tuple[str, ...] = ()
    requires_dump: bool = False
    #: Emit one invocation per flagged memory region instead of one for the whole
    #: entity: read ``(plugin, column)`` from the entity's rows and pass each
    #: value as ``--address``.
    #:
    #: ``VadInfo --dump --pid N`` writes *every* VAD, which runs to gigabytes on
    #: any substantial process and buries the few pages that mattered. The region
    #: the finding actually cited is usually a handful of pages, and is the thing
    #: an analyst wants to put through YARA or a disassembler.
    per_region: tuple[str, str] | None = None

    @property
    def flag(self) -> str:
        return f"--{self.scope}"


#: Action name -> the steps it expands to. The rule pack is validated against
#: these keys, so a typo in a pack is a load error rather than a silent no-op.
ACTIONS: dict[str, tuple[Step, ...]] = {
    "inspect_vads": (Step("windows.vadinfo.VadInfo"),),
    "inspect_modules": (
        Step("windows.dlllist.DllList"),
        Step("windows.malware.ldrmodules.LdrModules"),
    ),
    "inspect_threads": (Step("windows.malware.suspicious_threads.SuspiciousThreads"),),
    "inspect_context": (
        Step("windows.pstree.PsTree"),
        Step("windows.cmdline.CmdLine"),
        Step("windows.getsids.GetSIDs"),
        Step("windows.privileges.Privs"),
        Step("windows.handles.Handles"),
    ),
    # Kernel. Modules and ModScan take --name as a substring match, so the
    # normalised module key is the right argument.
    "inspect_module": (
        Step("windows.modules.Modules", scope="name"),
        Step("windows.modscan.ModScan", scope="name"),
    ),
    "dump_process": (Step("windows.pslist.PsList", extra=("--dump",),
                          requires_dump=True),),
    # Scoped to the regions malfind flagged. Volatility's --address takes one
    # address and excludes every other range; the CLI parses it with int(x, 0),
    # so the 0x form below is accepted.
    "dump_vads": (Step("windows.vadinfo.VadInfo", extra=("--dump",),
                       requires_dump=True,
                       per_region=("windows.malware.malfind.Malfind", "Start VPN")),),
    "dump_module": (Step("windows.modules.Modules", scope="name", extra=("--dump",),
                         requires_dump=True),),
}

#: Why a dump is described rather than performed. Stated once so the plan, the
#: report and next-steps.json cannot disagree about it.
DUMP_IS_SUGGESTED = (
    "writes live malicious code to this workstation; run it deliberately"
)


def _region_addresses(entity, step: Step) -> list[str]:
    """The regions this step should be scoped to, as ``0x``-prefixed strings.

    Returns ``[None]`` for an ordinary step so callers can loop uniformly. An
    entity whose source plugin produced no usable address falls back to the
    unscoped form rather than emitting nothing — a dump of the whole process is
    still better than silence, and the caller says which it got.
    """
    if step.per_region is None:
        return [None]

    plugin, column = step.per_region
    seen: list[str] = []
    for row in entity.seen_in.get(plugin, []):
        value = row.get(column)
        if value is None or isinstance(value, bool):
            continue
        try:
            address = int(str(value), 0)
        except (TypeError, ValueError):
            continue
        rendered = f"0x{address:x}"
        if rendered not in seen:
            seen.append(rendered)
    return seen or [None]


@dataclass
class PlannedTask:
    entity: dict
    #: The entity's human label, e.g. ``powershell.exe (PID 4180)``. Carried
    #: rather than re-derived: ``as_entity()`` is the machine shape and has no
    #: label, and a report that re-formats it would drift from the console.
    entity_label: str
    directory: str
    action: str
    plugin: str
    plugin_args: list[str]
    executed: bool = False
    skipped_reason: str | None = None
    status: str | None = None
    seconds: float | None = None
    #: Deliberately not run, and handed to the analyst as a command instead.
    #: Distinct from ``skipped_reason``, which means the tool *could* not act.
    #: Conflating the two makes a policy decision read as a coverage gap.
    suggested: bool = False
    suggested_reason: str | None = None
    suggested_command: str | None = None
    #: The memory region this task is scoped to, e.g. ``0x1a2b3c0000``.
    region: str | None = None

    @property
    def state(self) -> str:
        if self.skipped_reason is not None:
            return "skipped"
        if self.suggested:
            return "suggested"
        return "executed" if self.executed else "planned"

    def as_dict(self) -> dict:
        return {
            "entity": self.entity,
            "entity_label": self.entity_label,
            "action": self.action,
            "plugin": self.plugin,
            "plugin_args": self.plugin_args,
            "region": self.region,
            "output": f"{self.directory}/{self.plugin}.json",
            "state": self.state,
            "executed": self.executed,
            "reason": self.skipped_reason or self.suggested_reason,
            "suggested_command": self.suggested_command,
            "status": self.status,
            "seconds": self.seconds,
        }


@dataclass
class Plan:
    tasks: list[PlannedTask] = field(default_factory=list)
    elevated: int = 0
    planned: int = 0
    max_followups: int = 0
    notices: list[str] = field(default_factory=list)

    @property
    def pending(self) -> list[PlannedTask]:
        """Tasks this run will actually execute."""
        return [
            t for t in self.tasks if t.skipped_reason is None and not t.suggested
        ]

    @property
    def suggested(self) -> list[PlannedTask]:
        """Tasks handed to the analyst to run by hand."""
        return [t for t in self.tasks if t.suggested]

    def as_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_utc": manifest.utc_now(),
            "max_followups": self.max_followups,
            "entities_elevated": self.elevated,
            "entities_followed_up": self.planned,
            "tasks": [t.as_dict() for t in self.tasks],
        }


#: Filesystem-safe characters for an entity directory name.
_SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")


def _slug(text: str) -> str:
    cleaned = "".join(c if c in _SAFE else "-" for c in str(text)).strip("-")
    return cleaned[:60] or "unnamed"


def directory_name(entity, *, ambiguous: set) -> str:
    """``PID-4180``, ``KERN-evil``, ``SVC-updatersvc``.

    A PID that names two processes gets its offset appended. PsScan can recover
    two processes that reused a PID; they are separate entities and their
    evidence must not land in one folder.
    """
    if entity.kind == "process":
        if entity.pid in ambiguous and entity.offset is not None:
            return f"PID-{entity.pid}-{entity.offset:x}"
        return f"PID-{entity.pid}"
    prefix = "KERN" if entity.kind == "module" else "SVC"
    return f"{prefix}-{_slug(entity.key)}"


def plan(
    findings: list[Finding],
    *,
    max_followups: int = 10,
    allow_dump: bool = False,
) -> Plan:
    """Turn findings into an ordered, de-duplicated task list.

    Findings are grouped by entity, because two rules firing on one process
    should not collect the same evidence twice. Entities are taken most severe
    first, so a cap truncates the tail rather than an arbitrary slice.
    """
    result = Plan(max_followups=max_followups)

    order: list[tuple] = []
    grouped: dict[tuple, list[Finding]] = {}
    for finding in sorted(
        findings,
        key=lambda f: (
            SEVERITIES.index(f.severity), f.entity.kind, f.entity.sort_key
        ),
    ):
        key = (finding.entity.kind, finding.entity.sort_key)
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(finding)

    result.elevated = len(order)

    pids = [f[0].entity.pid for f in grouped.values()
            if f[0].entity.kind == "process"]
    ambiguous = {pid for pid in pids if pids.count(pid) > 1}

    selected = order[:max_followups]
    result.planned = len(selected)
    if len(order) > len(selected):
        result.notices.append(
            f"{len(order)} entities elevated; following up on the top "
            f"{len(selected)} by severity. Raise with --max-followups {len(order)}."
        )

    unscoped: set[str] = set()

    for key in selected:
        group = grouped[key]
        subject = group[0].entity
        folder = directory_name(subject, ambiguous=ambiguous)
        entity = subject.as_entity()
        scopes = subject.scope_values()

        actions: list[str] = []
        for finding in group:
            for action in finding.actions:
                if action not in actions:
                    actions.append(action)

        seen: set[tuple[str, tuple[str, ...], str | None]] = set()
        for action in actions:
            for step in ACTIONS.get(action, ()):
                for region in _region_addresses(subject, step):
                    if (step.plugin, step.extra, region) in seen:
                        continue
                    seen.add((step.plugin, step.extra, region))

                    value = scopes.get(step.scope)
                    # --address is a plugin option and belongs with --pid, after
                    # the plugin name. Nothing may follow the scope flag: pid is
                    # a ListRequirement and consumes every token after it.
                    args = [*step.extra]
                    if region is not None:
                        args += ["--address", region]
                    args += [step.flag, str(value)]

                    task = PlannedTask(
                        entity=entity,
                        entity_label=subject.label,
                        directory=f"followup/{folder}",
                        action=action,
                        plugin=step.plugin,
                        plugin_args=args,
                        region=region,
                    )
                    if value is None:
                        # A service with no running host has no PID to scope by.
                        # Say so rather than running the plugin unscoped.
                        task.plugin_args = []
                        task.skipped_reason = (
                            f"{subject.kind} supplies no {step.scope} to scope by"
                        )
                        unscoped.add(subject.label)
                    elif step.requires_dump and not allow_dump:
                        task.suggested = True
                        task.suggested_reason = DUMP_IS_SUGGESTED
                    result.tasks.append(task)

    dumps = len(result.suggested)
    if dumps:
        regions = sum(1 for t in result.suggested if t.region)
        detail = f" ({regions} scoped to a specific memory region)" if regions else ""
        result.notices.append(
            f"{dumps} dump(s) suggested but NOT run{detail}. The exact command for "
            "each is in\n  findings.txt and next-steps.json — run them deliberately, "
            "or re-run with --dump.\n"
            "  A dump writes live malicious code to this workstation, and endpoint "
            "protection\n  may quarantine it mid-write."
        )
    if unscoped:
        result.notices.append(
            f"{len(unscoped)} entity(ies) could not be followed up automatically: "
            + ", ".join(sorted(unscoped))
            + "\n  Nothing was run unscoped, which would have re-read the whole "
            "image."
        )

    return result


def build_tasks(
    plan_: Plan,
    *,
    image: Path,
    output_dir: Path,
    engine: VolEngine,
    symbols_dir: Path,
    cache_dir: Path,
    pagefiles: list[Path] | None = None,
) -> list[scheduler.Task]:
    tasks: list[scheduler.Task] = []
    for index, planned in enumerate(plan_.pending):
        target = output_dir / planned.directory
        tasks.append(
            scheduler.Task(
                key=f"{index}:{planned.directory}:{planned.plugin}",
                label=f"{planned.plugin} ({planned.directory})",
                command=engine.command(
                    image,
                    planned.plugin,
                    "json",
                    symbols_dir=symbols_dir,
                    cache_dir=cache_dir,
                    swap_files=pagefiles,
                    output_dir=target,
                    plugin_args=planned.plugin_args,
                ),
                stdout_path=target / f"{planned.plugin}.json",
                stderr_path=target / "logs" / f"{planned.plugin}.log",
            )
        )
    return tasks


#: Stands in for the image path when ``analyze`` was run without ``--image``.
#: The rest of the command is still exact, so filling this in is the only edit.
IMAGE_PLACEHOLDER = "<image>"


def render_suggestions(
    plan_: Plan,
    *,
    output_dir: Path,
    engine: VolEngine,
    symbols_dir: Path,
    cache_dir: Path,
    image: Path | None = None,
    pagefiles: list[Path] | None = None,
) -> None:
    """Fill in the command an analyst should run for each suggested task.

    Built with ``engine.command`` — the same call ``build_tasks`` makes — so the
    suggestion is by construction the command this tool would have run. Writing
    the string by hand would let it drift from the real argv, and ``engine.py``
    already carries two ordering hazards that make drift expensive: ``-o`` must
    precede the plugin name, and the scope flag must come last because ``pid``
    is a ListRequirement that swallows everything after it.
    """
    for task in plan_.suggested:
        target = output_dir / task.directory
        # Volatility refuses to start when -o names a directory that is not
        # there ("The output directory specified does not exist"), and a
        # suggested task never ran, so nothing has created it. Without this the
        # command fails the moment it is pasted — which is the one thing a
        # copy-pasteable command must not do. An empty directory is also honest:
        # it marks where that evidence belongs.
        try:
            target.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

        argv = engine.command(
            Path(IMAGE_PLACEHOLDER) if image is None else image,
            task.plugin,
            "json",
            symbols_dir=symbols_dir,
            cache_dir=cache_dir,
            swap_files=pagefiles,
            output_dir=target,
            plugin_args=task.plugin_args,
        )
        task.suggested_command = render_command(argv)


def record_results(plan_: Plan, results: list[scheduler.TaskResult]) -> None:
    """Fold execution outcomes back into the plan, so one document describes both."""
    for planned, result in zip(plan_.pending, results):
        planned.executed = True
        planned.status = result.status
        planned.seconds = round(result.duration, 2)


def write(findings_dir: Path, plan_: Plan) -> Path:
    findings_dir.mkdir(parents=True, exist_ok=True)
    path = findings_dir / FILENAME
    path.write_text(json.dumps(plan_.as_dict(), indent=2) + "\n", encoding="utf-8")
    return path
