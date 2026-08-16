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
from .engine import VolEngine
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
    "dump_vads": (Step("windows.vadinfo.VadInfo", extra=("--dump",),
                       requires_dump=True),),
    "dump_module": (Step("windows.modules.Modules", scope="name", extra=("--dump",),
                         requires_dump=True),),
}


@dataclass
class PlannedTask:
    entity: dict
    directory: str
    action: str
    plugin: str
    plugin_args: list[str]
    executed: bool = False
    skipped_reason: str | None = None
    status: str | None = None
    seconds: float | None = None

    def as_dict(self) -> dict:
        return {
            "entity": self.entity,
            "action": self.action,
            "plugin": self.plugin,
            "plugin_args": self.plugin_args,
            "output": f"{self.directory}/{self.plugin}.json",
            "executed": self.executed,
            "reason": self.skipped_reason,
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
        return [t for t in self.tasks if t.skipped_reason is None]

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

        seen: set[tuple[str, tuple[str, ...]]] = set()
        for action in actions:
            for step in ACTIONS.get(action, ()):
                if (step.plugin, step.extra) in seen:
                    continue
                seen.add((step.plugin, step.extra))

                value = scopes.get(step.scope)
                task = PlannedTask(
                    entity=entity,
                    directory=f"followup/{folder}",
                    action=action,
                    plugin=step.plugin,
                    plugin_args=[*step.extra, step.flag, str(value)],
                )
                if value is None:
                    # A service with no running host has no PID to scope by. Say
                    # so rather than running the plugin unscoped over the image.
                    task.plugin_args = []
                    task.skipped_reason = (
                        f"{subject.kind} supplies no {step.scope} to scope by"
                    )
                    unscoped.add(subject.label)
                elif step.requires_dump and not allow_dump:
                    task.skipped_reason = "requires --dump"
                result.tasks.append(task)

    dumps = sum(1 for t in result.tasks if t.skipped_reason == "requires --dump")
    if dumps:
        result.notices.append(
            f"{dumps} dump action(s) planned but not executed. Re-run with "
            "--dump to collect them.\n"
            "  Note: dumped executables may be quarantined by endpoint "
            "protection on this host."
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
