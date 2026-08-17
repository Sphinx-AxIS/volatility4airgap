"""Plugin JSON in, correlated entities out.

Triage writes one file per plugin. An analyst reading those files does the
correlation in their head: this PID in malfind is that PID in netscan is that
PID in pstree. This module does it on paper instead, producing one record per
entity that carries every row any plugin reported about it.

Three entity types, because the questions differ. A *process* is the spine of
most investigations. A *module* covers the kernel surface — loaded drivers,
callbacks, SSDT entries — where the equivalent of a hidden process is a module
missing from the loaded list. A *service* sits between the two: it names a
binary, and it names the process hosting it, which is what lets a finding run
from "this service is odd" to "and its host process has injected code in it".

Two things make correlation harder than it sounds.

Column names are not stable. ``PID`` in ten plugins is ``Pid`` in LdrModules.
The process name is ``ImageFileName`` in PsList, ``Process`` in Malfind,
``Name`` in PsXView and ``Owner`` in NetScan. Exit time is ``ExitTime`` in
PsScan and ``Exit Time`` in PsXView. Some names are not fixed even within one
plugin: PsScan builds its offset column as ``f"Offset{offsettype}"``, so it is
``Offset(V)`` or ``Offset(P)`` depending on how the scan ran. Every plugin
therefore gets an explicit extractor entry rather than a guess.

And a column name repeating across plugins does not mean it means the same
thing. NetScan has an ``Offset``, but it is the offset of the connection
object, not of the process — using it to identify a process would silently
merge unrelated entities. Only the three process-listing plugins contribute a
process offset.

Nothing is dropped in silence. A plugin whose columns do not match its
extractor is reported by name and counted, because a skipped plugin becomes a
false negative and a false negative is the expensive kind of wrong here.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

#: Values Volatility uses for "this column does not apply here".
_ABSENT = {None, "", "N/A", "-", "Disabled", "UNKNOWN", "Unknown"}

_UTC = datetime.timezone.utc


def _as_time(value) -> datetime.datetime | None:
    """Parse a Volatility timestamp, or ``None`` if it is not one.

    Renderers emit either ``2026-07-30T22:05:28+00:00`` or the same with a space
    separator, and occasionally a trailing ``Z``. A naive result is treated as
    UTC so two timestamps can always be compared: mixing naive and aware values
    raises rather than returning a wrong answer, and a raise here would take out
    the whole analysis for one odd row.
    """
    if not _present(value):
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_UTC)

PROCESS = "process"
MODULE = "module"
SERVICE = "service"

#: Stands in for a callback or SSDT owner that could not be identified. It is
#: not a module name — nothing can be filtered by it, so it supplies no scope.
UNRESOLVED = "<unresolved>"


@dataclass(frozen=True)
class Extractor:
    """How to find an entity in one plugin's rows."""

    plugin: str
    entity: str = PROCESS
    #: Column holding the entity's identity: a PID, a module name, a service name.
    key: str = "PID"
    #: Fallback identity column, used when ``key`` is absent from the row.
    alt_key: str | None = None
    name: str | None = None
    ppid: str | None = None
    #: Only set where the offset identifies the *entity*. See the module note.
    offset_prefix: str | None = None
    #: PsTree emits a hierarchy; every other plugin emits a flat list.
    nested: bool = False


EXTRACTORS: tuple[Extractor, ...] = (
    # Processes.
    Extractor("windows.pslist.PsList", PROCESS, "PID",
              name="ImageFileName", ppid="PPID", offset_prefix="Offset"),
    Extractor("windows.psscan.PsScan", PROCESS, "PID",
              name="ImageFileName", ppid="PPID", offset_prefix="Offset"),
    Extractor("windows.pstree.PsTree", PROCESS, "PID",
              name="ImageFileName", ppid="PPID", offset_prefix="Offset", nested=True),
    Extractor("windows.cmdline.CmdLine", PROCESS, "PID", name="Process"),
    # Both are in the triage set and were previously collected but never read,
    # so the session and user a process ran as never reached an entity. Sessions
    # keys on "Process ID" rather than "PID"; every other process plugin uses
    # "PID", which is exactly the kind of drift the extractor table exists for.
    Extractor("windows.sessions.Sessions", PROCESS, "Process ID", name="Process"),
    Extractor("windows.getsids.GetSIDs", PROCESS, "PID", name="Process"),
    Extractor("windows.netscan.NetScan", PROCESS, "PID", name="Owner"),
    Extractor("windows.netstat.NetStat", PROCESS, "PID", name="Owner"),
    Extractor("windows.malware.malfind.Malfind", PROCESS, "PID", name="Process"),
    Extractor("windows.malware.hollowprocesses.HollowProcesses", PROCESS, "PID",
              name="Process"),
    Extractor("windows.malware.processghosting.ProcessGhosting", PROCESS, "PID",
              name="Process"),
    Extractor("windows.malware.psxview.PsXView", PROCESS, "PID", name="Name"),
    Extractor("windows.malware.ldrmodules.LdrModules", PROCESS, "Pid", name="Process"),
    Extractor("windows.malware.suspicious_threads.SuspiciousThreads", PROCESS, "PID",
              name="Process"),
    Extractor("windows.malware.pebmasquerade.PebMasquerade", PROCESS, "PID",
              name="EPROCESS_ImageFileName"),
    # Kernel modules and drivers.
    Extractor("windows.modules.Modules", MODULE, "Name", name="Name"),
    Extractor("windows.modscan.ModScan", MODULE, "Name", name="Name"),
    Extractor("windows.driverscan.DriverScan", MODULE, "Driver Name",
              alt_key="Name", name="Driver Name"),
    Extractor("windows.malware.drivermodule.DriverModule", MODULE, "Driver Name",
              alt_key="Alternative Name", name="Driver Name"),
    Extractor("windows.callbacks.Callbacks", MODULE, "Module", name="Module"),
    Extractor("windows.ssdt.SSDT", MODULE, "Module", name="Module"),
    # Services.
    Extractor("windows.svcscan.SvcScan", SERVICE, "Name", name="Name"),
    Extractor("windows.malware.svcdiff.SvcDiff", SERVICE, "Name", name="Name"),
)

BY_PLUGIN = {e.plugin: e for e in EXTRACTORS}


@dataclass
class Notice:
    """Something the analyst needs to know, and what to do about it."""

    level: str  # error | warning | info
    message: str

    def __str__(self) -> str:
        return self.message


class Entity:
    """Shared behaviour. Not a dataclass, so subclasses may declare required fields.

    Python 3.9 has no ``kw_only``, so a dataclass base with defaulted fields
    would forbid a subclass field without one — and ``Process.pid`` must not
    have a default.
    """

    kind: str = ""
    seen_in: dict
    signals: set

    def rows(self, plugin: str) -> list[dict]:
        return self.seen_in.get(plugin, [])

    @property
    def label(self) -> str:
        raise NotImplementedError

    @property
    def sort_key(self) -> tuple:
        raise NotImplementedError

    def scope_values(self) -> dict[str, str]:
        """How a follow-up plugin can be pointed at this entity."""
        return {}

    def as_entity(self) -> dict:
        raise NotImplementedError


@dataclass
class Process(Entity):
    pid: int
    offset: int | None = None
    #: The column the offset came from, e.g. ``Offset(V)``. Two offsets are only
    #: comparable when their kinds agree — see ``build_entities``.
    offset_kind: str | None = None
    name: str | None = None
    ppid: int | None = None
    seen_in: dict[str, list[dict]] = field(default_factory=dict)
    signals: set[str] = field(default_factory=set)

    # Derived once from the rows above, by ``populate_details``. Held as fields
    # rather than re-read per signal because several signals want the same value
    # and each derivation has a wrinkle worth doing only once.
    command_line: str | None = None
    #: The kernel's own record of the image, from PebMasquerade's
    #: EPROCESS_SeAudit_ImageFileName. Deliberately not the PEB path: the PEB is
    #: writable by the process, which is the whole point of that plugin.
    image_path: str | None = None
    session_id: int | None = None
    user_name: str | None = None
    #: The process's own SID, not every SID in its token.
    user_sid: str | None = None
    #: Filled in by ``link_processes`` once every process exists.
    parent_name: str | None = None

    kind = PROCESS

    @property
    def key(self) -> tuple[int, int | None]:
        return (self.pid, self.offset)

    @property
    def started_at(self) -> "datetime.datetime | None":
        """Creation time, from whichever listing recorded one.

        Used to reject a PPID that resolves to a process younger than its
        supposed child — the signature of a reused PID rather than a parent.
        """
        for plugin in ("windows.pslist.PsList", "windows.psscan.PsScan",
                       "windows.pstree.PsTree"):
            for row in self.rows(plugin):
                parsed = _as_time(row.get("CreateTime"))
                if parsed is not None:
                    return parsed
        return None

    @property
    def label(self) -> str:
        return f"{self.name or 'unknown'} (PID {self.pid})"

    @property
    def sort_key(self) -> tuple:
        return (self.pid, self.offset or 0)

    def scope_values(self) -> dict[str, str]:
        return {"pid": str(self.pid)}

    def as_entity(self) -> dict:
        return {
            "type": PROCESS,
            "pid": self.pid,
            "offset": self.offset,
            "name": self.name,
            "ppid": self.ppid,
        }


@dataclass
class Module(Entity):
    """A kernel module or driver, keyed by normalised name.

    ``\\Driver\\foo`` from DriverScan and ``foo.sys`` from Modules are the same
    thing under most rootkit techniques, so both normalise to ``foo``. Where a
    driver's name genuinely differs from its module's, they stay separate —
    which is right: merging them would invent a relationship.
    """

    key: str
    name: str | None = None
    #: Case-preserving stem for Volatility's --name filter. See scope_values.
    scope_name: str | None = None
    seen_in: dict[str, list[dict]] = field(default_factory=dict)
    signals: set[str] = field(default_factory=set)

    kind = MODULE

    @property
    def label(self) -> str:
        return self.name or self.key

    @property
    def sort_key(self) -> tuple:
        return (self.key,)

    def scope_values(self) -> dict[str, str]:
        """The argument for ``--name``, which is **not** the correlation key.

        Modules filters with ``self.config["name"] not in BaseDllName`` — a
        case-sensitive Python substring test, inherited by ModScan. Passing the
        lowercased key would mean ``--name wdf01000`` never matches a
        ``Wdf01000.sys`` the analyst can see in the triage output, and the
        follow-up folder would come back empty with no error to explain it.

        ``scope_name`` therefore preserves the case of the source, preferring
        the BaseDllName that Modules and ModScan report because that is the
        exact string the filter compares against.

        A placeholder key supplies nothing. ``<unresolved>`` stands for a
        callback or SSDT entry whose owning module could not be identified —
        there is no such module name to filter on, and passing the placeholder
        through sent Modules and ModScan to search a 25 GB image for a driver
        literally called "<unresolved>", taking fifteen minutes to return
        nothing. Returning no scope routes it to the path that already exists
        for this: the step is skipped and the reason is reported.
        """
        if self.key == UNRESOLVED:
            return {}
        return {"name": self.scope_name or self.key}

    def as_entity(self) -> dict:
        return {
            "type": MODULE,
            "key": self.key,
            "name": self.name,
            "scope_name": self.scope_name,
        }


@dataclass
class Service(Entity):
    key: str
    name: str | None = None
    pid: int | None = None
    binary: str | None = None
    seen_in: dict[str, list[dict]] = field(default_factory=dict)
    signals: set[str] = field(default_factory=set)

    kind = SERVICE

    @property
    def label(self) -> str:
        host = f" (PID {self.pid})" if self.pid else ""
        return f"{self.name or self.key}{host}"

    @property
    def sort_key(self) -> tuple:
        return (self.key,)

    def scope_values(self) -> dict[str, str]:
        return {"pid": str(self.pid)} if self.pid else {}

    def as_entity(self) -> dict:
        return {
            "type": SERVICE,
            "key": self.key,
            "name": self.name,
            "pid": self.pid,
            "binary": self.binary,
        }


@dataclass
class Analysis:
    processes: list[Process] = field(default_factory=list)
    modules: list[Module] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    #: Plugins whose JSON was read, mapped to their row count.
    plugins_read: dict[str, int] = field(default_factory=dict)
    #: Plugins the run should have had but does not, mapped to why.
    plugins_missing: dict[str, str] = field(default_factory=dict)
    notices: list[Notice] = field(default_factory=list)

    def note(self, level: str, message: str) -> None:
        self.notices.append(Notice(level, message))

    def by_pid(self, pid: int) -> list[Process]:
        return [p for p in self.processes if p.pid == pid]

    # ---- process graph ----------------------------------------------------
    #
    # Windows reuses PIDs, so a PPID may name a process that has nothing to do
    # with the child: the real parent exited and something else inherited the
    # number. Every walk below therefore goes through ``parent``, which refuses
    # a candidate that started after its supposed child, and bounds itself
    # against a cycle formed by reuse.

    #: Deep enough for any real chain; short enough that a cycle cannot hang.
    MAX_ANCESTRY_DEPTH: ClassVar[int] = 32

    def parent(self, process: Process) -> Process | None:
        """The one process that plausibly launched ``process``.

        ``None`` when the parent has exited (the usual case for csrss, wininit
        and winlogon, whose smss is long gone), when the PPID resolves to
        several candidates that cannot be told apart, or when the only candidate
        started after the child and so cannot be its parent.
        """
        if process.ppid is None or process.ppid == process.pid:
            return None

        candidates = self.by_pid(process.ppid)
        if not candidates:
            return None

        child_start = process.started_at
        plausible = [
            candidate
            for candidate in candidates
            if not (
                child_start is not None
                and candidate.started_at is not None
                and candidate.started_at > child_start
            )
        ]
        if len(plausible) != 1:
            # Zero: the PID was reused by something younger than the child.
            # More than one: genuinely ambiguous, and guessing would attribute
            # a chain to the wrong process — worse than reporting nothing.
            return None
        return plausible[0]

    def children(self, process: Process) -> list[Process]:
        return [p for p in self.processes if self.parent(p) is process]

    def ancestors(self, process: Process) -> list[Process]:
        """Parent first, then grandparent, and so on. Never repeats a process."""
        chain: list[Process] = []
        seen = {id(process)}
        current = process
        for _ in range(self.MAX_ANCESTRY_DEPTH):
            current = self.parent(current)
            if current is None or id(current) in seen:
                break
            seen.add(id(current))
            chain.append(current)
        return chain

    def descendants(self, process: Process) -> list[Process]:
        found: list[Process] = []
        seen = {id(process)}
        queue = [process]
        while queue:
            current = queue.pop()
            for child in self.children(current):
                if id(child) in seen:
                    continue
                seen.add(id(child))
                found.append(child)
                queue.append(child)
        return found

    def has_ancestor(self, process: Process, names: frozenset[str]) -> Process | None:
        """The nearest ancestor whose image name is in ``names``.

        Returned rather than a bool so a finding can name the process it means,
        which is the difference between "Office-spawned shell" and evidence.
        """
        for ancestor in self.ancestors(process):
            if (ancestor.name or "").lower() in names:
                return ancestor
        return None

    def entities(self, kind: str) -> list:
        return {
            PROCESS: self.processes, MODULE: self.modules, SERVICE: self.services
        }[kind]

    @property
    def all_entities(self) -> list:
        return [*self.processes, *self.modules, *self.services]


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------


@dataclass
class InputCheck:
    """Whether the plugin JSON still matches what triage attested to.

    ``run-manifest.json`` records a SHA-256 for every file a run produced,
    precisely so a downstream consumer can prove nothing changed in transit.
    Reading those files without checking wastes that guarantee: the analysis
    manifest would then attest to findings derived from bytes nobody verified.
    """

    verified: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    unattested: list[str] = field(default_factory=list)
    manifest_absent: bool = False

    @property
    def ok(self) -> bool:
        return not self.modified and not self.unattested

    def as_dict(self) -> dict:
        return {
            "manifest_present": not self.manifest_absent,
            "verified": len(self.verified),
            "modified": sorted(self.modified),
            "unattested": sorted(self.unattested),
        }


def verify_inputs(output_dir: Path) -> InputCheck:
    """Check every plugin JSON we are about to read against the run manifest.

    Only the files this analysis consumes are checked. Logs and other outputs
    are hashed in the manifest too, but a changed log does not change a finding.
    """
    from . import manifest as manifest_mod

    check = InputCheck()
    manifest_path = output_dir / manifest_mod.FILENAME
    if not manifest_path.is_file():
        check.manifest_absent = True
        return check

    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = {
            entry["file"]: entry["sha256"]
            for entry in document.get("outputs", [])
            if entry.get("sha256")
        }
    except (OSError, ValueError, KeyError, TypeError):
        check.manifest_absent = True
        return check

    if not expected:
        check.manifest_absent = True
        return check

    for extractor in EXTRACTORS:
        path = output_json_path(output_dir, extractor.plugin)
        if not path.is_file():
            continue
        relative = path.relative_to(output_dir).as_posix()
        recorded = expected.get(relative)
        if recorded is None:
            # Present but never attested: added or replaced since the run.
            check.unattested.append(relative)
        elif manifest_mod.sha256_file(path) == recorded:
            check.verified.append(relative)
        else:
            check.modified.append(relative)

    return check


def output_json_path(output_dir: Path, plugin: str) -> Path:
    safe = plugin.replace("/", "_").replace("\\", "_")
    return output_dir / f"{safe}.json"


def load_rows(path: Path) -> list[dict]:
    """Read one plugin's JSON.

    The renderer writes a leading newline before the document, which
    ``json.loads`` tolerates. An empty file means the plugin produced nothing —
    not an error here, because triage already recorded why.
    """
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("expected a JSON array of rows")
    return data


def iter_rows(rows: list[dict], *, nested: bool) -> list[dict]:
    """Flatten a plugin's rows, walking ``__children`` where the grid nests.

    PsTree is the only plugin in the triage set that emits a hierarchy, and its
    depth is bounded by the process tree, so recursion is safe. The children key
    is stripped from what is stored: keeping it would nest an entire subtree
    inside every finding that cites a PsTree row.
    """
    flat: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        children = row.get("__children") or []
        flat.append({k: v for k, v in row.items() if k != "__children"})
        if nested and children:
            flat.extend(iter_rows(children, nested=True))
    return flat


def _first_column(row: dict, prefix: str) -> str | None:
    """PsScan's offset column is ``Offset(V)`` or ``Offset(P)``; match by prefix."""
    for key in row:
        if key.startswith(prefix):
            return key
    return None


def _as_int(value) -> int | None:
    if isinstance(value, bool) or value in _ABSENT:
        return None
    if isinstance(value, int):
        return value
    try:
        text = str(value).strip()
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except (TypeError, ValueError):
        return None


def _present(value) -> bool:
    return value not in _ABSENT and value is not None


#: Plugins whose name column is the module's BaseDllName, which is what
#: Modules and ModScan compare ``--name`` against.
_BASE_DLL_NAME_SOURCES = ("windows.modules.Modules", "windows.modscan.ModScan")


def module_stem(name) -> str | None:
    """The name with its path and extension removed, case intact."""
    if not _present(name):
        return None
    text = str(name).strip().replace("/", "\\")
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    for suffix in (".sys", ".exe", ".dll"):
        if text.lower().endswith(suffix):
            text = text[: -len(suffix)]
            break
    return text or None


def normalise_module(name) -> str | None:
    """``\\Driver\\foo``, ``foo.sys`` and ``FOO.SYS`` are one module.

    Rootkits register drivers from hidden modules, so the driver object and the
    module usually share a stem even when the decorations differ. Normalising
    to that stem is what lets DriverModule's verdict land on the same entity
    that ModScan recovered.
    """
    stem = module_stem(name)
    return stem.lower() if stem else None


# --------------------------------------------------------------------------
# Entity construction
# --------------------------------------------------------------------------


def _build_processes(
    rows_by_plugin: dict[str, list[dict]], analysis: Analysis
) -> list[Process]:
    """Fold every plugin's rows into one record per process.

    Keyed by PID *and* offset. PsScan can recover two distinct processes that
    reused a PID; merging them would destroy the evidence that there were two.
    Plugins that report no offset attach to the entity already holding that PID,
    or create an offset-less one if this is the first sighting.

    Offsets are only comparable when they came from the same kind of column.
    PsList, PsScan and PsTree all default to ``physical=False`` and so emit
    ``Offset(V)``, but ``--physical`` makes one of them emit ``Offset(P)`` for
    the same process — a different number entirely. Splitting on that would give
    every process two entities and make ``psscan_only`` fire on all of them.
    Where the kinds disagree the offset is ignored and the row attaches by PID.
    """
    entities: dict[tuple[int, int | None], Process] = {}

    def by_pid(pid: int) -> list[Process]:
        return [p for (p_pid, _), p in entities.items() if p_pid == pid]

    def attach(pid: int, offset: int | None, kind: str | None) -> Process:
        if offset is not None:
            if (pid, offset) in entities:
                return entities[(pid, offset)]
            # A different offset for a known PID means either genuine PID reuse
            # or an incomparable offset kind. Only the former is a new entity.
            mismatched = [
                p for p in by_pid(pid)
                if p.offset_kind is not None and p.offset_kind != kind
            ]
            if mismatched:
                return mismatched[0]

        if offset is None:
            existing = by_pid(pid)
            if existing:
                return existing[0]

        return entities.setdefault(
            (pid, offset), Process(pid=pid, offset=offset, offset_kind=kind)
        )

    discarded: list[str] = []

    # Offset-bearing plugins run first, so later offset-less rows attach to a
    # fully identified entity rather than creating a shadow of it.
    plugins = [p for p in rows_by_plugin if BY_PLUGIN[p].entity == PROCESS]
    for plugin in sorted(plugins, key=lambda n: BY_PLUGIN[n].offset_prefix is None):
        extractor = BY_PLUGIN[plugin]
        recognised = 0
        for row in rows_by_plugin[plugin]:
            pid = _as_int(row.get(extractor.key))
            if pid is None:
                continue
            reason = implausible_process(row)
            if reason is not None:
                # Counted and reported below, never dropped in silence: a real
                # process discarded here would be a false negative.
                discarded.append(f"PID {pid} from {plugin.rsplit('.', 1)[-1]} ({reason})")
                continue
            recognised += 1

            offset, offset_kind = None, None
            if extractor.offset_prefix:
                offset_kind = _first_column(row, extractor.offset_prefix)
                offset = _as_int(row.get(offset_kind)) if offset_kind else None

            process = attach(pid, offset, offset_kind)
            process.seen_in.setdefault(plugin, []).append(row)

            if process.name is None and extractor.name:
                value = row.get(extractor.name)
                process.name = str(value) if _present(value) else None
            if process.ppid is None and extractor.ppid:
                process.ppid = _as_int(row.get(extractor.ppid))

        _report_drift(plugin, extractor, rows_by_plugin[plugin], recognised, analysis)

    if discarded:
        shown = "; ".join(discarded[:5])
        more = f" (and {len(discarded) - 5} more)" if len(discarded) > 5 else ""
        analysis.note(
            "info",
            f"Discarded {len(discarded)} pool-scan hit(s) that cannot describe a "
            f"real process: {shown}{more}.\n"
            "  These are coincidental matches on the _EPROCESS signature. Left in "
            "place they read as hidden processes and send follow-up plugins "
            "searching the image for something that was never there.",
        )

    return sorted(entities.values(), key=lambda p: p.sort_key)


def _build_modules(
    rows_by_plugin: dict[str, list[dict]], analysis: Analysis
) -> list[Module]:
    entities: dict[str, Module] = {}

    for plugin in (p for p in rows_by_plugin if BY_PLUGIN[p].entity == MODULE):
        extractor = BY_PLUGIN[plugin]
        recognised = 0
        for row in rows_by_plugin[plugin]:
            raw = row.get(extractor.key)
            if not _present(raw) and extractor.alt_key:
                raw = row.get(extractor.alt_key)

            # A callback or SSDT entry whose owning module cannot be resolved is
            # exactly the interesting case, so it becomes an entity of its own
            # rather than being discarded for having no name.
            key = normalise_module(raw)
            if key is None:
                if plugin not in ("windows.callbacks.Callbacks", "windows.ssdt.SSDT"):
                    continue
                key = UNRESOLVED
            recognised += 1

            module = entities.setdefault(key, Module(key=key))
            module.seen_in.setdefault(plugin, []).append(row)
            if module.name is None and _present(raw):
                module.name = str(raw)

            # A BaseDllName always wins, even if a driver object named this
            # module first: it is the only string --name is actually compared
            # against.
            authoritative = plugin in _BASE_DLL_NAME_SOURCES
            if module.scope_name is None or authoritative:
                stem = module_stem(raw)
                if stem and (authoritative or module.scope_name is None):
                    module.scope_name = stem

        _report_drift(plugin, extractor, rows_by_plugin[plugin], recognised, analysis)

    return sorted(entities.values(), key=lambda m: m.sort_key)


def _build_services(
    rows_by_plugin: dict[str, list[dict]], analysis: Analysis
) -> list[Service]:
    entities: dict[str, Service] = {}

    for plugin in (p for p in rows_by_plugin if BY_PLUGIN[p].entity == SERVICE):
        extractor = BY_PLUGIN[plugin]
        recognised = 0
        for row in rows_by_plugin[plugin]:
            raw = row.get(extractor.key)
            if not _present(raw):
                continue
            recognised += 1

            key = str(raw).strip().lower()
            service = entities.setdefault(key, Service(key=key))
            service.seen_in.setdefault(plugin, []).append(row)

            if service.name is None:
                service.name = str(raw)
            if service.pid is None:
                service.pid = _as_int(row.get("PID")) or None
            if service.binary is None:
                for column in ("Binary", "Binary (Registry)"):
                    if _present(row.get(column)):
                        service.binary = str(row[column])
                        break

        _report_drift(plugin, extractor, rows_by_plugin[plugin], recognised, analysis)

    return sorted(entities.values(), key=lambda s: s.sort_key)


def _report_drift(
    plugin: str, extractor: Extractor, rows: list[dict], recognised: int,
    analysis: Analysis,
) -> None:
    if rows and recognised == 0:
        analysis.note(
            "warning",
            f"{plugin} has no recognised {extractor.key} column "
            f"(volatility version drift?). Its {len(rows)} row(s) were skipped.",
        )


#: A path Volatility reports device-relative, e.g.
#: ``\Device\HarddiskVolume5\Windows\System32\lsass.exe``. The volume prefix
#: varies by host and says nothing useful, so comparisons use what follows it.
_DEVICE_PREFIX = re.compile(r"^\\device\\harddiskvolume\d+", re.I)


def normalise_path(value) -> str | None:
    """Lowercase, backslash-separated, with any device prefix removed."""
    if not _present(value):
        return None
    text = str(value).strip().replace("/", "\\").lower()
    text = _DEVICE_PREFIX.sub("", text)
    return text or None


def _derive_details(process: Process) -> None:
    """Lift the fields several signals share out of the raw rows, once."""
    for row in process.rows("windows.cmdline.CmdLine"):
        if _present(row.get("Args")):
            process.command_line = str(row["Args"]).strip()
            break

    # The kernel's own record, not the PEB: PebMasquerade exists because a
    # process can rewrite its PEB path, so trusting that field here would
    # believe exactly the lie the plugin was written to expose.
    for row in process.rows("windows.malware.pebmasquerade.PebMasquerade"):
        path = normalise_path(row.get("EPROCESS_SeAudit_ImageFileName"))
        if path:
            process.image_path = path
            break

    for row in process.rows("windows.sessions.Sessions"):
        session = _as_int(row.get("Session ID"))
        if session is not None:
            process.session_id = session
        if _present(row.get("User Name")):
            process.user_name = str(row["User Name"]).strip()
        if process.session_id is not None:
            break

    # GetSIDs lists every SID in the token; the process's own is the one whose
    # name matches the account, and the first row is it in practice. Taking them
    # all would make "the user" mean "any group it belongs to".
    for row in process.rows("windows.getsids.GetSIDs"):
        if _present(row.get("SID")):
            process.user_sid = str(row["SID"]).strip()
            break


def link_processes(analysis: Analysis) -> None:
    """Resolve each process's parent name, once every process exists."""
    for process in analysis.processes:
        parent = analysis.parent(process)
        if parent is not None:
            process.parent_name = parent.name


def build_entities(rows_by_plugin: dict[str, list[dict]], analysis: Analysis) -> None:
    analysis.processes = _build_processes(rows_by_plugin, analysis)
    analysis.modules = _build_modules(rows_by_plugin, analysis)
    analysis.services = _build_services(rows_by_plugin, analysis)

    for process in analysis.processes:
        _derive_details(process)
    link_processes(analysis)


# --------------------------------------------------------------------------
# Signals
# --------------------------------------------------------------------------

#: The closed vocabulary, per entity type. A rule may reference nothing outside
#: the set belonging to the entity it applies to.
VOCABULARY: dict[str, frozenset[str]] = {
    PROCESS: frozenset(
        {
            "pslist", "psscan", "psscan_only", "exited", "malfind", "hollow",
            "ghosted", "peb_masquerade", "psxview_hidden", "suspicious_thread",
            "ldrmodules_unlinked", "network", "network_external", "unusual_parent",
            # Image and context.
            "system_process_wrong_path", "user_writable_image",
            "system_process_wrong_session", "system_process_wrong_user",
            # Command line.
            "encoded_command", "suspicious_command_line",
            # Lineage.
            "lolbin_proxy_parent", "office_spawned_shell",
            "browser_spawned_shell", "script_engine_spawned_lolbin",
            "wmi_spawned_process",
        }
    ),
    MODULE: frozenset(
        {
            "loaded", "scanned", "scanned_only", "unbacked_driver",
            "known_exception", "owns_callback", "unresolved_callback",
            "ssdt_hook", "no_disk_path",
        }
    ),
    SERVICE: frozenset(
        {
            "service_running", "svcdiff_hidden", "service_binary_in_user_path",
            "service_no_binary", "service_host_injected", "service_host_hidden",
        }
    ),
}

ALL_SIGNALS: frozenset[str] = frozenset().union(*VOCABULARY.values())

#: Which plugin each signal needs. Used to report rules that could not be
#: evaluated rather than letting an absent plugin read as an absent finding.
SIGNAL_SOURCE: dict[str, str] = {
    # Process.
    "pslist": "windows.pslist.PsList",
    "psscan": "windows.psscan.PsScan",
    "psscan_only": "windows.psscan.PsScan",
    "exited": "windows.psscan.PsScan",
    "malfind": "windows.malware.malfind.Malfind",
    "hollow": "windows.malware.hollowprocesses.HollowProcesses",
    "ghosted": "windows.malware.processghosting.ProcessGhosting",
    "peb_masquerade": "windows.malware.pebmasquerade.PebMasquerade",
    "psxview_hidden": "windows.malware.psxview.PsXView",
    "suspicious_thread": "windows.malware.suspicious_threads.SuspiciousThreads",
    "ldrmodules_unlinked": "windows.malware.ldrmodules.LdrModules",
    "network": "windows.netscan.NetScan",
    "network_external": "windows.netscan.NetScan",
    "unusual_parent": "windows.pslist.PsList",
    "system_process_wrong_path": "windows.malware.pebmasquerade.PebMasquerade",
    "user_writable_image": "windows.malware.pebmasquerade.PebMasquerade",
    "system_process_wrong_session": "windows.sessions.Sessions",
    "system_process_wrong_user": "windows.sessions.Sessions",
    "encoded_command": "windows.cmdline.CmdLine",
    "suspicious_command_line": "windows.cmdline.CmdLine",
    "lolbin_proxy_parent": "windows.pslist.PsList",
    "office_spawned_shell": "windows.pslist.PsList",
    "browser_spawned_shell": "windows.pslist.PsList",
    "script_engine_spawned_lolbin": "windows.pslist.PsList",
    "wmi_spawned_process": "windows.pslist.PsList",
    # Module.
    "loaded": "windows.modules.Modules",
    "scanned": "windows.modscan.ModScan",
    "scanned_only": "windows.modscan.ModScan",
    "unbacked_driver": "windows.malware.drivermodule.DriverModule",
    "known_exception": "windows.malware.drivermodule.DriverModule",
    "owns_callback": "windows.callbacks.Callbacks",
    "unresolved_callback": "windows.callbacks.Callbacks",
    "ssdt_hook": "windows.ssdt.SSDT",
    "no_disk_path": "windows.modules.Modules",
    # Service.
    "service_running": "windows.svcscan.SvcScan",
    "svcdiff_hidden": "windows.malware.svcdiff.SvcDiff",
    "service_binary_in_user_path": "windows.svcscan.SvcScan",
    "service_no_binary": "windows.svcscan.SvcScan",
    "service_host_injected": "windows.malware.malfind.Malfind",
    "service_host_hidden": "windows.malware.psxview.PsXView",
}

#: Processes whose parent is fixed by Windows itself. Deliberately short: a
#: broad table of "expected" parents produces false positives on every unusual
#: but legitimate application, and the value here is in the few relationships
#: that malware is known to break.
EXPECTED_PARENT: dict[str, frozenset[str]] = {
    # The master smss is a child of System. It then spawns one instance of
    # itself per new session, which initialises that session — creating its
    # csrss and winlogon — and exits immediately. smss parented by smss is
    # therefore normal, and allowing only "system" here fired on every session
    # ever created on the host: two on a real capture, both already exited.
    "smss.exe": frozenset({"system", "smss.exe"}),
    "csrss.exe": frozenset({"smss.exe"}),
    "wininit.exe": frozenset({"smss.exe"}),
    "winlogon.exe": frozenset({"smss.exe"}),
    "services.exe": frozenset({"wininit.exe"}),
    "lsass.exe": frozenset({"wininit.exe"}),
    "lsaiso.exe": frozenset({"wininit.exe"}),
    "svchost.exe": frozenset({"services.exe"}),
}

#: Where Windows keeps the processes whose parent is already fixed above. Held
#: as a directory rather than a full path because the volume prefix varies and
#: SysWOW64 is a legitimate home for a 32-bit instance of some of these.
EXPECTED_IMAGE_DIR: dict[str, tuple[str, ...]] = {
    "smss.exe": ("\\windows\\system32\\",),
    "csrss.exe": ("\\windows\\system32\\",),
    "wininit.exe": ("\\windows\\system32\\",),
    "winlogon.exe": ("\\windows\\system32\\",),
    "services.exe": ("\\windows\\system32\\",),
    "lsass.exe": ("\\windows\\system32\\",),
    "lsaiso.exe": ("\\windows\\system32\\",),
    "svchost.exe": ("\\windows\\system32\\", "\\windows\\syswow64\\"),
    "explorer.exe": ("\\windows\\",),
    "spoolsv.exe": ("\\windows\\system32\\",),
    "taskhostw.exe": ("\\windows\\system32\\",),
}

#: Processes Windows runs only in session 0. csrss and winlogon are deliberately
#: absent: one of each exists per interactive session, so a non-zero session is
#: correct for them and flagging it would fire on every healthy host.
SESSION_ZERO_ONLY = frozenset(
    {"wininit.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe"}
)

#: The account each of these runs as. Anything else on one of them is either a
#: masquerade or a token manipulation. svchost is excluded: it legitimately runs
#: as LocalService and NetworkService as well as SYSTEM.
EXPECTED_USER: dict[str, frozenset[str]] = {
    "wininit.exe": frozenset({"system"}),
    "services.exe": frozenset({"system"}),
    "lsass.exe": frozenset({"system"}),
    "smss.exe": frozenset({"system"}),
    "csrss.exe": frozenset({"system"}),
    "winlogon.exe": frozenset({"system"}),
}

#: Binaries whose presence as a *parent* means the real launcher is hidden.
#: Each is a documented indirect-execution technique, and each was chosen
#: because it has almost no reason to parent anything in ordinary use.
#:
#: pcalua.exe and wmiprvse.exe are here from a real intrusion: a pasted command
#: ran "pcalua.exe -a powershell", then had WMI create the payload so that its
#: parent became WmiPrvSE rather than the shell. Two lineage breaks in one line,
#: both of which defeat a rule that walks ancestry looking for a known-bad pair.
PROXY_PARENTS: dict[str, str] = {
    "pcalua.exe": "Program Compatibility Assistant used as a launcher (T1202)",
    "wmiprvse.exe": "created through WMI, hiding the real parent (T1047)",
    "mshta.exe": "spawned by the HTML Application host (T1218.005)",
    "forfiles.exe": "spawned by forfiles, an indirect-execution proxy (T1202)",
}

OFFICE_PROCESSES = frozenset(
    {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
     "onenote.exe", "visio.exe", "acrord32.exe", "acrobat.exe"}
)
BROWSERS = frozenset(
    {"msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "brave.exe",
     "opera.exe"}
)
SHELLS = frozenset({"cmd.exe", "powershell.exe", "pwsh.exe"})
SCRIPT_ENGINES = frozenset({"wscript.exe", "cscript.exe", "mshta.exe"})
#: Signed Microsoft binaries commonly used to proxy execution of attacker code.
LOLBINS = frozenset(
    {"regsvr32.exe", "rundll32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
     "installutil.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe", "msiexec.exe",
     "cmstp.exe", "odbcconf.exe"}
)

#: PowerShell accepts any unambiguous prefix of -EncodedCommand, so -e, -enc and
#: -encodedcommand are all valid. The long base64 argument is what makes it a
#: finding rather than a match on -ExecutionPolicy, which shares the prefix but
#: is followed by a word.
_ENCODED_COMMAND = re.compile(
    r"[-/]e[a-z]*\s+[\"']?[A-Za-z0-9+/]{40,}={0,2}", re.I
)

#: (pattern, why) — the reason is carried into the finding, because "suspicious
#: command line" on its own tells an examiner nothing they can put in a report.
SUSPICIOUS_COMMAND: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\biex\b|invoke-expression", re.I),
     "pipes text into Invoke-Expression"),
    (re.compile(r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|\birm\b", re.I),
     "downloads and runs content in memory"),
    (re.compile(r"frombase64string", re.I), "decodes an embedded base64 payload"),
    (re.compile(r"-w(indowstyle)?\s+hidden|-noni|-noprofile", re.I),
     "hides the console window or skips the profile"),
    (re.compile(r"-ep\s+bypass|executionpolicy\s+bypass", re.I),
     "bypasses the PowerShell execution policy"),
    # The drive letter sits between "net use" and the UNC path, so the match
    # cannot require @SSL to follow the verb directly.
    (re.compile(r"net\s+use\b.{0,80}@ssl", re.I | re.S),
     "mounts a remote WebDAV share over HTTPS"),
    (re.compile(r"regsvr32.{0,40}scrobj", re.I),
     "executes a remote scriptlet via regsvr32 (Squiblydoo, T1218.010)"),
    (re.compile(r"win32_process.{0,20}create", re.I),
     "creates a process through WMI, detaching it from this one"),
    (re.compile(r"certutil.{0,40}(-urlcache|-decode)", re.I),
     "uses certutil to fetch or decode a payload"),
    (re.compile(r"bitsadmin.{0,20}/transfer", re.I),
     "transfers a file with bitsadmin"),
)

#: The only modules that legitimately own a system-call table entry.
KERNEL_MODULES = frozenset(
    {"ntoskrnl", "ntkrnlmp", "ntkrnlpa", "ntkrpamp",
     "win32k", "win32kbase", "win32kfull"}
)

#: Directories a Windows service binary has no ordinary reason to live in.
#: ProgramData is deliberately excluded — several legitimate updaters use it,
#: and the false positives would outnumber the finds.
USER_WRITABLE = ("\\users\\", "\\temp\\", "\\appdata\\", "\\tmp\\",
                 "\\downloads\\", "\\public\\")

_NETWORK_PLUGINS = ("windows.netscan.NetScan", "windows.netstat.NetStat")

#: Windows process IDs are allocated below this; anything above is not one.
_MAX_PID = 4_194_304
#: Generous: the busiest real process on a loaded server stays in the hundreds.
_MAX_THREADS = 10_000
#: A process image name is a filename. None of these can appear in one.
_INVALID_IN_NAME = set('\\/:*?"<>|')


def implausible_process(row: dict) -> str | None:
    """Why this row cannot describe a real process, or ``None`` if it might.

    Pool scanning recovers anything shaped like an ``_EPROCESS``, and on a
    multi-gigabyte image some of those hits are coincidence rather than a
    process. One such row — name ``\\``, PPID 3,014,702, 7,143,525 threads —
    satisfied every clause of ``psscan_only`` (present in PsScan, absent from
    PsList, no exit time), became a high-severity finding, and sent eight
    follow-up plugins to search a 25 GB image for a process that never existed.

    This is the same failure the kernel-symbol scan already guards against,
    where most ``RSDS`` matches in raw memory are coincidental. The bounds here
    are deliberately loose: they reject the physically impossible, not the
    merely unusual, so a real process is never discarded to tidy up output.
    """
    name = row.get("ImageFileName") or row.get("Process") or row.get("Name")
    if _present(name) and set(str(name)) & _INVALID_IN_NAME:
        return f"image name {str(name)!r} is not a valid filename"

    threads = _as_int(row.get("Threads"))
    if threads is not None and (threads < 0 or threads > _MAX_THREADS):
        return f"{threads:,} threads"

    for field_name in ("PID", "PPID"):
        value = _as_int(row.get(field_name))
        if value is not None and (value < 0 or value > _MAX_PID):
            return f"{field_name} {value:,} is outside the range Windows allocates"

    return None


def _has_exit_time(process: Process) -> bool:
    for plugin in ("windows.psscan.PsScan", "windows.pslist.PsList",
                   "windows.pstree.PsTree"):
        for row in process.rows(plugin):
            if _present(row.get("ExitTime")):
                return True
    for row in process.rows("windows.malware.psxview.PsXView"):
        if _present(row.get("Exit Time")):
            return True
    return False


def _is_external(address) -> bool:
    """Whether a foreign address is routable off the host.

    ``is_global`` excludes loopback, link-local, private ranges, multicast and
    the unspecified address in one check, which is exactly the set that should
    not raise an eyebrow on its own. It also excludes carrier-grade NAT, which
    is right — those are legitimate on a mobile-tethered host — and the
    documentation ranges such as 203.0.113.0/24, which is a defensible loss: a
    connection to one would be odd, but it is rare enough not to be worth the
    false positives that hand-rolling this check would bring.
    """
    if not _present(address):
        return False
    try:
        return ipaddress.ip_address(str(address).strip()).is_global
    except ValueError:
        return False


def _connections(process: Process) -> list[dict]:
    rows: list[dict] = []
    for plugin in _NETWORK_PLUGINS:
        rows.extend(process.rows(plugin))
    return rows


def compute_process_signals(process: Process, analysis: Analysis) -> None:
    """Derive the signal set for one process. Pure: reads rows, sets names."""
    signals = process.signals

    in_pslist = bool(process.rows("windows.pslist.PsList"))
    in_psscan = bool(process.rows("windows.psscan.PsScan"))
    exited = _has_exit_time(process)

    if in_pslist:
        signals.add("pslist")
    if in_psscan:
        signals.add("psscan")
    if exited:
        signals.add("exited")

    # The guard is the whole rule. Without "and not exited" this fires on every
    # process that has terminated recently — Windows does not zero the pool, so
    # PsScan recovers dozens of dead processes on any busy host, and a finding
    # that appears eighty times teaches the analyst to ignore the category.
    if in_psscan and not in_pslist and not exited:
        signals.add("psscan_only")

    if process.rows("windows.malware.malfind.Malfind"):
        signals.add("malfind")
    if process.rows("windows.malware.hollowprocesses.HollowProcesses"):
        signals.add("hollow")
    if process.rows("windows.malware.processghosting.ProcessGhosting"):
        signals.add("ghosted")
    if process.rows("windows.malware.suspicious_threads.SuspiciousThreads"):
        signals.add("suspicious_thread")

    for row in process.rows("windows.malware.pebmasquerade.PebMasquerade"):
        if row.get("PEB_ImageFilePath_Spoofed") or row.get("PEB_CommandLine_Spoofed"):
            signals.add("peb_masquerade")

    # A module absent from one of the three PEB lists but present in the others
    # is the classic reflectively-loaded DLL. Absent from all three is a mapped
    # file rather than a module, which is ordinary.
    for row in process.rows("windows.malware.ldrmodules.LdrModules"):
        flags = [row.get("InLoad"), row.get("InInit"), row.get("InMem")]
        if any(f is True for f in flags) and any(f is False for f in flags):
            signals.add("ldrmodules_unlinked")

    # PsXView's csrss and thrdscan columns are legitimately false for several
    # system processes, so only the pslist discrepancy is treated as hiding.
    for row in process.rows("windows.malware.psxview.PsXView"):
        seen_elsewhere = row.get("psscan") is True or row.get("thrdscan") is True
        if row.get("pslist") is False and seen_elsewhere and not _present(
            row.get("Exit Time")
        ):
            signals.add("psxview_hidden")

    connections = _connections(process)
    if connections:
        signals.add("network")
    for row in connections:
        if _is_external(row.get("ForeignAddr")):
            signals.add("network_external")
            break

    expected = EXPECTED_PARENT.get((process.name or "").lower())
    if expected and process.ppid is not None:
        parents = analysis.by_pid(process.ppid)
        # Only judged when the parent is actually resolvable. csrss, wininit and
        # winlogon are all children of an smss that has since exited, so an
        # unresolvable parent is normal and must not fire.
        names = {(p.name or "").lower() for p in parents if p.name}
        if names and not (names & expected):
            signals.add("unusual_parent")

    _image_signals(process)
    _context_signals(process)
    _command_line_signals(process)
    _lineage_signals(process, analysis)


def _image_signals(process: Process) -> None:
    """Where the executable lives, judged against where it should."""
    if not process.image_path:
        return

    name = (process.name or "").lower()
    expected_dirs = EXPECTED_IMAGE_DIR.get(name)
    if expected_dirs and not any(d in process.image_path for d in expected_dirs):
        process.signals.add("system_process_wrong_path")

    # A user-writable image is only remarkable for something claiming to be a
    # system binary; ordinary applications live under a user profile all the
    # time, and flagging those would bury the one that matters.
    if expected_dirs and any(d in process.image_path for d in USER_WRITABLE):
        process.signals.add("user_writable_image")


def _context_signals(process: Process) -> None:
    """The session and account a process runs under."""
    name = (process.name or "").lower()

    if (
        process.session_id is not None
        and name in SESSION_ZERO_ONLY
        and process.session_id != 0
    ):
        process.signals.add("system_process_wrong_session")

    expected_users = EXPECTED_USER.get(name)
    if expected_users and process.user_name:
        # Volatility renders these as DOMAIN\user or /SYSTEM depending on the
        # account; the trailing component is the part worth comparing.
        account = process.user_name.replace("/", "\\").rsplit("\\", 1)[-1].lower()
        if account and account not in expected_users:
            process.signals.add("system_process_wrong_user")


def _command_line_signals(process: Process) -> None:
    if not process.command_line:
        return
    if _ENCODED_COMMAND.search(process.command_line):
        process.signals.add("encoded_command")
    for pattern, _reason in SUSPICIOUS_COMMAND:
        if pattern.search(process.command_line):
            process.signals.add("suspicious_command_line")
            break


def command_line_reasons(process: Process) -> list[str]:
    """Why a command line was called suspicious. Used by the report."""
    if not process.command_line:
        return []
    return [
        reason
        for pattern, reason in SUSPICIOUS_COMMAND
        if pattern.search(process.command_line)
    ]


def _lineage_signals(process: Process, analysis: Analysis) -> None:
    """What launched this, and what that launched in turn.

    Ancestry rather than immediate parent, so a loader inserted between the
    document and the shell does not hide the relationship. The proxy-parent
    check is separate and deliberately *not* ancestry-based: the point of
    pcalua and WMI is that the chain above them is a lie.
    """
    name = (process.name or "").lower()

    parent = analysis.parent(process)
    if parent is not None and (parent.name or "").lower() in PROXY_PARENTS:
        process.signals.add("lolbin_proxy_parent")
        if (parent.name or "").lower() == "wmiprvse.exe":
            process.signals.add("wmi_spawned_process")

    if name in SHELLS or name in SCRIPT_ENGINES:
        if analysis.has_ancestor(process, OFFICE_PROCESSES):
            process.signals.add("office_spawned_shell")
        if analysis.has_ancestor(process, BROWSERS):
            process.signals.add("browser_spawned_shell")

    if name in LOLBINS and analysis.has_ancestor(process, SCRIPT_ENGINES):
        process.signals.add("script_engine_spawned_lolbin")


def compute_module_signals(module: Module, analysis: Analysis) -> None:
    """Derive the signal set for one kernel module or driver."""
    signals = module.signals

    loaded = bool(module.rows("windows.modules.Modules"))
    scanned = bool(module.rows("windows.modscan.ModScan"))
    if loaded:
        signals.add("loaded")
    if scanned:
        signals.add("scanned")

    # The kernel analogue of psscan_only: recovered by pool scan, missing from
    # PsLoadedModuleList. Unlike processes there is no exit time to guard
    # against, because an unloaded driver's module entry is removed outright.
    if scanned and not loaded:
        signals.add("scanned_only")

    # DriverModule only emits rows for drivers whose start address matches no
    # known module, so a row is already the anomaly. Known Exception marks the
    # ones upstream has confirmed benign.
    for row in module.rows("windows.malware.drivermodule.DriverModule"):
        if row.get("Known Exception") is True:
            signals.add("known_exception")
        else:
            signals.add("unbacked_driver")

    if module.rows("windows.callbacks.Callbacks"):
        signals.add("owns_callback")
        if module.key == UNRESOLVED:
            signals.add("unresolved_callback")

    for row in module.rows("windows.ssdt.SSDT"):
        owner = normalise_module(row.get("Module"))
        if owner is None or owner not in KERNEL_MODULES:
            signals.add("ssdt_hook")

    for row in module.rows("windows.modules.Modules"):
        if not _present(row.get("Path")):
            signals.add("no_disk_path")


def compute_service_signals(service: Service, analysis: Analysis) -> None:
    """Derive the signal set for one service, including its host process."""
    signals = service.signals

    for row in service.rows("windows.svcscan.SvcScan"):
        if str(row.get("State", "")).upper() == "SERVICE_RUNNING":
            signals.add("service_running")

    # Every SvcDiff row is already the finding. Upstream compares
    # SvcScan.service_scan() against SvcList.service_list() and yields only
    # `from_scan - from_list` — services recovered by pool scan that the service
    # manager's own list does not admit to.
    #
    # So a SvcDiff hit is by construction *also* a SvcScan hit, and an earlier
    # version of this that required "in SvcDiff and not in SvcScan" could never
    # fire. Presence is the whole condition.
    #
    # Caveat worth knowing: SvcDiff only runs on Windows 10 15063+ 64-bit. On
    # anything older it logs a warning and yields nothing, which is
    # indistinguishable here from "no hidden services".
    if service.rows("windows.malware.svcdiff.SvcDiff"):
        signals.add("svcdiff_hidden")

    if service.rows("windows.svcscan.SvcScan") and not _present(service.binary):
        signals.add("service_no_binary")

    binary = (service.binary or "").replace("/", "\\").lower()
    if binary and any(fragment in binary for fragment in USER_WRITABLE):
        signals.add("service_binary_in_user_path")

    # The correlation the whole service entity exists for: a service is only as
    # trustworthy as the process hosting it.
    #
    # Bare malfind is deliberately not enough. Every JIT compiler on the host
    # produces an executable private VAD, which is why the process rule for it
    # alone is only medium. Propagating that to a critical service finding would
    # undo the distinction — so the host must carry a qualifying signal too.
    if service.pid:
        for host in analysis.by_pid(service.pid):
            qualified = {"network_external", "suspicious_thread", "hollow", "ghosted"}
            if "malfind" in host.signals and qualified & host.signals:
                signals.add("service_host_injected")
            if {"psscan_only", "psxview_hidden"} & host.signals:
                signals.add("service_host_hidden")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def analyse(output_dir: Path) -> Analysis:
    """Read a finished triage folder and return its correlated entities."""
    analysis = Analysis()
    rows_by_plugin: dict[str, list[dict]] = {}

    any_json = any(output_dir.glob("*.json"))
    any_csv = any(output_dir.glob("*.csv"))
    if not any_json and any_csv:
        analysis.note(
            "error",
            "This folder contains CSV output only, and analysis reads JSON.\n"
            "  Re-run triage to produce it: v4ag triage --image <image> "
            "--format json\n"
            "  Add csv back only if something downstream needs it "
            "(--format csv,json), which costs a second pass over the image.",
        )
        return analysis

    for extractor in EXTRACTORS:
        path = output_json_path(output_dir, extractor.plugin)
        if not path.is_file():
            analysis.plugins_missing[extractor.plugin] = "no output file"
            continue
        try:
            rows = iter_rows(load_rows(path), nested=extractor.nested)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            analysis.plugins_missing[extractor.plugin] = f"unreadable: {exc}"
            continue
        rows_by_plugin[extractor.plugin] = rows
        analysis.plugins_read[extractor.plugin] = len(rows)

    if not rows_by_plugin:
        analysis.note(
            "error",
            "No plugin JSON was found in this folder. Is it a triage output "
            "directory?",
        )
        return analysis

    build_entities(rows_by_plugin, analysis)

    # Processes first: service signals consult their host process's verdict.
    for process in analysis.processes:
        compute_process_signals(process, analysis)
    for module in analysis.modules:
        compute_module_signals(module, analysis)
    for service in analysis.services:
        compute_service_signals(service, analysis)

    if analysis.plugins_read and not any(analysis.plugins_read.values()):
        analysis.note(
            "error",
            "Every plugin returned zero rows. Volatility read the image but "
            "could not map its memory.\n"
            "  Findings from this run are not trustworthy.",
        )

    for plugin, reason in sorted(analysis.plugins_missing.items()):
        analysis.note(
            "warning",
            f"{plugin} produced no usable output ({reason}).\n"
            f"  See logs/{plugin}.json.log, or re-run it alone: "
            f"v4ag triage --image <image> --plugins {plugin}",
        )

    return analysis


