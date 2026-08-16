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

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path

#: Values Volatility uses for "this column does not apply here".
_ABSENT = {None, "", "N/A", "-", "Disabled", "UNKNOWN", "Unknown"}

PROCESS = "process"
MODULE = "module"
SERVICE = "service"


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

    kind = PROCESS

    @property
    def key(self) -> tuple[int, int | None]:
        return (self.pid, self.offset)

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
        # Volatility's --name is a substring match, so the normalised key is a
        # better argument than the decorated name it came from.
        return {"name": self.key}

    def as_entity(self) -> dict:
        return {"type": MODULE, "key": self.key, "name": self.name}


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


def normalise_module(name) -> str | None:
    """``\\Driver\\foo``, ``foo.sys`` and ``FOO.SYS`` are one module.

    Rootkits register drivers from hidden modules, so the driver object and the
    module usually share a stem even when the decorations differ. Normalising
    to that stem is what lets DriverModule's verdict land on the same entity
    that ModScan recovered.
    """
    if not _present(name):
        return None
    text = str(name).strip().replace("/", "\\")
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    for suffix in (".sys", ".exe", ".dll"):
        if text.lower().endswith(suffix):
            text = text[: -len(suffix)]
            break
    return text.lower() or None


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
                key = "<unresolved>"
            recognised += 1

            module = entities.setdefault(key, Module(key=key))
            module.seen_in.setdefault(plugin, []).append(row)
            if module.name is None and _present(raw):
                module.name = str(raw)

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


def build_entities(rows_by_plugin: dict[str, list[dict]], analysis: Analysis) -> None:
    analysis.processes = _build_processes(rows_by_plugin, analysis)
    analysis.modules = _build_modules(rows_by_plugin, analysis)
    analysis.services = _build_services(rows_by_plugin, analysis)


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
            "service_running", "svcdiff_only", "service_binary_in_user_path",
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
    "svcdiff_only": "windows.malware.svcdiff.SvcDiff",
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
    "smss.exe": frozenset({"system"}),
    "csrss.exe": frozenset({"smss.exe"}),
    "wininit.exe": frozenset({"smss.exe"}),
    "winlogon.exe": frozenset({"smss.exe"}),
    "services.exe": frozenset({"wininit.exe"}),
    "lsass.exe": frozenset({"wininit.exe"}),
    "lsaiso.exe": frozenset({"wininit.exe"}),
    "svchost.exe": frozenset({"services.exe"}),
}

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
        if module.key == "<unresolved>":
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

    # SvcDiff walks the registry rather than the in-memory service record, so a
    # service it finds that SvcScan does not is one hidden from the service
    # control manager's own list.
    if service.rows("windows.malware.svcdiff.SvcDiff") and not service.rows(
        "windows.svcscan.SvcScan"
    ):
        signals.add("svcdiff_only")

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
            "  Re-run triage with both: v4ag triage --image <image> "
            "--format csv,json",
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
