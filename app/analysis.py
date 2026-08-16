"""Plugin JSON in, correlated entities out.

Triage writes one file per plugin. An analyst reading those files does the
correlation in their head: this PID in malfind is that PID in netscan is that
PID in pstree. This module does it on paper instead, producing one record per
process that carries every row any plugin reported about it.

Two things make that harder than it sounds.

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
_ABSENT = {None, "", "N/A", "-", "Disabled"}


@dataclass(frozen=True)
class Extractor:
    """How to find a process in one plugin's rows."""

    plugin: str
    pid: str
    name: str | None = None
    ppid: str | None = None
    #: Only set where the offset identifies the *process*. See the module note.
    offset_prefix: str | None = None
    #: PsTree emits a hierarchy; every other plugin emits a flat list.
    nested: bool = False


EXTRACTORS: tuple[Extractor, ...] = (
    Extractor("windows.pslist.PsList", "PID", "ImageFileName", "PPID", "Offset"),
    Extractor("windows.psscan.PsScan", "PID", "ImageFileName", "PPID", "Offset"),
    Extractor("windows.pstree.PsTree", "PID", "ImageFileName", "PPID", "Offset",
              nested=True),
    Extractor("windows.cmdline.CmdLine", "PID", "Process"),
    Extractor("windows.netscan.NetScan", "PID", "Owner"),
    Extractor("windows.netstat.NetStat", "PID", "Owner"),
    Extractor("windows.malware.malfind.Malfind", "PID", "Process"),
    Extractor("windows.malware.hollowprocesses.HollowProcesses", "PID", "Process"),
    Extractor("windows.malware.processghosting.ProcessGhosting", "PID", "Process"),
    Extractor("windows.malware.psxview.PsXView", "PID", "Name"),
    Extractor("windows.malware.ldrmodules.LdrModules", "Pid", "Process"),
    Extractor("windows.malware.suspicious_threads.SuspiciousThreads", "PID", "Process"),
    Extractor("windows.malware.pebmasquerade.PebMasquerade", "PID",
              "EPROCESS_ImageFileName"),
)

BY_PLUGIN = {e.plugin: e for e in EXTRACTORS}


@dataclass
class Notice:
    """Something the analyst needs to know, and what to do about it."""

    level: str  # error | warning | info
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass
class Process:
    pid: int
    offset: int | None = None
    #: The column the offset came from, e.g. ``Offset(V)``. Two offsets are only
    #: comparable when their kinds agree — see ``build_entities``.
    offset_kind: str | None = None
    name: str | None = None
    ppid: int | None = None
    #: plugin name -> the raw rows that plugin reported for this process.
    seen_in: dict[str, list[dict]] = field(default_factory=dict)
    signals: set[str] = field(default_factory=set)

    @property
    def key(self) -> tuple[int, int | None]:
        return (self.pid, self.offset)

    @property
    def label(self) -> str:
        return f"{self.name or 'unknown'} (PID {self.pid})"

    def rows(self, plugin: str) -> list[dict]:
        return self.seen_in.get(plugin, [])

    def as_entity(self) -> dict:
        return {
            "type": "process",
            "pid": self.pid,
            "offset": self.offset,
            "name": self.name,
            "ppid": self.ppid,
        }


@dataclass
class Analysis:
    processes: list[Process] = field(default_factory=list)
    #: Plugins whose JSON was read, mapped to their row count.
    plugins_read: dict[str, int] = field(default_factory=dict)
    #: Plugins the run should have had but does not, mapped to why.
    plugins_missing: dict[str, str] = field(default_factory=dict)
    notices: list[Notice] = field(default_factory=list)

    def note(self, level: str, message: str) -> None:
        self.notices.append(Notice(level, message))

    def by_pid(self, pid: int) -> list[Process]:
        return [p for p in self.processes if p.pid == pid]


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


# --------------------------------------------------------------------------
# Entity construction
# --------------------------------------------------------------------------


def build_entities(rows_by_plugin: dict[str, list[dict]], analysis: Analysis) -> None:
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

        process = entities.setdefault(
            (pid, offset), Process(pid=pid, offset=offset, offset_kind=kind)
        )
        return process

    # Offset-bearing plugins run first, so later offset-less rows attach to a
    # fully identified entity rather than creating a shadow of it.
    ordered = sorted(
        rows_by_plugin, key=lambda name: BY_PLUGIN[name].offset_prefix is None
    )

    for plugin in ordered:
        extractor = BY_PLUGIN[plugin]
        recognised = 0
        for row in rows_by_plugin[plugin]:
            pid = _as_int(row.get(extractor.pid))
            if pid is None:
                continue
            recognised += 1

            offset, kind = None, None
            if extractor.offset_prefix:
                kind = _first_column(row, extractor.offset_prefix)
                offset = _as_int(row.get(kind)) if kind else None

            process = attach(pid, offset, kind)
            process.seen_in.setdefault(plugin, []).append(row)

            if process.name is None and extractor.name:
                name = row.get(extractor.name)
                process.name = str(name) if _present(name) else None
            if process.ppid is None and extractor.ppid:
                process.ppid = _as_int(row.get(extractor.ppid))

        if rows_by_plugin[plugin] and recognised == 0:
            analysis.note(
                "warning",
                f"{plugin} has no recognised {extractor.pid} column "
                f"(volatility version drift?). Its "
                f"{len(rows_by_plugin[plugin])} row(s) were skipped.",
            )

    analysis.processes = sorted(entities.values(), key=lambda p: (p.pid, p.offset or 0))


# --------------------------------------------------------------------------
# Signals
# --------------------------------------------------------------------------

#: The closed vocabulary. A rule may reference nothing outside this set.
VOCABULARY: frozenset[str] = frozenset(
    {
        "pslist",
        "psscan",
        "psscan_only",
        "exited",
        "malfind",
        "hollow",
        "ghosted",
        "peb_masquerade",
        "psxview_hidden",
        "suspicious_thread",
        "ldrmodules_unlinked",
        "network",
        "network_external",
        "unusual_parent",
    }
)

#: Which plugin each signal needs. Used to report rules that could not be
#: evaluated rather than letting an absent plugin read as an absent finding.
SIGNAL_SOURCE: dict[str, str] = {
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


def compute_signals(process: Process, analysis: Analysis) -> None:
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
    for process in analysis.processes:
        compute_signals(process, analysis)

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
