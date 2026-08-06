"""The curated Windows triage set.

Running all 181 installed plugins wastes time on Linux and macOS ones that cannot
apply, and buries the useful output in failures. This list is Windows-only,
ordered roughly by how early it earns its keep in an investigation.

Every name here was validated against volatility3 2.28.0. A test re-checks them
against whatever version is installed, so a rename upstream surfaces as a failed
test rather than as a plugin that silently never runs.

``cost`` marks plugins that scan the whole image rather than walking structures.
Those dominate wall-clock on a large capture and are the reason ``--jobs`` exists.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Plugin:
    name: str
    category: str
    cost: str = "fast"  # fast | slow

    @property
    def short(self) -> str:
        return self.name.rsplit(".", 1)[-1]


TRIAGE: tuple[Plugin, ...] = (
    # Establish what the image even is. Runs first, alone, as a probe.
    Plugin("windows.info.Info", "system"),
    # Processes: the spine of most investigations.
    Plugin("windows.pslist.PsList", "processes"),
    Plugin("windows.pstree.PsTree", "processes"),
    Plugin("windows.psscan.PsScan", "processes", cost="slow"),
    Plugin("windows.cmdline.CmdLine", "processes"),
    Plugin("windows.sessions.Sessions", "processes"),
    Plugin("windows.getsids.GetSIDs", "processes"),
    Plugin("windows.privileges.Privs", "processes"),
    Plugin("windows.envars.Envars", "processes"),
    # Network.
    Plugin("windows.netscan.NetScan", "network", cost="slow"),
    Plugin("windows.netstat.NetStat", "network", cost="slow"),
    # Injection and unbacked code.
    # Canonical name: windows.malfind.Malfind still resolves but is a deprecated
    # alias, due for removal in the first release after 2026-06-07.
    Plugin("windows.malware.malfind.Malfind", "injection", cost="slow"),
    Plugin("windows.vadinfo.VadInfo", "injection", cost="slow"),
    Plugin("windows.dlllist.DllList", "modules"),
    Plugin("windows.modules.Modules", "modules"),
    Plugin("windows.modscan.ModScan", "modules", cost="slow"),
    # Persistence.
    Plugin("windows.svcscan.SvcScan", "persistence", cost="slow"),
    Plugin("windows.registry.hivelist.HiveList", "registry"),
    Plugin("windows.registry.printkey.PrintKey", "registry"),
    Plugin("windows.registry.userassist.UserAssist", "registry"),
    # Kernel surface.
    Plugin("windows.driverscan.DriverScan", "kernel", cost="slow"),
    Plugin("windows.callbacks.Callbacks", "kernel"),
    Plugin("windows.ssdt.SSDT", "kernel"),
    Plugin("windows.devicetree.DeviceTree", "kernel"),
    # Dedicated malware hunting. These are the highest-yield plugins in an
    # intrusion investigation and are cheap to include: a plugin that cannot apply
    # to this image fails, is logged, and does not affect the rest of the run.
    Plugin("windows.malware.psxview.PsXView", "malware", cost="slow"),
    Plugin("windows.malware.hollowprocesses.HollowProcesses", "malware", cost="slow"),
    Plugin("windows.malware.ldrmodules.LdrModules", "malware", cost="slow"),
    Plugin("windows.malware.processghosting.ProcessGhosting", "malware", cost="slow"),
    Plugin("windows.malware.pebmasquerade.PebMasquerade", "malware", cost="slow"),
    Plugin("windows.malware.suspicious_threads.SuspiciousThreads", "malware", cost="slow"),
    Plugin("windows.malware.unhooked_system_calls.UnhookedSystemCalls", "malware"),
    Plugin("windows.malware.drivermodule.DriverModule", "malware", cost="slow"),
    Plugin("windows.malware.svcdiff.SvcDiff", "malware", cost="slow"),
    Plugin("windows.malware.skeleton_key_check.Skeleton_Key_Check", "malware"),
    # Objects and handles. Handles is among the slowest here.
    Plugin("windows.handles.Handles", "objects", cost="slow"),
    Plugin("windows.filescan.FileScan", "objects", cost="slow"),
    Plugin("windows.mutantscan.MutantScan", "objects", cost="slow"),
    Plugin("windows.symlinkscan.SymlinkScan", "objects", cost="slow"),
    Plugin("windows.thrdscan.ThrdScan", "objects", cost="slow"),
)

#: Run first, on its own, to prove symbols resolve before committing to a full run.
PROBE = "windows.info.Info"

CATEGORIES = tuple(dict.fromkeys(p.category for p in TRIAGE))


def triage_names() -> list[str]:
    return [p.name for p in TRIAGE]


def by_category(category: str) -> list[str]:
    return [p.name for p in TRIAGE if p.category == category]


def discover_all(windows_only: bool = True) -> list[str]:
    """Every plugin the installed volatility exposes.

    Used by ``--all``. Defaults to Windows only: the Linux and macOS plugins
    cannot apply to a Windows image and would only pad the failure list.
    """
    import volatility3.framework
    import volatility3.plugins

    volatility3.framework.require_interface_version(2, 0, 0)
    volatility3.framework.import_files(volatility3.plugins, True)

    names = sorted(volatility3.framework.list_plugins())
    if windows_only:
        names = [n for n in names if n.startswith("windows.")]
    return names


def resolve(selection: str | None, *, all_plugins: bool, windows_only: bool = True) -> list[str]:
    """Turn CLI options into an ordered, de-duplicated plugin list."""
    if all_plugins:
        return discover_all(windows_only=windows_only)

    if not selection:
        return triage_names()

    requested: list[str] = []
    for raw in selection.split(","):
        item = raw.strip()
        if not item:
            continue
        if item in CATEGORIES:
            requested.extend(by_category(item))
        else:
            requested.append(item)

    return list(dict.fromkeys(requested))
