"""Emit the synthetic triage folder used by the analysis tests.

    python3 tests/fixtures/make_triage_sample.py

Synthetic rather than captured, so no real host data enters the repository and
the expected findings are knowable by construction. Thirteen processes: nine
ordinary, four carrying planted signals, and one — notepad.exe, PID 3300 — that
exists purely to prove the exit-time guard on ``psscan_only`` holds. Without it
that signal fires on every recently terminated process.

Regenerating changes the golden expectations in tests/test_rules.py.
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "triage-sample"
OUT.mkdir(parents=True, exist_ok=True)

# (pid, ppid, name, offset, exit_time)
PROCS = [
    (4, 0, "System", 0xB0000000, None),
    (388, 4, "smss.exe", 0xB0001000, None),
    (500, 388, "csrss.exe", 0xB0002000, None),
    (560, 388, "wininit.exe", 0xB0003000, None),
    (660, 560, "services.exe", 0xB0004000, None),
    (700, 560, "lsass.exe", 0xB0005000, None),
    (900, 660, "svchost.exe", 0xB0006000, None),
    (2100, 900, "explorer.exe", 0xB0007000, None),
    (4180, 900, "powershell.exe", 0xB0008000, None),
    (5000, 660, "svchost.exe", 0xB0009000, None),
    (6000, 4180, "lsass.exe", 0xB000A000, None),
]
# Only PsScan sees these two.
SCAN_ONLY = [
    (7224, 900, "rundll32.exe", 0xB000B000, None),                     # hidden
    (3300, 2100, "notepad.exe", 0xB000C000, "2026-08-15 09:14:02+00:00"),  # merely exited
]


def proc_row(pid, ppid, name, offset, exit_time, offset_key="Offset(V)"):
    return {
        "__children": [],
        "PID": pid,
        "PPID": ppid,
        "ImageFileName": name,
        offset_key: offset,
        "Threads": 4,
        "Handles": 120,
        "SessionId": 1,
        "Wow64": False,
        "CreateTime": "2026-08-15 08:00:00+00:00",
        "ExitTime": exit_time,
        "File output": "Disabled",
    }


def write_lf(path, text):
    """Write with LF endings whatever the platform.

    The manifest below records a SHA-256 for every file, and .gitattributes
    marks the folder ``-text`` so git never converts it either. Python's text
    mode would write CRLF on Windows, changing every digest, so the newline is
    pinned here rather than left to the platform.
    """
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def write(name, rows):
    write_lf(OUT / name, "\n" + json.dumps(rows, indent=2, sort_keys=True) + "\n")


write("windows.pslist.PsList.json", [proc_row(*p) for p in PROCS])
write("windows.psscan.PsScan.json",
      [proc_row(*p, offset_key="Offset(V)") for p in PROCS + SCAN_ONLY])

# PsTree nests: services.exe owns both svchost instances.
tree = [proc_row(*p) for p in PROCS if p[0] not in (900, 5000)]
services = next(r for r in tree if r["PID"] == 660)
services["__children"] = [proc_row(*p) for p in PROCS if p[0] in (900, 5000)]
write("windows.pstree.PsTree.json", tree)

write("windows.cmdline.CmdLine.json", [
    {"__children": [], "PID": p[0], "Process": p[2], "Args": f"C:\\Windows\\System32\\{p[2]}"}
    for p in PROCS
])

def conn(pid, owner, foreign, port, state="ESTABLISHED"):
    return {"__children": [], "Offset": 0xC0000000 + pid, "Proto": "TCPv4",
            "LocalAddr": "10.0.0.15", "LocalPort": 49000 + pid % 1000,
            "ForeignAddr": foreign, "ForeignPort": port, "State": state,
            "PID": pid, "Owner": owner, "Created": "2026-08-15 08:30:00+00:00"}

write("windows.netscan.NetScan.json", [
    conn(4180, "powershell.exe", "93.184.216.34", 443),
    conn(2100, "explorer.exe", "10.0.0.1", 445),       # internal only
    conn(900, "svchost.exe", "127.0.0.1", 135, "LISTENING"),
])

write("windows.malware.malfind.Malfind.json", [
    {"__children": [], "PID": pid, "Process": name, "Start VPN": 0x1F0000,
     "End VPN": 0x1F0FFF, "Tag": "VadS", "Protection": "PAGE_EXECUTE_READWRITE",
     "CommitCharge": 1, "PrivateMemory": 1, "File output": "Disabled",
     "Notes": "", "Hexdump": "4d 5a 90 00", "Disasm": "push rbp"}
    for pid, name in ((4180, "powershell.exe"), (2100, "explorer.exe"))
])

write("windows.malware.hollowprocesses.HollowProcesses.json", [
    {"__children": [], "PID": 5000, "Process": "svchost.exe",
     "Notes": "Mapped file does not match the process image"},
])

write("windows.malware.processghosting.ProcessGhosting.json", [])

write("windows.malware.suspicious_threads.SuspiciousThreads.json", [
    {"__children": [], "Process": "powershell.exe", "PID": 4180, "TID": 4184,
     "Context": "User", "Address": 0x1F0100, "VAD Path": "",
     "Note": "Thread start address is not backed by a module"},
])

write("windows.malware.ldrmodules.LdrModules.json", [
    {"__children": [], "Pid": 6000, "Process": "lsass.exe", "Base": 0x7FF000000000,
     "InLoad": False, "InInit": True, "InMem": True, "MappedPath": ""},
    {"__children": [], "Pid": 700, "Process": "lsass.exe", "Base": 0x7FF000001000,
     "InLoad": True, "InInit": True, "InMem": True,
     "MappedPath": "\\Windows\\System32\\ntdll.dll"},
    # Absent from all three: a mapped data file, not a module. Must not fire.
    {"__children": [], "Pid": 2100, "Process": "explorer.exe", "Base": 0x7FF000002000,
     "InLoad": False, "InInit": False, "InMem": False,
     "MappedPath": "\\Windows\\Fonts\\segoeui.ttf"},
    # The .NET runtime, present in every PEB list, in the planted powershell.
    # Its malfind region above begins with MZ — the one .NET malfind hit that
    # is not the JIT. explorer's region begins with MZ too, but explorer hosts
    # no runtime, so it stays a bare PROC-INJECT with the header noted.
    {"__children": [], "Pid": 4180, "Process": "powershell.exe", "Base": 0x7FF000003000,
     "InLoad": True, "InInit": True, "InMem": True,
     "MappedPath": "\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll"},
])

write("windows.malware.pebmasquerade.PebMasquerade.json", [
    {"__children": [], "PID": 6000, "EPROCESS_ImageFileName": "lsass.exe",
     "EPROCESS_SeAudit_ImageFileName": "\\Device\\Temp\\x.exe",
     "PEB_ImageFilePath": "C:\\Windows\\System32\\lsass.exe",
     "PEB_ImageFilePath_Spoofed": True, "PEB_CommandLine_Spoofed": False},
])

write("windows.malware.psxview.PsXView.json", [
    {"__children": [], "Name": "rundll32.exe", "PID": 7224, "pslist": False,
     "psscan": True, "thrdscan": True, "csrss": False, "Exit Time": None},
    {"__children": [], "Name": "notepad.exe", "PID": 3300, "pslist": False,
     "psscan": True, "thrdscan": False, "csrss": False,
     "Exit Time": "2026-08-15 09:14:02+00:00"},
    {"__children": [], "Name": "System", "PID": 4, "pslist": True, "psscan": True,
     "thrdscan": True, "csrss": False, "Exit Time": None},
])

# --- Kernel surface -------------------------------------------------------
# evilrk.sys is the planted rootkit: recovered by scan but absent from the
# loaded list, registering a driver from that hidden module, and owning an SSDT
# entry. Everything else here is ordinary.

def module_row(name, path, base=0xFFFFF80000000000, offset=0xA0000000):
    return {"__children": [], "Offset": offset, "Base": base, "Size": 0x100000,
            "Name": name, "Path": path, "File output": "Disabled"}

LOADED = [
    ("ntoskrnl.exe", "\\SystemRoot\\system32\\ntoskrnl.exe"),
    ("tcpip.sys", "\\SystemRoot\\System32\\drivers\\tcpip.sys"),
    ("ndis.sys", "\\SystemRoot\\System32\\drivers\\ndis.sys"),
    ("Wdf01000.sys", "\\SystemRoot\\System32\\drivers\\Wdf01000.sys"),
]
write("windows.modules.Modules.json",
      [module_row(n, p, offset=0xA0000000 + i * 0x1000)
       for i, (n, p) in enumerate(LOADED)])
write("windows.modscan.ModScan.json",
      [module_row(n, p, offset=0xA0000000 + i * 0x1000)
       for i, (n, p) in enumerate(LOADED)]
      + [module_row("evilrk.sys", "", offset=0xA0009000)])

write("windows.driverscan.DriverScan.json", [
    {"__children": [], "Offset": 0xA1000000, "Start": 0xFFFFF80000010000,
     "Size": 0x8000, "Service Key": "Tcpip", "Driver Name": "\\Driver\\Tcpip",
     "Name": "Tcpip"},
    {"__children": [], "Offset": 0xA1001000, "Start": 0xFFFFF80000020000,
     "Size": 0x4000, "Service Key": "evilrk", "Driver Name": "\\Driver\\evilrk",
     "Name": "evilrk"},
])

write("windows.malware.drivermodule.DriverModule.json", [
    {"__children": [], "Offset": 0xA1001000, "Known Exception": False,
     "Driver Name": "\\Driver\\evilrk", "Service Key": "evilrk",
     "Alternative Name": "evilrk"},
    # Upstream recognises this one; the rule must not fire on it.
    {"__children": [], "Offset": 0xA1002000, "Known Exception": True,
     "Driver Name": "\\Driver\\WMIxWDM", "Service Key": "",
     "Alternative Name": ""},
])

write("windows.callbacks.Callbacks.json", [
    {"__children": [], "Type": "PsSetCreateProcessNotifyRoutine",
     "Callback": 0xFFFFF80000011000, "Module": "ntoskrnl.exe",
     "Symbol": "PspCreateProcessNotify", "Detail": ""},
    {"__children": [], "Type": "PsSetCreateThreadNotifyRoutine",
     "Callback": 0xFFFFF80000021000, "Module": "UNKNOWN", "Symbol": "",
     "Detail": ""},
])

write("windows.ssdt.SSDT.json", [
    {"__children": [], "Index": 0, "Address": 0xFFFFF80000012000,
     "Module": "ntoskrnl.exe", "Symbol": "NtAcceptConnectPort"},
    {"__children": [], "Index": 41, "Address": 0xFFFFF80000022000,
     "Module": "evilrk.sys", "Symbol": "N/A"},
])

# --- Services -------------------------------------------------------------

def service_row(order, pid, name, binary, state="SERVICE_RUNNING"):
    return {"__children": [], "Offset": 0xD0000000 + order, "Order": order,
            "PID": pid, "Start": "SERVICE_AUTO_START", "State": state,
            "Type": "SERVICE_WIN32_OWN_PROCESS", "Name": name,
            "Display": name, "Binary": binary,
            "Binary (Registry)": binary, "Dll": ""}

write("windows.svcscan.SvcScan.json", [
    service_row(1, 660, "DcomLaunch",
                "C:\\Windows\\system32\\svchost.exe -k DcomLaunch"),
    service_row(2, 900, "Dhcp", "C:\\Windows\\system32\\svchost.exe -k netsvcs"),
    # Hosted by the injected powershell process.
    service_row(3, 4180, "SysMonSvc", "C:\\Windows\\system32\\svchost.exe -k rpc"),
    # Persistence pattern: SYSTEM service running a binary a user can write.
    service_row(4, 2100, "UpdaterSvc",
                "C:\\Users\\jdoe\\AppData\\Local\\Temp\\upd.exe"),
    # Recovered by the pool scan SvcScan performs, so it appears here as well as
    # in SvcDiff below. PID 0 leaves it with no host to scope a follow-up by.
    service_row(9, 0, "GhostSvc", "C:\\Windows\\system32\\ghost.exe"),
])

# SvcDiff yields only `from_scan - from_list`: services the pool scan recovers
# that walking the service manager's list does not report. Every row is already
# the anomaly, and every row also appears in SvcScan above.
write("windows.malware.svcdiff.SvcDiff.json", [
    service_row(9, 0, "GhostSvc", "C:\\Windows\\system32\\ghost.exe"),
])

# The manifest must attest to the files beside it, or analyse() has nothing to
# verify its inputs against. Written last, and excluding itself, exactly as
# manifest.build does.
import hashlib

MANIFEST = OUT / "run-manifest.json"
outputs = []
for path in sorted(p for p in OUT.rglob("*") if p.is_file() and p != MANIFEST):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    outputs.append({
        "file": path.relative_to(OUT).as_posix(),
        "size_bytes": path.stat().st_size,
        "sha256": digest,
    })

write_lf(MANIFEST, json.dumps({
    "schema_version": 1,
    "tool_version": "0.1.0",
    "image": {"path": "D:\\memory.raw", "name": "memory.raw",
              "size_bytes": 34359738368,
              "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    # A run that used a swap layer. The follow-up must use the same one, or it
    # reads a different memory image than the findings describe.
    "pagefiles": [{
        "path": "D:\\pagefile.sys",
        "size_bytes": 8589934592,
        "sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    }],
    "plugins": [],
    "summary": {"total": 0, "succeeded": 0, "failed": 0},
    "outputs": outputs,
}, indent=2) + "\n")

print(f"wrote {len(list(OUT.glob('*.json')))} files to {OUT}")
