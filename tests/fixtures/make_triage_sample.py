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


def write(name, rows):
    (OUT / name).write_text("\n" + json.dumps(rows, indent=2, sort_keys=True) + "\n")


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

(OUT / "run-manifest.json").write_text(json.dumps({
    "schema_version": 1,
    "tool_version": "0.1.0",
    "image": {"path": "D:\\memory.raw", "name": "memory.raw",
              "size_bytes": 34359738368,
              "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    "plugins": [],
    "summary": {"total": 0, "succeeded": 0, "failed": 0},
    "outputs": [],
}, indent=2) + "\n")

print(f"wrote {len(list(OUT.glob('*.json')))} files to {OUT}")
