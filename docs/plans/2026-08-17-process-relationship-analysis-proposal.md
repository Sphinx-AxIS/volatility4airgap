# Process Relationship Analysis — Proposal

**Date:** 2026-08-17
**Status:** Proposed

Brainstorming notes on extending `analyze` with process-relationship, ancestry and
baseline signals. **Not a specification.** The implemented design is
[2026-08-15-post-triage-analysis-design.md](2026-08-15-post-triage-analysis-design.md);
where the sections below describe current behaviour they are descriptive rather than
normative, and where they propose new work none of it is built.

Two notes for anyone picking this up:

- The example rule recommending `dump_process` is no longer in tension with the
  shipped pack. Rules may now recommend dumps; the tool renders the command for the
  analyst instead of executing it, gated behind `--dump`.
- Ancestry-based signals would not have caught the ClickFix intrusion this project
  was built for. That chain was `explorer.exe → pcalua.exe → powershell.exe` followed
  by a WMI reparent to `WmiPrvSE.exe → regsvr32.exe` — two deliberate lineage breaks.
  A `lolbin_proxy_parent` signal (parent is a known execution proxy) is the sharper
  lesson, and is cheap: it needs only `ppid` and `Analysis.by_pid`, both of which exist.

---

Volatility4AirGap already has a strong separation between **collection** and **analysis**:

```text
memory image
    │
    ▼
v4ag triage
    │
    ├── pslist
    ├── pstree
    ├── psscan
    ├── cmdline
    ├── netscan
    ├── malfind
    ├── dlllist
    └── ...
         │
         ▼
    CSV / JSON
         │
         ▼
v4ag analyze
         │
         ▼
 correlated entities
 signals / rules
 findings
 follow-up actions
```

`triage` already runs the curated Volatility set, writes the outputs and manifest, while `analyze` subsequently verifies those outputs, correlates them into processes/modules/services, evaluates rules, and generates findings.

More importantly, **you have already started implementing the exact process-parent concept we were discussing.**

`analysis.py` contains an `EXPECTED_PARENT` table:

```python
EXPECTED_PARENT = {
    "smss.exe": {"system"},
    "csrss.exe": {"smss.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "lsaiso.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe"},
}
```

and `compute_process_signals()` generates an `unusual_parent` signal when the resolved PPID doesn't correspond to the expected executable.

That's actually a very good foundation.

## I would evolve `analyze`, rather than add another top-level collection command

I'd keep:

```text
v4ag triage
```

meaning:

> Extract forensic evidence.

And:

```text
v4ag analyze
```

meaning:

> Interpret and correlate forensic evidence.

Then introduce a **baseline/profile concept inside `analyze`**.

For example:

```text
v4ag analyze output\memory --profile windows
```

or:

```text
v4ag analyze output\memory --baseline baselines\windows11.json
```

And optionally:

```text
v4ag analyze output\memory --baseline baselines\corporate-workstations.json
```

This fits existing architecture much better.

---

## I'd actually make three layers

The model I'd use is:

```text
                    ANALYSIS
                       │
       ┌───────────────┼────────────────┐
       │               │                │
       ▼               ▼                ▼
  Windows          Detection       Organisation
  invariant         rules           baseline
       │               │                │
       └───────────────┼────────────────┘
                       ▼
                  Process signals
                       │
                       ▼
                    Findings
```

Those three things are subtly different.

## 1. Windows invariants

Things that are sufficiently constrained that violating them is genuinely suspicious.

You already have this.

For example:

```text
services.exe
   parent → wininit.exe

lsass.exe
   parent → wininit.exe

svchost.exe
   parent → services.exe
```

I would keep these inside the code or bundled Windows profile because these aren't really “enterprise baselines.”

They're OS expectations.

The table is deliberately short because broad “expected parent” tables create false positives.

I'd preserve that philosophy.

---

## 2. Suspicious process relationships

This is different from expected parents.

For example:

```text
WINWORD.EXE
    └─ powershell.exe
```

Word isn't required to have a particular parent.

But PowerShell being its child is interesting.

So introduce a second type of relationship:

```json
{
  "suspicious_children": {
    "winword.exe": [
      "powershell.exe",
      "cmd.exe",
      "mshta.exe",
      "wscript.exe",
      "cscript.exe",
      "rundll32.exe",
      "regsvr32.exe"
    ],

    "excel.exe": [
      "powershell.exe",
      "cmd.exe",
      "mshta.exe",
      "wscript.exe"
    ],

    "acrord32.exe": [
      "powershell.exe",
      "cmd.exe",
      "mshta.exe"
    ]
  }
}
```

Then:

```text
WINWORD → powershell
```

generates:

```text
suspicious_process_chain
```

rather than:

```text
unusual_parent
```

That distinction matters.

---

## 3. Environment-specific baseline

Then have an optional analyst-maintained profile.

For example:

```json
{
  "name": "Corporate Windows 11 Workstation",
  "version": "2026.08",

  "allowed_relationships": [
    {
      "parent": "explorer.exe",
      "child": "companyagent.exe"
    },
    {
      "parent": "outlook.exe",
      "child": "vendorplugin.exe"
    }
  ],

  "trusted_paths": {
    "companyagent.exe": [
      "C:\\Program Files\\Company\\Agent\\companyagent.exe"
    ]
  }
}
```

This gives you:

```text
Windows invariant
        +
Threat detection knowledge
        +
Organisation-specific context
```

without confusing the three.

---

## I would NOT produce one numeric “maliciousness score”

I noticed this comment in `rules.py`:

> a finding that names its rule and cites the rows that triggered it can be defended in a report

rather than treating something like `0.82` as meaningfully worse than `0.78`.

I strongly agree with that design decision for a forensic tool.

Instead of:

```text
powershell.exe = 87/100 malicious
```

I'd produce:

```text
PROC-0004  HIGH

PID:       4832
Image:     powershell.exe
Parent:    WINWORD.EXE
PPID:      2716

Signals:
    suspicious_process_chain
    encoded_command
    network_external
    malfind

Evidence:
    windows.pslist.PsList
    windows.cmdline.CmdLine
    windows.netscan.NetScan
    windows.malware.malfind.Malfind
```

That's vastly more defensible.

And it fits your existing `Finding` model, which already stores:

```text
rule_id
severity
title
entity
evidence
recommended_actions
```

---

## I'd expand `Process`

Your current `Process` entity already correlates records using PID/offset and stores PPID and data from multiple plugins. The extractor framework pulls process information from `pslist`, `psscan`, `pstree`, `cmdline`, `netscan`, etc.

I'd make the derived representation more explicit:

```python
@dataclass
class Process(Entity):
    pid: int
    ppid: int | None

    name: str | None
    parent_name: str | None

    command_line: str | None
    image_path: str | None

    session_id: int | None
    user_sid: str | None

    children: list[int]

    offset: int | None
```

Not all of those need to be canonical fields immediately; some can continue living in `seen_in`.

But `parent_name` and `children` are worth deriving.

Then give `Analysis` helpers such as:

```python
analysis.parent(process)
analysis.children(process)
analysis.ancestors(process)
analysis.descendants(process)
```

That becomes extremely powerful.

---

## Ancestors are more useful than just parent/child

Consider:

```text
OUTLOOK.EXE
   └─ WINWORD.EXE
       └─ cmd.exe
           └─ powershell.exe
               └─ rundll32.exe
```

A rule engine limited to individual process properties misses some context.

I'd add process-chain signals such as:

```text
office_spawned_shell
office_spawned_script_engine
browser_spawned_shell
pdf_reader_spawned_shell
service_spawned_user_binary
wmi_spawned_shell
script_engine_spawned_lolbin
shell_spawned_credential_tool
```

But derive them based on **ancestry**, not necessarily immediate PPID.

For example:

```python
if has_ancestor(process, OFFICE_PROCESSES) and process.name in SHELLS:
    signals.add("office_spawned_shell")
```

That catches:

```text
WINWORD
   └─ cmd
       └─ powershell
```

as well as:

```text
WINWORD
   └─ some-loader.exe
       └─ powershell
```

---

## Your existing signal framework is ideal for this

Right now your process vocabulary includes things such as:

```text
psscan_only
malfind
hollow
ghosted
peb_masquerade
psxview_hidden
suspicious_thread
ldrmodules_unlinked
network_external
unusual_parent
```

I would extend it with:

```text
unusual_parent
suspicious_parent_child
suspicious_ancestor
system_process_wrong_path
system_process_wrong_session
system_process_wrong_user
encoded_command
suspicious_command_line
user_writable_image
network_external
network_lateral
```

Then rules combine signals.

For example:

```json
{
  "id": "PROC-OFFICE-SHELL-001",
  "severity": "high",
  "title": "Office application spawned command interpreter",
  "all": [
    {"signal": "office_spawned_shell"}
  ],
  "actions": [
    "process_tree",
    "dump_process",
    "inspect_vads"
  ]
}
```

And a stronger rule:

```json
{
  "id": "PROC-OFFICE-SHELL-NET-001",
  "severity": "critical",
  "title": "Office-spawned command interpreter established external network communication",
  "all": [
    {"signal": "office_spawned_shell"},
    {"signal": "network_external"}
  ]
}
```

This plays directly into your existing rule combinators such as `all`, `any`, `none`, and `at_least`.

---

## The really interesting extension: baseline paths

Parent chains alone are insufficient.

Consider:

```text
services.exe
   └─ svchost.exe
```

Perfect process chain.

But:

```text
Image:
C:\Users\bob\AppData\Roaming\svchost.exe
```

changes everything.

So your baseline format should eventually support:

```json
{
  "processes": {
    "lsass.exe": {
      "parents": ["wininit.exe"],
      "paths": [
        "\\Windows\\System32\\lsass.exe"
      ],
      "session": [0]
    },

    "services.exe": {
      "parents": ["wininit.exe"],
      "paths": [
        "\\Windows\\System32\\services.exe"
      ],
      "session": [0]
    },

    "svchost.exe": {
      "parents": ["services.exe"],
      "paths": [
        "\\Windows\\System32\\svchost.exe"
      ]
    }
  }
}
```

Now you can generate independent signals:

```text
unexpected_parent
unexpected_image_path
unexpected_session
```

And combine them.

---

## This gives you a very nice forensic result

Suppose RAM contains:

```text
PID   4932
Name  svchost.exe
PPID  812
```

and:

```text
PID 812 = services.exe
```

Process chain:

```text
services.exe → svchost.exe
```

Normal.

But analysis finds:

```text
Path:
C:\Users\jsmith\AppData\Local\svchost.exe

Session:
2

Malfind:
yes

Remote:
185.x.x.x:443
```

Your result becomes:

```text
PROC-0012 CRITICAL
Possible masqueraded/injected svchost process

Evidence:
 ✓ Expected parent relationship
 ✗ Image located in user-writable directory
 ✗ Interactive session
 ✗ Executable private memory
 ✗ External network connection

PID: 4932
PPID: 812
```

Notice the **expected relationship isn't used as proof of benignity**.

That's exactly what you want.

---

## CLI-wise, I'd make it look like this

Your normal workflow stays:

```text
v4ag triage --image E:\evidence\host.raw
```

Then:

```text
v4ag analyze output\host
```

uses built-in detection knowledge.

For corporate baselines:

```text
v4ag analyze output\host ^
    --baseline baselines\workstation.json
```

Or both:

```text
v4ag analyze output\host ^
    --baseline baselines\windows11.json ^
    --baseline baselines\corporate.json
```

Although I'd probably make the Windows invariants built-in rather than requiring a file.

---

## And you already support the combined workflow

There's an especially relevant part of your current `cmd_triage()`.

After writing all plugin outputs and the run manifest, it checks:

```python
if getattr(args, "follow_up", False):
```

and then invokes the same `cmd_analyze()` used by the standalone analyzer against the just-generated triage folder.

So architecturally you already have:

```text
TRIAGE ONLY

v4ag triage ...
       │
       └── Volatility extraction

TRIAGE + ANALYSIS

v4ag triage ... [follow-up option]
       │
       ├── Volatility extraction
       │
       └── cmd_analyze()
                │
                ├── correlate
                ├── detect
                └── targeted follow-up

ANALYSIS ONLY

v4ag analyze output\...
```

That's exactly the architecture I'd want.

---

## What I would add to the repository

I would evolve it roughly into:

```text
app/
├── analysis.py
├── rules.py
│
├── baselines/
│   ├── __init__.py
│   ├── loader.py
│   └── windows.json
│
├── rules/
│   └── default.json
│
└── ...
```

Keep the responsibilities very explicit:

```text
analysis.py
    Evidence correlation
    Process graph creation
    Signal derivation

baselines/
    What's expected

rules/
    What combinations of signals are concerning

followup.py
    What evidence to gather next
```

I would **not put detection severity into the baseline**.

The baseline says:

```text
svchost → services
```

Analysis says:

```text
this one violates that expectation
```

Rules say:

```text
unusual parent + malfind = HIGH
```

That separation will pay off enormously later.

---

## The first version I'd implement

Don't try to baseline everything at once.

I'd make v1 specifically **Process Relationship Analysis**.

Add about 6–8 signals:

```text
unexpected_system_parent
office_spawned_shell
office_spawned_script
browser_spawned_shell
service_spawned_user_path
user_writable_process_image
encoded_powershell
suspicious_lolbin_chain
```

And combine them with signals you already have:

```text
malfind
hollow
ghosted
suspicious_thread
peb_masquerade
network_external
psscan_only
```

The existing curated triage set already collects most of the evidence needed: process listings/tree/scan, command lines, sessions, SIDs/privileges/environment, network state, injection/VAD data, modules, malware-focused plugins, services, handles and other objects.

So this is largely an **analysis-layer enhancement**, not a Volatility execution redesign.

The end state I'd aim for is:

```text
v4ag analyze output\host

Process analysis
──────────────────────────────────────────

CRITICAL  PROC-0001
powershell.exe PID 4220
WINWORD.EXE → cmd.exe → powershell.exe

    Office-originated shell
    Encoded command line
    Executable private memory
    External connection 91.x.x.x:443

HIGH      PROC-0002
svchost.exe PID 7720
services.exe → svchost.exe

    Parent relationship normal
    Image path anomalous
    Suspicious thread
    External connection

MEDIUM    PROC-0003
rundll32.exe PID 9182

    User-writable DLL loaded
```

That would make `volatility4airgap` much more than a convenient Volatility wrapper: **triage becomes evidence acquisition, and analyze becomes a reproducible memory-forensics detection and hypothesis-generation engine.**

The present codebase is already close to that design.
