# Post-Triage Analysis — Design

**Date:** 2026-08-15
**Status:** Implemented

## Purpose

Turn the thirty-odd plugin outputs a triage run produces into a prioritised list of
findings, and collect the evidence an examiner would ask for next.

Triage answers "what did the plugins say". This phase answers "which process should I
look at first, and why". It reads the JSON a triage run already wrote, correlates rows
across plugins into one record per process, applies a rule pack, and writes findings
with the evidence that produced them. Given the image, it also runs targeted, PID-scoped
Volatility commands to gather what those findings imply.

The tool does not decide whether the host is compromised. It decides what to look at,
and it records why.

## Scope boundary

Triage keeps its current responsibility: run plugins, record outcomes, hash outputs,
write `run-manifest.json`. No detection logic enters `triage.py`. Analysis is a separate
command over a finished output folder, so rules can be developed and tested against
archived folders without re-running a 32 GB image.

## Decisions

| Decision | Choice |
| --- | --- |
| Command | `v4ag analyze <output-dir>`, separate from `triage` |
| Follow-up execution | Same command; runs Volatility only when `--image` is given |
| Machine interface | JSON plugin outputs, never CSV |
| Scoring | Discrete findings with provenance. No numeric maliciousness score |
| Severity | Three labels: `critical`, `high`, `medium` |
| Rules | External JSON rule packs, validated against a closed signal vocabulary |
| Rule language | Fixed combinators (`all`/`any`/`none`/`at_least`). No expression DSL |
| Dumping | Planned but not executed in v1; gated behind `--dump` |
| Entity types | Process, kernel module, service. Files remain out of scope |
| Manifest | Separate `analysis-manifest.json` referencing the triage manifest by digest |
| Dependencies | Standard library only, as with the rest of `app/` |

### Why a separate command rather than `triage --follow-up`

Rule development needs a fast loop. An `analyze` command over an existing output folder
runs in seconds against a fixture, so detection logic can be iterated without touching
a memory image. `triage --follow-up` can call the same analyser later, once the rules
have settled.

The command has two modes. Without `--image` it reads JSON and writes findings; it never
invokes Volatility. With `--image` it also executes the follow-up tasks it planned. Both
modes write `next-steps.json`, each task marked `executed: true` or `false` with a
reason, so what the tool decided to collect and what it actually collected stay
separately auditable.

### Why no numeric score

A single number invites the reader to treat 0.82 as meaningfully worse than 0.78, and it
cannot be defended in a report. A finding names its rule, its severity, and the plugin
rows that triggered it. "Why did the tool investigate PID 4180" then has an explicit
answer that survives cross-examination.

Correlation is expressed through rules rather than arithmetic. A malfind region alone is
`medium`. The same region with an external socket is `critical`. The `at_least`
combinator covers "several independent signals on one process" without summing anything.

### Why external rule packs

Rules change faster than code, and an analyst on an air-gapped host cannot rebuild the
bundle. A JSON pack is editable in place, hashable, and recorded in every finding it
produces, so a report can cite the exact rule text in force at the time.

JSON rather than YAML because `app/` depends on nothing outside the standard library and
`pyproject.toml` states so deliberately. PyYAML would be the first third-party import in
the tool, and another supply-chain item for an approval authority to consider.
`requires-python = ">=3.9"` also rules out stdlib `tomllib`. Rules carry an optional
`note` field to replace the comments JSON lacks.

No expression language. Conditions are structured data over a closed vocabulary of
signals computed in `analysis.py`:

```json
{ "id": "PROC-INJECT-NET", "severity": "critical",
  "title": "Injected process has external network activity",
  "note": "malfind alone is noisy; with an external socket it is not",
  "all": [{"signal": "malfind"}, {"signal": "network_external"}],
  "actions": ["inspect_vads", "inspect_threads", "inspect_modules"] }
```

That needs no parser and no `eval`, validates against a schema, and makes a rule naming
an unknown signal a load error rather than a rule that never fires.

## Architecture

```
app/
  analysis.py     plugin JSON -> normalised entities -> signals
  rules.py        load and validate rule packs, evaluate them, emit findings
  followup.py     findings -> Volatility tasks -> executed evidence
  engine.py       modified: plugin_args and output_dir
  rules/
    default.json  the shipped rule pack
```

Each stage has a serialisable boundary, so any stage can be tested against a fixture
without the one before it.

```
run-manifest.json + *.json
        |
        v
   analysis.py  --> entities, each carrying a set of computed signals
        |
        v
   rules.py     --> findings/findings.json, findings/findings.csv
        |
        v
   followup.py  --> findings/next-steps.json          (always written)
        |
        v  only when --image is supplied
   scheduler.run_tasks()  --> followup/PID-4180/*.json
        |
        v
   analysis-manifest.json
```

Output layout:

```
output/memory/
    run-manifest.json
    analysis-manifest.json
    findings/
        findings.json
        findings.csv
        next-steps.json
    followup/
        PID-4180/
        PID-7224/
```

### Entity model

One record per entity, keyed by identity rather than by plugin. Processes are keyed by
PID *and* offset: PsScan can surface two processes reusing a PID, and merging them
destroys evidence.

```python
@dataclass
class Process:
    pid: int
    offset: int | None
    name: str | None
    ppid: int | None
    seen_in: dict[str, list[dict]]   # plugin name -> its raw rows
    signals: set[str]
```

`seen_in` keeps raw rows rather than a summary, so a finding cites the row that
triggered it instead of re-describing it.

Column names are not stable across plugins — `PID` and `Pid`, `ImageFileName` and
`Process` and `Name` — and PsTree nests children under `__children` rather than emitting
flat rows. Some column names are not even fixed within a plugin: PsScan builds its
offset column as `f"Offset{offsettype}"`, so it is `Offset(V)` or `Offset(P)` depending
on how the scan ran, and must be matched by prefix. Each plugin therefore gets an
explicit extractor entry naming its PID column and the columns that matter. That table
is the highest-risk code in this design and carries a fixture test per plugin.

### Signal vocabulary

`analysis.py` computes a closed set; `rules.py` may reference nothing outside it.

`pslist`, `psscan`, `psscan_only`, `exited`, `malfind`, `hollow`, `ghosted`,
`peb_masquerade`, `psxview_hidden`, `suspicious_thread`, `ldrmodules_unlinked`,
`network`, `network_external`, `unusual_parent`.

`psscan_only` means present in PsScan, absent from PsList, **and** carrying no exit
time. Without that last clause the signal fires on every cleanly terminated process and
becomes noise on a busy host.

`windows.malware.psxview.PsXView` already performs a cross-view comparison and is in the
triage set. Its verdict is consumed as `psxview_hidden` rather than re-derived. The
independently computed `psscan_only` is kept as a cross-check; disagreement between the
two is itself worth reporting.

### Shipped rules

Eight, chosen for confidence rather than coverage.

| Rule | Severity | Condition |
| --- | --- | --- |
| `PROC-INJECT-NET` | critical | `malfind` and `network_external` |
| `PROC-THREAD-INJECT` | critical | `malfind` and `suspicious_thread` |
| `PROC-HIDDEN` | high | `psscan_only` |
| `PROC-HOLLOW` | high | `hollow` |
| `PROC-GHOST` | high | `ghosted` |
| `PROC-XVIEW` | high | `psxview_hidden` |
| `PROC-MULTI-SIGNAL` | high | at least 3 of six independent signals |
| `PROC-INJECT` | medium | `malfind` alone |

### Finding record

```json
{
  "finding_id": "PROC-0042",
  "rule_id": "PROC-INJECT-NET",
  "rules_sha256": "c41e...",
  "severity": "critical",
  "entity": { "type": "process", "pid": 4180, "offset": 1234567,
              "name": "powershell.exe" },
  "evidence": [
    { "plugin": "windows.malware.malfind.Malfind",
      "reason": "executable private VAD", "row": { } },
    { "plugin": "windows.netscan.NetScan",
      "reason": "outbound connection to 203.0.113.4:443", "row": { } }
  ],
  "recommended_actions": ["inspect_vads", "inspect_threads", "inspect_modules"]
}
```

## The engine change

Two keyword arguments, in the right argv positions:

```python
def command(self, image, plugin, renderer, *, symbols_dir=None, cache_dir=None,
            offline=True, parallelism="off", swap_files=None,
            output_dir=None,      # emits -o in the GLOBAL block, before the plugin
            plugin_args=None):    # appended AFTER the plugin name
```

`-o` is a global Volatility option and must precede the plugin name. `--pid` belongs to
the plugin and must follow it. Both facts were verified against volatility3 2.28.0.

`pid` is a `ListRequirement`, so argparse gives it `nargs='+'` and it consumes every
following token. Nothing may be appended after `plugin_args`. This is the same hazard the
`--single-swap-locations` comment in `engine.py` already records, and it gets the same
treatment: a comment at the point of risk and a test asserting argv order.

`output_dir` exists because `--dump` writes files to the process working directory, and
`scheduler.launch()` passes no `cwd` to `Popen`. Without `-o` there is no way to place
dumped artefacts in `followup/PID-4180/`.

## Follow-ups

| Action | Tasks |
| --- | --- |
| `inspect_vads` | `VadInfo --pid N` |
| `inspect_modules` | `DllList --pid N`, `LdrModules --pid N` |
| `inspect_threads` | `SuspiciousThreads --pid N` |
| `inspect_context` | `PsTree`, `CmdLine`, `GetSIDs`, `Privs`, `Handles`, each `--pid N` |
| `dump_process`, `dump_vads` | planned, `executed: false`, `reason: "requires --dump"` |

`NetScan` and `ThrdScan` accept no `--pid`. Network and thread-scan correlation is
therefore done by filtering the triage JSON already on disk, never by re-running.

Handles is one of the slow whole-image scanners. Scoped to a PID it becomes cheap, which
is most of the reason targeted re-running beats re-reading.

Execution reuses `scheduler.run_tasks()` unchanged — same timeout, same fault isolation,
same discipline of writing child output to files rather than pipes. `followup.py` only
builds `Task` objects.

Follow-ups are capped by `--max-followups`, default 10 entities, highest severity first.
Exceeding the cap is reported, never silently truncated.

### Why dumping waits

`--dump` writes process executables and VAD contents to disk. Two problems in v1: a
dumped malicious PE lands unquarantined on the analyst's workstation, where endpoint
protection will remove it mid-run and break the output; and VAD dumps of a large process
run to gigabytes. Both are manageable, neither is worth solving before the rules are
proven. Dump actions are planned and recorded, and `--dump` executes them.

## Manifest and provenance

`analysis-manifest.json` sits beside `run-manifest.json` and records:

- the triage manifest's SHA-256, binding findings to one triage run
- the rule pack's SHA-256, version and path
- counts of findings by severity
- plugins the rules could not evaluate, and why
- SHA-256 for every file under `findings/` and `followup/`

A separate manifest rather than a rewritten one. `manifest.build()` hashes every file
under the output directory, so writing `findings/` into that tree makes the existing
`run-manifest.json` incomplete the moment analysis runs. Referencing it by digest is also
the stronger claim: it proves which triage run the findings came from.

`app/rules/default.json` needs no build change. `copy_app()` in
`tools/build_portable.py` copies the tree whole, and the filelist digests everything
under the bundle root, so `v4ag check` verifies the rule pack alongside the code.

## Guidance output

Every stage where the analyst must do something says what to do, following the precedent
`probe_diagnosis()` sets in `triage.py`.

| Condition | Message |
| --- | --- |
| Folder has CSV only | `Analysis needs JSON. Re-run: v4ag triage --image <img> --format csv,json` |
| A plugin's JSON is missing or failed | Names the plugin, its log file, how many rules cannot be evaluated, and the command to re-run that plugin alone |
| Every plugin returned zero rows | Reuses `layer_warning()`, plus `Findings from this run are not trustworthy.` |
| Columns do not match the extractor | `<plugin> has no recognised PID column (volatility version drift?). Skipping.` Named and counted, never silent |
| `--validate-rules` | Per error: rule index, rule id, what is wrong, and the nearest valid signal name |
| A local pack overrides the shipped one | Names the path and digest, and states that findings will record it |
| A rule's plugin is absent from the run | Rule listed under `not_evaluated` in `findings.json` |
| No rules matched | `No rules matched. 34 plugins evaluated, 0 skipped.` Distinguishes clean from could-not-look |
| Findings exist, no `--image` | `12 follow-up tasks planned but not run. Execute with: v4ag analyze <dir> --image <img>` |
| `--image` digest differs from the manifest | Refuses. `This image is not the one triaged (sha256 mismatch).` |
| Cap exceeded | `23 entities elevated; following up on the top 10. Raise with --max-followups 23.` |
| Dumps planned | States how many, that `--dump` executes them, and that endpoint protection may quarantine the results |
| A follow-up plugin fails | Logged per task as in triage; the run continues and the failure is named in the manifest |

A silently skipped plugin becomes a false negative, and in this tool that is the
expensive kind of wrong. Nothing is dropped without saying so.

## Testing

Three layers, one per pipeline boundary, so a failure names its own stage.

**`test_analysis.py`** — table-driven extractor cases: a JSON row in, expected entity
fields out, one case per plugin in the map. Covers PsTree's `__children` nesting and a
row with an unrecognised PID column, asserting it is reported and counted.

**`test_rules.py`** — pure evaluation over synthetic entities with hand-set signals. No
I/O. Plus schema validation: unknown signal, unknown combinator, missing `id`, duplicate
`id`.

**`test_followup.py`** — findings in, exact argv out. Asserts `-o` precedes the plugin
name, `--pid` follows it, and nothing follows `--pid`.

Two consistency tests keep the pack and the code together:

- Every `signal` in `default.json` exists in the vocabulary, and every `action` has an
  implementation. A typo becomes a failed test rather than a rule that never fires.
- Following the pattern `plugins.py` already uses: every plugin in the extractor map
  still exists in the installed volatility3 and still accepts `--pid`. An upstream
  rename surfaces as a red test rather than an empty follow-up folder.

`tests/fixtures/` gains a small synthetic triage folder: hand-written JSON with a dozen
processes, several carrying planted signals. Synthetic rather than captured, so no real
host data enters the repository and the expected findings are knowable by construction.
One golden test runs `analyze` over it and diffs `findings.json` against a checked-in
expected file.

## Second pass

Three of the four items originally deferred are now built. What changed:

**Three entity types, not one.** A `Module` covers the kernel surface and a `Service`
sits between module and process. Rules carry an optional `entity` field defaulting to
`process`, so a pack written against the first version still loads. The signal
vocabulary became a dict keyed by entity type, and a rule naming a signal belonging to
another type is told so by name rather than offered a spelling correction.

Module identity is normalised: `\Driver\foo` and `foo.sys` both become `foo`. Rootkits
register drivers from hidden modules, so the driver object and the module usually share
a stem. Where they genuinely differ the entities stay separate, which is right —
merging them would invent a relationship.

Finding identifiers are prefixed and numbered within their prefix: `PROC-0003` is the
third process finding, not the third finding that happens to be about a process.

**Seven more rules**, taking the pack to fifteen: SSDT hooks (critical), kernel modules
recovered by scan but absent from the loaded list, unbacked driver objects, callbacks
owned by no identifiable module, and three service rules — hidden from the service
manager, binary in a user-writable directory, and hosted by a process with injected code.

That last one needed a guard of the same kind `psscan_only` needed. A bare malfind is
why `PROC-INJECT` is only medium; propagating it to a critical service finding would
have undone the distinction. `service_host_injected` therefore requires the host to
carry a qualifying signal too — external network, suspicious thread, hollowing or
ghosting.

**Follow-up steps gained a scope.** A process is selected by `--pid`, a module by
`--name`, a service by the PID hosting it. An entity that cannot supply its step's scope
is skipped and said so, rather than running the plugin unscoped across the whole image.

**`triage --follow-up`** calls `cmd_analyze` directly, with the digest check skipped —
the image is already known to match, and re-hashing tens of gigabytes to prove it would
be absurd. A test asserts the two entry points share the one code path.

**`findings.txt`** joins the JSON and CSV: the same findings grouped by entity and
written to be read, with a section naming the rules that could not run.

## Third pass: correctness review

Four defects found in review, all of which would have mattered in real work.

**SVC-HIDDEN was dead code.** The signal assumed SvcDiff walks the registry and so
required "in SvcDiff, not in SvcScan". Upstream actually compares
`SvcScan.service_scan()` against `SvcList.service_list()` and yields only
`from_scan - from_list`. Every SvcDiff row is therefore *also* a SvcScan row, and the
condition could never be true. Presence alone is now the whole signal, renamed
`svcdiff_hidden`. Worth knowing: SvcDiff runs only on Windows 10 15063+ 64-bit and
yields nothing otherwise, which reads here the same as finding nothing.

**Follow-ups dropped the pagefile.** `analyze` had no `--pagefile`, never passed
`pagefiles=` to `build_tasks`, and `triage --follow-up` did not carry `args.pagefile`
into the chained call. So `triage --pagefile X --follow-up` triaged RAM-plus-swap and
then followed up on RAM alone. A VAD, DLL or handle that resolved only because the swap
layer supplied the paged-out bytes would be silently absent from the targeted
collection, contradicting the finding that requested it.

The set is now taken from `run-manifest.json` rather than from what the analyst types,
each file verified against its recorded digest, and the resolved paths recorded in
`analysis-manifest.json`. `--pagefile` relocates a file that has moved; `--no-pagefile`
proceeds without and states what is given up. A test asserts every `analyze` argument is
supplied by the `triage --follow-up` chain, so a new flag cannot silently default.

**Module follow-ups used a lowercased filter.** `scope_values()` returned the correlation
key, but Modules filters with `self.config["name"] not in BaseDllName` — a case-sensitive
substring test, inherited by ModScan. `--name wdf01000` matches no `Wdf01000.sys`, so the
follow-up folder comes back empty with nothing to explain it. `Module` now carries both:
`key` stays lowercased for correlation and directory naming, `scope_name` preserves case
for the filter, and a BaseDllName from Modules or ModScan always wins over a driver
object's name because it is the exact string the filter compares against.

**Plugin JSON was read without checking its digest.** The run manifest hashes every
output so a consumer can prove nothing changed, and the analyser ignored that, which made
`analysis-manifest.json` attest to findings derived from unverified bytes. `verify_inputs`
now checks each file it is about to read; a modified or unattested file fails closed with
exit code 6, `--allow-modified-input` overrides, and the override is itself recorded.

Two smaller items: `--max-followups` is validated at parse rather than at the slice, where
a negative value silently dropped the least severe entity; and `cmd_analyze` catches the
`ValueError` from `resolve_jobs` like `cmd_triage` already did.

## Still out of scope

- **File entities.** FileScan and MutantScan produce entities readily enough, but no
  rule over them clears the confidence bar the rest of the pack is held to. A path
  looking suspicious is not a finding. Left until there is something defensible to say.
- **Executed dumping by default.** The mechanism is built and `--dump` drives it; no
  shipped rule recommends a dump action, and a test fails if one starts to.
