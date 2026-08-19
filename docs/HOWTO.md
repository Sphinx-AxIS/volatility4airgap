# Volatility4AirGap — HOWTO

A portable Volatility3 triage tool for air-gapped Windows workstations. Nothing is
installed; the bundle carries its own Python interpreter. No administrator rights are
needed.

Run everything through `v4ag.bat` from the bundle folder.

---

## Contents

1. [Extracting the bundle](#extracting-the-bundle)
2. [The 60-second version](#the-60-second-version)
2. [The two-machine workflow](#the-two-machine-workflow)
3. [Command reference](#command-reference)
4. [Choosing plugins](#choosing-plugins)
5. [Speed and `--jobs`](#speed-and---jobs)
6. [What you get out](#what-you-get-out)
7. [Exit codes](#exit-codes)
8. [Worked examples](#worked-examples)
9. [Troubleshooting](#troubleshooting)
10. [Why the symbol filename matters](#why-the-symbol-filename-matters)

---

## Extracting the bundle

Prefer PowerShell over Explorer's right-click "Extract All":

```powershell
cd C:\vol3work
certutil -hashfile Volatility4AirGap.zip SHA256    # compare with the .sha256 sidecar
Expand-Archive -Path .\Volatility4AirGap.zip -DestinationPath . -Force
```

Explorer's built-in zip handling has been observed to extract this bundle
incorrectly, placing one file's contents under another file's name — which then
surfaces as an unrelated error somewhere downstream. `Expand-Archive` does not.

Always verify the archive hash *before* extracting. A partial or corrupt copy extracts
without complaint.

Extract to a clean folder. If an older bundle is already there, delete it rather than
merging — Explorer's "skip these files" prompt will silently keep stale copies.

Confirm you have a current bundle: the folder should contain `cache`, `output` and
`BUILD-FILES.sha256` alongside `app`, `lib`, `python` and `v4ag.bat`. Then:

```bat
v4ag.bat check
```

---

## The 60-second version

```bat
cd C:\vol3work\Volatility4AirGap

v4ag.bat doctor                                    :: is the bundle healthy?
v4ag.bat triage --image E:\evidence\image.raw      :: run the triage set
```

If symbols are missing, `triage` stops before running anything and writes
`symbol_request.json`. Take that file to a machine with internet:

```bat
v4ag.bat fetch-symbols symbol_request.json
```

Copy the resulting `symbols\` folder back into the bundle, then re-run the same `triage`
command. That is the whole loop.

---

## The two-machine workflow

```
AIR-GAPPED HOST                          INTERNET-CONNECTED HOST
───────────────                          ───────────────────────
v4ag.bat triage --image ...
   │
   ├─ symbols present ──► runs plugins, done
   │
   └─ symbols missing
         │
         writes symbol_request.json
         │
         ══════ carry the file across ══════►
                                          v4ag.bat fetch-symbols symbol_request.json
                                             │
                                             downloads PDB from Microsoft
                                             converts to ISF
                                             writes symbols\
                                             │
         ◄═════ carry symbols\ back ═══════
         │
   v4ag.bat verify symbol_request.json   (optional: check before walking back)
         │
   v4ag.bat triage --image ...           ► runs plugins
```

The request file is self-contained. `fetch-symbols` needs nothing else — not the image,
not the original host.

---

## Command reference

### `triage` — run plugins against an image

The main command.

| Option | Default | What it does |
| --- | --- | --- |
| `--image PATH` | *required* | The memory image to analyse |
| `--plugins LIST` | triage set | Comma-separated plugin names and/or categories |
| `--all` | off | Run every discovered Windows plugin instead |
| `--format LIST` | `csv,json` | Which of `csv` and `json` to write. `--format json` for JSON only, `--format csv` for CSV only. Each format is a separate Volatility run, so one format halves the work. **`analyze` reads JSON and never CSV**, so do not drop `json` if you intend to analyse the results |
| `--jobs N` | `1` | Plugins to run concurrently. `auto` picks 1–4 |
| `--engine NAME` | `auto` | `library`, `exe`, or `auto` |
| `--out DIR` | `output\<image>` | Where results go |
| `--symbols DIR` | `symbols\` | Where to look for ISF symbol files |
| `--timeout SECONDS` | `3600` | Per-plugin limit before the process is killed |
| `--pagefile PATH` | none | Include a pagefile as a swap layer; repeat for several |
| `--no-hash` | off | Skip the custody SHA-256 of the image |
| `--force` | off | Run even if symbols are missing or the probe fails |
| `--follow-up` | off | Analyse the results afterwards and collect the follow-up evidence |
| `--output PATH` | cwd | Where to write `symbol_request.json` if symbols are missing |

`--follow-up` runs the same analyser as `analyze` on the folder just written, with the
image and any `--pagefile` already to hand. Useful when you have one shot at the machine; `analyze` on its own
is the better tool once the output folder exists, because it re-runs in seconds.

### `analyze` — turn a finished run into findings

Reads the JSON `triage` wrote, correlates it into one record per process, and applies a
rule pack. Give it a triage output folder, not an image:

```bat
v4ag.bat analyze output\WS01
```

That needs no memory image, so it can be run against an archived output folder — on a
different machine, days later, as often as you like. Add `--image` and it also runs the
follow-up Volatility commands the findings imply, filed under `followup\PID-<n>\`.

| Option | Default | What it does |
| --- | --- | --- |
| `output_dir` | *required* | A triage output directory |
| `--image PATH` | none | The image that was triaged. Supply it to run the follow-ups too |
| `--rules PATH` | bundled pack | Rule pack to apply |
| `--validate-rules` | off | Check a rule pack and exit without analysing |
| `--max-followups N` | `10` | Entities to follow up, most severe first |
| `--dump` | off | Also execute dump actions (see the warning below) |
| `--jobs N` | `1` | Follow-ups to run concurrently. `auto` picks 1–4 |
| `--engine NAME` | `auto` | `library`, `exe`, or `auto` |
| `--symbols DIR` | `symbols\` | Where to look for ISF symbol files |
| `--timeout SECONDS` | `3600` | Per-task limit before the process is killed |
| `--pagefile PATH` | from manifest | Where the run's pagefile lives now, if it has moved |
| `--no-pagefile` | off | Run follow-ups without the swap layer triage used |
| `--allow-modified-input` | off | Analyse plugin output that no longer matches the manifest |
| `--no-hash` | off | Skip checking the image and pagefiles against the manifest |

**Three things are checked before a follow-up runs**, because evidence gathered against
the wrong inputs is worse than no evidence at all.

*The plugin output.* `run-manifest.json` records a SHA-256 for every file the run
produced. Those are checked before anything is read, so the findings can be tied to the
exact bytes triage attested to. A file that has changed, or one added afterwards and
never recorded, stops the run with exit code 6. `--allow-modified-input` overrides that,
and the override itself is recorded in `analysis-manifest.json`.

*The image.* Checked against the SHA-256 in `run-manifest.json`. A mismatch stops the
run: the findings describe a different capture, so PID 4180 there means something else
here.

*The pagefile.* If triage used `--pagefile`, the follow-up uses the same one, verified by
digest. This matters more than it looks. A VAD, DLL or handle that resolved during triage
only because the swap layer supplied the paged-out bytes will simply be missing from a
follow-up run without it — so the targeted collection would quietly contradict the
finding that asked for it. If the file has moved, point at it with `--pagefile`. If you
genuinely cannot supply it, `--no-pagefile` proceeds and says what is being given up.

**On `--dump`.** Dump actions write process executables and VAD contents to disk. Two
consequences on a live workstation: a dumped malicious PE will very likely be
quarantined by endpoint protection while the run is in progress, and VAD dumps of a
large process run to gigabytes. Dumps are therefore planned and recorded in
`next-steps.json` but not executed unless you ask.

A rule pack named `rules.json` sitting in the output folder is used in preference to the
bundled one, which is reported at the top of the run and recorded in every finding.

**What it looks at.** Rules run against three kinds of thing, and a finding's identifier
says which: `PROC-` for a process, `KERN-` for a kernel module or driver, `SVC-` for a
service. The shipped pack has 28 rules across all three — process injection and
hiding, kernel modules missing from the loaded list, SSDT hooks, unbacked drivers, and
services that are hidden, run from a user-writable path, or are hosted by a process with
injected code in it.

### `strings` — write every string in the image, with its true offset

`windows.strings.Strings` does one thing no other plugin does: given a strings file it
says which process, kernel region or free page each string sits in. It does not make the
strings file; this command does.

```bat
v4ag.bat strings --image E:\evidence\WS01.raw
```

Writes `output\WS01\strings\WS01.strings` — one `offset:string` line per string, ASCII and
UTF-16, decimal offsets — and a small `.json` beside it recording how it was made. On a
25 GB image expect several minutes and a file of a few gigabytes; progress is printed as
it goes.

| Option | Default | What it does |
| --- | --- | --- |
| `--image PATH` | *required* | The memory image |
| `--out DIR` | `output\<image>` | Results directory; the file goes in its `strings\` folder |
| `--min-length N` | `4` | Shortest string to keep, in characters |
| `--encoding NAME` | `both` | `ascii`, `unicode` (UTF-16LE), or `both` |
| `--overwrite` | off | Replace an existing strings file |

**Why not Sysinternals `strings.exe`?** You can — `strings-hits` reads its output too —
but on an image over 4 GiB its `-o` offsets are 32-bit and wrap: a string at 27 GB is
reported at 27 GB minus six times 4 GiB. That is not an error the plugin can see. The
wrapped offset lands on a real page in the low 4 GiB, owned by some real process, and the
string is attributed to that process with nothing to say it is wrong. This command's
offsets are exact at any size, and `strings-hits` detects and corrects the wrapped kind
if that is what you have.

### `strings-hits` — who holds each string you care about

The plugin loads its entire input into memory and emits a row for every line, so it is
never fed a whole strings file. This searches one for your terms, checks each hit against
the image, and runs the plugin on just those lines:

```bat
v4ag.bat strings-hits --image E:\evidence\WS01.raw --term evil.example.com --term "net use Z:"
```

```
Searching WS01.strings (2.06 GB) for 2 term(s)...
  71,203,455 line(s); 212 matched
Checking each hit against WS01.raw...
  178 hit(s) are not where their offsets say, but exactly a multiple of 4 GiB further on: the file has 32-bit offsets,
  as Sysinternals strings.exe writes them. Using where the bytes actually are.
  31 hit(s) at their stated offset
  3 hit(s) not in the image at any candidate offset; kept out of the plugin's input, listed in strings-hits-unresolved.txt
Wrote output\WS01\strings\strings-hits.txt (215 line(s))

Running windows.strings.Strings on 215 line(s) (engine library; the reverse map takes a while on a large image)...
  ok (312.4s)

Process 4180 powershell.exe  (58 hits)
       0x61b2c3d4e  HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe ...
  ...
FREE MEMORY  (120 hits)
  ...
```

Every hit is verified by reading the image at its offset — and, when the image is over
4 GiB, at each offset a 32-bit wrap could have folded onto it. A hit found only at such a
folded offset is the signature of a Sysinternals file, and the true offsets are used. A
hit found nowhere is kept out of the plugin's input rather than mis-attributed, and listed
so you can search for it by hand. If *no* hit resolves, the command tells two cases apart.
When the file's offsets are structurally those of a wrapped 32-bit copy of *this* image
(none above 4 GiB though the image is larger, the sequence restarting where it folds), the
file is most likely the right one and your terms simply landed on strings with no stable
page — a signature buffer, transient text — so it warns and suggests a term you know is
genuine, rather than stopping. Only when the offsets show no such structure is the file
taken to be for some other image, and the command stops (exit code 5).

| Option | Default | What it does |
| --- | --- | --- |
| `--image PATH` | *required* | The memory image |
| `--term TEXT` | | Text to look for, case-insensitive; repeat for several |
| `--terms-file FILE` | | Terms one per line; `#` starts a comment |
| `--strings-file PATH` | the one `strings` wrote | Any `offset:string` file — this tool's, Sysinternals', or GNU `strings -td` |
| `--case-sensitive` | off | Match case |
| `--max-hits N` | `50000` | Stop if more lines than this match; the terms are too broad |
| `--trust-offsets` | off | Skip the check; pass the file's offsets through as they are |
| `--pid PID` | all | Map only these processes — faster, but other hits then show as `FREE MEMORY` |
| `--no-run` | off | Write the hits file and stop |
| `--out DIR` | `output\<image>` | Results directory |
| `--engine`, `--symbols`, `--timeout` | as `triage` | |

Output lands in `output\<image>\strings\`: `strings-hits.txt` (what the plugin was given),
`windows.strings.Strings.json` (its full table), `strings-hits-report.txt` (the table by
owner, as printed), `strings-hits.json` (terms, counts, what was relocated, digests), and
`logs\`. If the folder also holds a triage run, process names from its `pslist` output are
shown beside the PIDs.

Two things worth knowing about the plugin itself. It works in physical addresses, which is
why this only makes sense for a raw image where file offset and physical address are the
same thing. And it maps every process's whole address space before it answers, so on a
large image the run is minutes even for a handful of lines — `--pid` narrows that when
you already know whose memory you are asking about.

### `strings-map` — attribute the whole file once, then grep

That reverse map is the whole cost, and it is the same map no matter how many strings you
look up. `strings-hits` rebuilds it for every search, which is right for one or two terms
but wasteful when you are hunting: an hour of map-building per term. `strings-map` builds it
**once**, attributes the entire strings file, and writes a grep-able CSV — after which every
term you think of costs a `findstr`, not another hour.

```
v4ag.bat strings-map --image E:\evidence\WS01.raw
...
Probing WS01.strings (2.21 GB) offsets...
  60,120,547 line(s); largest offset 24.9 GiB
Attributing all 60,120,547 line(s) with windows.strings.Strings (engine library). The
reverse map is built once — on a large image that is the slow part, tens of minutes to an hour.
Wrote output\WS01\strings\strings-map.csv (13.882 GB) in 58 min
Columns: String, Physical Address, Result (the owner, FREE MEMORY, or kernel). Grep it for
any term now — no more map builds:
  findstr /i "some.ioc" "output\WS01\strings\strings-map.csv"
```

| Option | Default | What it does |
| --- | --- | --- |
| `--image PATH` | *required* | The memory image |
| `--strings-file PATH` | the one `strings` wrote | Any true-offset `offset:string` file |
| `--force` | off | Attribute even a file whose offsets look wrapped; offsets used as written |
| `--overwrite` | off | Replace an existing `strings-map.csv` |
| `--pid PID` | all | Map only these processes — faster, other strings then show as `FREE MEMORY` |
| `--out DIR` | `output\<image>` | Results directory |
| `--engine`, `--symbols`, `--timeout` | as `triage` (timeout 4 h) | |

Because it attributes the file in one pass, it does **no** per-line offset repair — so it
needs a true-offset file, which is what `strings` writes (or GNU `strings -td`). A wrapped
Sysinternals `-o` file is refused (exit code 5): its offsets would place every string past
4 GiB on the wrong process. Regenerate with `strings`, or pass `--force` to attribute it
exactly as written if you know the offsets are sound. Each record is one physical line —
the plugin folds the source line's trailing newline into the String column and the CSV
renderer would otherwise leave it there, splitting every record across two lines, so the
command flattens it — which is what lets `findstr`/`grep` work directly. The CSV is recorded
in `strings-map.json` by size rather than digest — a whole-image run makes tens of millions
of rows, and it is a derived, greppable artifact, not evidence.

Expect the run to hold the reverse map (tens of GB) plus the whole strings file in memory at
once; it is built for a host with the RAM to spare. When you have a defined IOC list rather
than an open-ended hunt, one `strings-hits --terms-file` run gets you there without the giant
CSV: it too builds the map only once, and attributes every term's hits in that single pass.

### `symbols` — report what symbols the image needs

Use when you want the symbol answer without starting a run.

| Option | Default | What it does |
| --- | --- | --- |
| `--image PATH` | *required* | The memory image to scan |
| `--symbols DIR` | `symbols\` | Where to look for existing symbols |
| `--output PATH` | cwd | Where to write `symbol_request.json` |
| `--no-hash` | off | Skip the SHA-256 — faster on a large image |

### `fetch-symbols` — download and convert symbols

Run on the **internet-connected** machine.

| Option | Default | What it does |
| --- | --- | --- |
| `REQUEST` | *required* | Path to `symbol_request.json` |
| `--out DIR` | `symbols\` | Where to build the symbols tree |
| `--all` | off | Refetch every kernel, not only the missing ones |

### `verify` — confirm a request is satisfied

Run before walking back to the secure area, so a bad conversion costs seconds instead of
a second trip.

| Option | Default | What it does |
| --- | --- | --- |
| `REQUEST` | *required* | Path to `symbol_request.json` |
| `--symbols DIR` | `symbols\` | Symbols folder to check |

### `check` — verify the bundle is intact

Recomputes a SHA-256 for every bundled file and compares it with `BUILD-FILES.sha256`,
written at build time. Names any file that was modified or is missing.

Run it after copying the bundle between machines, and whenever anything behaves
inexplicably. Corruption on removable media is silent, and shows up as an unrelated
error somewhere downstream — a damaged `v4ag.bat` reports `'{' is not recognized as an
internal or external command`, which points nowhere useful.

Takes no options. Files you have added — symbols, output — are ignored; only what shipped
in the bundle is checked.

```bat
v4ag.bat check
```

```
Checked 1047 file(s) against BUILD-FILES.sha256
  build   built 2026-08-06T05:19:34+00:00, payload 38905d41

MODIFIED (1):
  v4ag.bat

Re-extract the bundle to a clean folder.
```

### `doctor` — check the bundle

Reports build identity, interpreter architecture, `sys.path`, and whether every required
component imports. Run this first whenever something behaves oddly.

| Option | Default | What it does |
| --- | --- | --- |
| `--symbols DIR` | `symbols\` | Also summarise what symbols are present |

### `--version`

```
v4ag 0.5.0b1 (built 2026-08-06T04:47:39+00:00, payload 0efe5162)
```

The build time and payload digest identify exactly which bundle you are running. Check
this first if a command you expect is "not a valid choice" — you are probably on an older
extract.

---

## Choosing plugins

The default is a curated 39-plugin Windows set. Everything in it is Windows-only, so no
time is wasted on Linux and macOS plugins that cannot apply.

| Category | Count | Plugins |
| --- | --- | --- |
| `system` | 1 | `info` |
| `processes` | 8 | `pslist`, `pstree`, `psscan`, `cmdline`, `sessions`, `getsids`, `privileges`, `envars` |
| `network` | 2 | `netscan`, `netstat` |
| `injection` | 2 | `malfind`, `vadinfo` |
| `modules` | 3 | `dlllist`, `modules`, `modscan` |
| `persistence` | 1 | `svcscan` |
| `registry` | 3 | `hivelist`, `printkey`, `userassist` |
| `kernel` | 4 | `driverscan`, `callbacks`, `ssdt`, `devicetree` |
| `malware` | 10 | `psxview`, `hollowprocesses`, `ldrmodules`, `processghosting`, `pebmasquerade`, `suspicious_threads`, `unhooked_system_calls`, `drivermodule`, `svcdiff`, `skeleton_key_check` |
| `objects` | 5 | `handles`, `filescan`, `mutantscan`, `symlinkscan`, `thrdscan` |

Select by category, by name, or mix the two:

```bat
v4ag.bat triage --image E:\img.raw --plugins network
v4ag.bat triage --image E:\img.raw --plugins network,registry
v4ag.bat triage --image E:\img.raw --plugins windows.pslist.PsList,windows.malfind.Malfind
v4ag.bat triage --image E:\img.raw --plugins processes,windows.netscan.NetScan
```

`--all` runs every Windows plugin Volatility exposes (91 in 2.28). Expect failures: many
plugins need conditions your image will not meet. They are recorded in the manifest and
their logs kept.

`--all` also includes `windows.dumpfiles.DumpFiles`, which with no filter carves *every*
cached file object in the image — often thousands of files, several gigabytes. These land
in a `dumps\` subfolder of the output directory (never the directory you launched from),
are summarised in the manifest as a count and total size rather than hashed one by one,
and the run tells you how many there are and where. Move or delete them once you have what
you need. To carve deliberately instead, name the plugin and target it — e.g.
`--plugins windows.dumpfiles.DumpFiles` is still untargeted, so prefer running it by hand
with `--filter <name>` or a specific `--physaddr`.

---

## Speed and `--jobs`

Two settings dominate wall-clock.

**`--format`.** Each format is rendered by its own Volatility run, so the default
`csv,json` runs every plugin **twice**. Fidelity was chosen over speed here: both files
are exactly what Volatility produces rather than one being derived from the other. If you
only need one, say so and halve the work:

```bat
:: JSON only — half the runtime, and everything `analyze` needs
v4ag.bat triage --image E:\img.raw --format json

:: CSV only — for ingest into another tool. `analyze` cannot read this folder
v4ag.bat triage --image E:\img.raw --format csv
```

**Prefer `--format json` when dropping one.** The analysis phase reads the JSON and
never the CSV, so a CSV-only folder cannot be analysed: `analyze` refuses it and tells
you to re-run the triage. CSV is for reading and for feeding other tools; JSON is the
machine interface. Keeping both is only worth the second pass if something downstream
consumes the CSV.

**`--jobs`.** Defaults to `1`. Whether more helps depends entirely on where the image
lives:

| Situation | Guidance |
| --- | --- |
| Image on internal NVMe, plenty of RAM | `--jobs 4` is a large win — the page cache absorbs repeat reads |
| Image on a USB evidence drive | Keep `--jobs 1`. Workers contend for the same reads and can run *slower* |
| Unsure | `--jobs auto` picks a conservative 1–4 |

These plugins scan the whole image and dominate a large run: `psscan`, `netscan`,
`netstat`, `malfind`, `vadinfo`, `modscan`, `svcscan`, `driverscan`, `handles`,
`filescan`, `mutantscan`, `symlinkscan`, `thrdscan`.

A quick first pass that skips all of them:

```bat
v4ag.bat triage --image E:\img.raw --plugins processes,registry,modules --format csv --jobs 4
```

---

## What you get out

```
output\<image name>\
├─ windows.pslist.PsList.csv
├─ windows.pslist.PsList.json
├─ windows.pstree.PsTree.csv
├─ ...
├─ run-manifest.json
├─ dumps\                       only if a plugin carved files (see --all)
│  └─ file.0x....ImageSectionObject.<name>.img
└─ logs\
   ├─ windows.pslist.PsList.csv.log
   └─ ...
```

After `analyze`, the same folder also holds:

```
output\<image name>\
├─ analysis-manifest.json
├─ findings\
│  ├─ findings.json          the machine interface
│  ├─ findings.csv           the same findings, as a table
│  ├─ findings.txt           the same findings, written to be read
│  └─ next-steps.json        what was planned, and whether it ran
└─ followup\
   ├─ PID-4180\
   └─ PID-7224\
```

After `strings` and `strings-hits`:

```
output\<image name>\
└─ strings\
   ├─ <image name>.strings       every string, offset:string — gigabytes
   ├─ <image name>.strings.json  how it was made
   ├─ strings-hits.txt           the lines the plugin was given, offsets verified
   ├─ strings-hits-unresolved.txt  hits found nowhere in the image, if any
   ├─ strings-hits-report.txt    the plugin's answer, by owner
   ├─ strings-hits.json          terms, counts, relocations, digests
   ├─ windows.strings.Strings.json
   └─ logs\
```

`findings.json` records, for each finding, the rule that produced it, the digest of the
rule pack in force, and the plugin rows that triggered it. It also lists the rules that
could *not* be evaluated because a plugin they need failed during triage — so an empty
findings list cannot be mistaken for a clean host.

`analysis-manifest.json` is written beside `run-manifest.json` rather than replacing it,
and records the triage manifest's SHA-256. That is what ties a set of findings to one
specific triage run.

CSV filenames match what CORE-Respond's `ingest_volatility.py` expects, so results can be
fed into it unchanged.

`run-manifest.json` records the image path and SHA-256, the kernels identified, the engine
and job count used, every plugin's outcome and duration, and a SHA-256 for every output
file — enough to attest to a run later.

**Empty outputs are deleted.** A plugin that fails can leave a zero-byte
`windows.netscan.NetScan.csv`, which in a results folder reads as "no network artefacts
found" rather than "this plugin did not run". The log is always kept, so nothing
diagnostic is lost. If a plugin you expected is absent from the output folder, check
`logs\` and the manifest.

---

## Exit codes

| Code | Meaning | What to do |
| --- | --- | --- |
| `0` | Success | — |
| `1` | Plugin failures, or no kernel found | Check `logs\` and the manifest |
| `2` | Bad input | Fix the path or option named in the error |
| `3` | Symbols missing | Run `fetch-symbols` on a connected machine |
| `4` | Probe failed | Read the diagnosis; `--force` to run anyway |
| `5` | Evidence does not match: `analyze` given a different image or pagefile than the triage run; `strings-hits` given a strings file none of whose hits is in the image and whose offsets do not look like a wrapped copy of it | Supply the image and pagefile that were triaged; check the strings file is this image's |
| `6` | Plugin output does not match `run-manifest.json` | Re-run triage, or `--allow-modified-input` |

Useful in a batch file:

```bat
v4ag.bat triage --image E:\img.raw
if %ERRORLEVEL%==3 echo Fetch symbols first.
```

---

## Worked examples

**Standard triage, symbols already present**

```bat
v4ag.bat triage --image E:\evidence\WS01.raw --jobs 4
```

**First look at an unknown image, fastest useful answer**

```bat
v4ag.bat triage --image E:\evidence\WS01.raw --plugins processes,network --format csv
```

**Find out what symbols are needed, without committing to a run**

```bat
v4ag.bat symbols --image E:\evidence\WS01.raw
```

**Complete the symbol round trip**

```bat
:: air-gapped host
v4ag.bat symbols --image E:\evidence\WS01.raw --output D:\transfer\symbol_request.json

:: connected host — the request file is all you need
v4ag.bat fetch-symbols D:\transfer\symbol_request.json --out D:\transfer\symbols

:: back on the air-gapped host, after copying symbols\ into the bundle
v4ag.bat verify D:\transfer\symbol_request.json
v4ag.bat triage --image E:\evidence\WS01.raw
```

**Exhaustive run, results to a case folder**

```bat
v4ag.bat triage --image E:\evidence\WS01.raw --all --jobs 4 --out D:\cases\IR-2026-014\WS01
```

**Hunt for injected code specifically**

```bat
v4ag.bat triage --image E:\evidence\WS01.raw --plugins injection,modules --format json
```

**Use the official Volatility binary instead of the bundled library**

```bat
v4ag.bat triage --image E:\evidence\WS01.raw --engine exe
```

**A plugin is hanging — cap it at five minutes**

```bat
v4ag.bat triage --image E:\evidence\WS01.raw --timeout 300
```

**Huge image, skip the custody hash for a quick look**

```bat
v4ag.bat symbols --image E:\evidence\64GB.raw --no-hash
```

Only skip the hash for exploratory work. For anything that may become evidence, let it
run — it costs nothing extra, because the image is being read anyway.

---

## Troubleshooting

**`invalid choice: 'fetch-symbols'`**
You are running an older extract. Check `v4ag.bat --version` against the build you meant
to deploy, and re-extract.

**`No module named app`**
The bundle folder is incomplete or was extracted oddly. `python\`, `lib\` and `app\` must
all sit beside `v4ag.bat`. Re-extract the zip.

**`No Windows kernel PDB record found`** (exit 1)
The scan found no kernel signature. Likely causes: the capture is not Windows; it is a
hibernation file or compressed crash dump rather than raw physical memory; or the file is
truncated. Check the image size looks right.

**`Volatility could not identify the image`** (exit 4)
Volatility read the file but could not establish a profile. Usually an unsupported or
damaged capture format.

**`Volatility could not load symbols`** (exit 4)
Symbols are present but not the right ones. Run `symbols` to see exactly what is wanted,
and `verify` to confirm what you have.

**Plugins succeed but every output has only a header row**
Volatility read the image but could not map its memory. The commonest cause is a
`.vmem` opened without its `.vmss`/`.vmsn` companion: Volatility selects its VMware
layer from the extension and cannot translate addresses without the metadata. Either put
the companion file beside the image with the same basename, or copy the image to a `.raw`
extension to force the raw physical layer. The tool reports this explicitly when every
plugin returns zero rows.

**A plugin fails with `needs --something, which triage does not pass`**
Nothing is missing from the bundle. Some plugins take an input of their own —
`windows.strings.Strings` wants a `--strings-file` produced beforehand,
`windows.vadregexscan.VadRegExScan` wants a `--pattern` — and Volatility refuses
to start them without it. Triage passes no per-plugin arguments, which is why none of these is in
the curated set; you meet them under `--all` or by naming one. The failure line prints
the exact command to run it by hand with a placeholder for the missing argument, and
`run-manifest.json` records the same under `diagnosis`. For `windows.strings.Strings`
specifically, the `strings` and `strings-hits` commands are the intended route: they make
the input, cut it down to the lines that matter, and run the plugin for you.

**Everything fails after copying symbols across**
Check the folder landed in the right place. The tool expects
`symbols\windows\<pdb name>\<GUID>-<age>.json.xz`. `v4ag.bat verify symbol_request.json`
answers this definitively.

**`fetch-symbols` reports some records as `unavailable` (HTTP 404)**
Not every record the scan finds is real. The scan reads raw physical memory, so it
also surfaces stale copies — freed pages from before an update, update payloads,
cached file data — and Microsoft's server has no PDB for some of those GUIDs. This
is expected and harmless: Volatility asks for exactly one kernel identity (read from
the mapped kernel, which the probe validates) and one identity per module. As long
as `fetch-symbols` ends with "Every module Volatility can ask for is covered", the
404s cost nothing. If a specific module build genuinely matters and is not on the
server, extract the matching binary from the host's disk and convert it locally:
`python -m volatility3.framework.symbols.windows.pdbconv -f <binary>`, then place
the compressed result at the `place at` path printed by `symbols`.

**`fetch-symbols` cannot reach Microsoft**
The URL is printed by `symbols`, so you can fetch the PDB with a browser on any machine.
The tool also prints a `.pd_` fallback URL; that variant is a Microsoft cabinet and needs
`expand.exe` (present on Windows) or `cabextract` to unpack.

**Runs are slower with `--jobs 4` than with `--jobs 1`**
The image is probably on slow or removable media. Every plugin streams the whole image, so
workers contend. Drop back to `--jobs 1`, or copy the image to local disk first.

**A command prints gibberish, or `'{' is not recognized as an internal or external command`**
A bundled file holds another file's contents. This has been seen with Explorer's built-in
zip extractor; re-extract with `Expand-Archive` (see [Extracting the
bundle](#extracting-the-bundle)) after verifying the archive hash. `v4ag.bat check` names
the affected files — but if `v4ag.bat` is itself damaged it cannot run, so just re-extract
to a clean folder.

**Something is wrong and I do not know what**

```bat
v4ag.bat check     :: are the files intact?
v4ag.bat doctor    :: does everything import?
```

`check` verifies every bundled file against its build-time digest. `doctor` reports the
build, the interpreter architecture, every `sys.path` entry, and whether each required
component imports. Between them they cover corrupt files, stale extracts, wrong
architecture and missing components.

---

## Why the symbol filename matters

`symbols` prints two strings that look almost identical but are not interchangeable:

```
download  .../ntkrnlpa.pdb/BD8F451F3E754ED8A34B50560CEB08E31/ntkrnlpa.pdb
                           └──────────── 33 chars ─────────┘

place at  symbols/windows/ntkrnlpa.pdb/BD8F451F3E754ED8A34B50560CEB08E3-1.json.xz
                                       └────── 32 chars ──────┘ └age┘
```

The URL segment is the GUID **concatenated** with the age. The ISF filename joins them
with a **hyphen**. Treating the 33-character URL segment as the GUID produces a file
Volatility silently ignores — no error, just symbols that never load.

`fetch-symbols` handles this for you and verifies the result. If you convert a PDB by hand
instead, get this right, and use `verify` to check.
