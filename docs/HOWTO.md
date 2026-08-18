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
service. The shipped pack has 27 rules across all three — process injection and
hiding, kernel modules missing from the loaded list, SSDT hooks, unbacked drivers, and
services that are hidden, run from a user-writable path, or are hosted by a process with
injected code in it.

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
v4ag 0.1.0 (built 2026-08-06T04:47:39+00:00, payload 0efe5162)
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
| `5` | `analyze` evidence does not match the triage run | Supply the image and pagefile that were triaged |
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
