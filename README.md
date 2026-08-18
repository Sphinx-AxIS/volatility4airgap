# Volatility4AirGap

A portable Volatility3 triage tool for air-gapped Windows workstations.

Runs Volatility3 against a memory image, writes one file per plugin, then correlates
those outputs into a prioritised list of findings and collects the evidence an examiner
would ask for next.

When the kernel symbols are missing it prints the exact Microsoft symbol-server URL and
the exact ISF filename Volatility needs. Fetch the symbols on an internet-connected
machine, carry them back, re-run the same command.

Installs nothing. Needs no Python on the target and no administrator rights.

## Status

**0.5.0b1 — beta.** Feature complete, and run against real captures on an air-gapped
Windows x64 workstation. Two false positives found that way have been fixed, and the
sample of distinct images is still small, so read findings as a prioritised worklist
rather than a conclusion.

What has to be true before a production release candidate is set out in
[docs/RELEASE-CRITERIA.md](docs/RELEASE-CRITERIA.md).

| | |
| --- | --- |
| `triage` | runs the plugin set against an image and writes one file per plugin per format |
| `analyze` | correlates a finished run into findings, and collects the follow-up evidence |
| `strings` | writes every string in the image with its true offset, for `windows.strings` |
| `strings-hits` | searches a strings file for your terms, corrects wrapped offsets, and asks the plugin who holds each hit |
| `symbols` | identifies the kernel, reports URLs, writes `symbol_request.json` |
| `fetch-symbols` | downloads and converts symbols on the connected side |
| `verify` | checks a request is satisfied before you walk back |
| `check` | verifies a bundle against the digests recorded at build time |
| `doctor` | reports build identity, architecture and import health |

Design: [docs/plans/2026-08-05-portable-memory-triage-design.md](docs/plans/2026-08-05-portable-memory-triage-design.md)

## The workflow

On the air-gapped workstation:

```
v4ag.bat triage --image E:\evidence\image.raw --jobs 4
```

Results land in `output\<image>\` as `windows.pslist.PsList.csv` and `.json`, one pair
per plugin, alongside `run-manifest.json` recording the image digest, every plugin's
outcome and a SHA-256 for each output. Per-plugin logs go to `output\<image>\logs\`.

If symbols are missing, `triage` stops before running anything and writes the request. To
see what is needed without starting a run:

```
v4ag.bat symbols --image E:\evidence\image.raw
```

```
ntkrnlmp.pdb  GUID AF550CAA73AFB287705CC40079D786B4  age 1
  status    MISSING
  download  http://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/AF550CAA73AFB287705CC40079D786B41/ntkrnlmp.pdb
  fallback  http://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/AF550CAA73AFB287705CC40079D786B41/ntkrnlmp.pd_
  place at  symbols/windows/ntkrnlmp.pdb/AF550CAA73AFB287705CC40079D786B4-1.json.xz
```

Note that the URL segment and the ISF filename are *not* the same string. The URL
concatenates the GUID and age; the filename joins them with a hyphen. Getting this wrong
produces a symbol file Volatility silently ignores.

Copy the resulting `symbols/` folder back and re-run.

### After the run

`triage` records what the plugins said. `analyze` works out which of it matters:

```
v4ag.bat analyze output\image
```

It reads the JSON that run wrote, correlates rows across plugins into one record per
process, kernel module and service, and applies a rule pack. Findings land in
`output\image\findings\` — as JSON for machines, CSV for a spreadsheet, and text to
read — each one naming the rule that produced it and the plugin rows that triggered it.

No memory image is needed, so this can run against an archived output folder days later
on a different machine. Give it `--image` as well and it also runs the targeted, scoped
Volatility commands the findings imply, filing the results under
`output\image\followup\`.

Exit codes: `0` success, `1` plugin failures or no kernel found, `2` bad input,
`3` symbols missing, `4` probe failed, `5` evidence does not match the triage run,
`6` plugin output does not match `run-manifest.json`.

### Choosing plugins

```
v4ag.bat triage --image ... --plugins network,registry     # by category
v4ag.bat triage --image ... --plugins windows.pslist.PsList
v4ag.bat triage --image ... --all                          # every Windows plugin
v4ag.bat triage --image ... --format json                  # one format, half the work
```

The default is a curated 39-plugin Windows triage set.

### Formats and speed

Two separate knobs, often confused because both affect how long a run takes.

`--format` selects which of `csv` and `json` to write, and defaults to both. Each format
is a separate Volatility run, so the default renders every plugin twice — dropping one
halves the work.

**Drop `csv`, not `json`.** `analyze` reads the JSON and never the CSV, so a CSV-only
folder cannot be analysed; it refuses and tells you to re-run. CSV is for reading and for
feeding other tools, JSON is the machine interface, and keeping both is only worth the
second pass if something downstream consumes the CSV.

`--jobs` is unrelated to output: it sets how many plugins run concurrently, and defaults
to 1. Parallelism helps on NVMe with enough RAM to cache the image, and can *hurt* on a
USB-attached evidence drive where workers contend for the same reads.

## Building

The build runs on Windows, macOS or Linux and always produces the same Windows x64
bundle. It never compiles anything: `volatility3` and its dependencies are either
pure-Python or ship prebuilt `win_amd64` wheels, and `pip` is asked for those explicitly
via `--platform`. The host only downloads and arranges files, so it does not have to be
— and does not have to match — the machine the bundle will run on.

On Windows, substitute `py` for `python3`:

```
python3 tools/build_portable.py                     # full bundle, ~875 MB with symbol pack
python3 tools/build_portable.py --lean              # ~75 MB, no symbol pack
python3 tools/build_portable.py --check build/...   # verify a bundle against its manifest
```

Two builds of the same inputs produce the same `payload_sha256` whichever host made
them, so an approval authority can rebuild on their own platform and compare.

Add `--vol-exe path/to/volatility3.exe` to include the official binary for the `exe`
engine.

The bundle contains an embedded CPython, so nothing is installed on the target and no
administrator rights are needed. The archive differs between builds only by the build
timestamp in `BUILD-MANIFEST.json`, which also records the host that made it.

## Tests

```
python3 -m pytest
```

The suite needs neither Windows nor a memory image. Where it matters, behaviour is checked
against the real `volatility3` library rather than against our own assumptions — install
the `dev` extra to enable those.

## Repository notes

The build script downloads the embedded Python distribution, the Python wheels, and the
Volatility symbol pack. None of these are committed — see [.gitignore](.gitignore). The
official `volatility3.exe` is likewise ignored by default; if you need it vendored for a
disconnected build, `git add -f` it.

## Origin

Extracted and rewritten from the memory-forensics portions of CORE-Respond. Two defects
in the original are fixed by construction: an ISF filename that could never match, and an
unreachable subprocess timeout. Both are documented in the design.
