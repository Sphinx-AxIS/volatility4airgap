# Volatility4AirGap

A portable Volatility3 triage tool for air-gapped Windows workstations.

Runs Volatility3 against a memory image, writes one CSV and one JSON per plugin, and —
when the kernel symbols are missing — prints the exact Microsoft symbol-server URL and the
exact ISF filename Volatility needs. Fetch the symbols on an internet-connected machine,
carry them back, re-run the same command.

Installs nothing. Needs no Python on the target and no administrator rights.

## Status

Feature complete.

| | |
| --- | --- |
| `triage` | runs plugins, one CSV and one JSON each, with `--jobs` |
| `symbols` | identifies the kernel, reports URLs, writes `symbol_request.json` |
| `fetch-symbols` | downloads and converts symbols on the connected side |
| `verify` | checks a request is satisfied before you walk back |
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

Exit codes: `0` success, `1` plugin failures or no kernel found, `2` bad input,
`3` symbols missing, `4` probe failed.

### Choosing plugins

```
v4ag.bat triage --image ... --plugins network,registry     # by category
v4ag.bat triage --image ... --plugins windows.pslist.PsList
v4ag.bat triage --image ... --all                          # every Windows plugin
v4ag.bat triage --image ... --format csv                   # skip JSON, halves the work
```

The default is a curated 29-plugin Windows triage set. Each requested format is rendered
by its own Volatility run, so `--format csv,json` runs each plugin twice; narrow it if
wall-clock matters more than having both.

`--jobs` defaults to 1. Parallelism helps on NVMe with enough RAM to cache the image, and
can *hurt* on a USB-attached evidence drive where workers contend for the same reads.

## Building

The Windows x64 bundle is built on macOS or Linux. No Windows machine is required —
`volatility3` and its dependencies are either pure-Python or ship prebuilt `win_amd64`
wheels, so nothing needs compiling.

```
python3 tools/build_portable.py                     # full bundle, ~875 MB with symbol pack
python3 tools/build_portable.py --lean              # ~75 MB, no symbol pack
python3 tools/build_portable.py --check build/...   # verify a bundle against its manifest
```

Add `--vol-exe path/to/volatility3.exe` to include the official binary for the `exe`
engine.

The bundle contains an embedded CPython, so nothing is installed on the target and no
administrator rights are needed. Two builds produce the same `payload_sha256`; the archive
itself differs only by the build timestamp in `BUILD-MANIFEST.json`.

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
