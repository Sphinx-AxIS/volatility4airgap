# Volatility4AirGap

A portable Volatility3 triage tool for air-gapped Windows workstations.

Runs Volatility3 against a memory image, writes one CSV and one JSON per plugin, and —
when the kernel symbols are missing — prints the exact Microsoft symbol-server URL and the
exact ISF filename Volatility needs. Fetch the symbols on an internet-connected machine,
carry them back, re-run the same command.

Installs nothing. Needs no Python on the target and no administrator rights.

## Status

Design approved; implementation not yet started.
See [docs/plans/2026-08-05-portable-memory-triage-design.md](docs/plans/2026-08-05-portable-memory-triage-design.md).

## The workflow

On the air-gapped workstation:

```
v4ag.bat triage --image E:\evidence\image.raw --jobs 4
```

If symbols are missing, the tool stops and writes `symbol_request.json` containing the
download URL and the required ISF path. On an internet-connected machine:

```
v4ag.bat fetch-symbols symbol_request.json
```

Copy the resulting `symbols/` folder back, re-run the first command, and it proceeds.

## Building

The Windows x64 bundle is built on macOS or Linux. No Windows machine is required —
`volatility3` and its dependencies are either pure-Python or ship prebuilt `win_amd64`
wheels, so nothing needs compiling.

```
python3 tools/build_portable.py            # full bundle, ~820 MB with symbol pack
python3 tools/build_portable.py --lean     # ~20 MB, no symbol pack
```

## Repository notes

The build script downloads the embedded Python distribution, the Python wheels, and the
Volatility symbol pack. None of these are committed — see [.gitignore](.gitignore). The
official `volatility3.exe` is likewise ignored by default; if you need it vendored for a
disconnected build, `git add -f` it.

## Origin

Extracted and rewritten from the memory-forensics portions of CORE-Respond. Two defects
in the original are fixed by construction: an ISF filename that could never match, and an
unreachable subprocess timeout. Both are documented in the design.
