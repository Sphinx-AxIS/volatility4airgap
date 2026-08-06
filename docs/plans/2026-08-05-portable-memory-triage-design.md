# Volatility4AirGap — Design

**Date:** 2026-08-05
**Status:** Approved, not yet implemented

## Purpose

Give an analyst a portable tool that runs Volatility3 against a memory image on an
air-gapped Windows workstation, writes one CSV and one JSON per plugin, and — when the
kernel symbols are missing — prints the exact Microsoft symbol-server URL and the exact
ISF filename Volatility requires. The analyst fetches the symbols on an
internet-connected machine, carries them back, and re-runs the same command.

The tool installs nothing. It requires no Python on the target and no administrator
rights.

## Origin

Extracted from the CORE-Respond project, which had the right workflow buried inside a
FastAPI service bound to Postgres:

| Reused from | For |
| --- | --- |
| `src/api/routes/volatility.py:405-484` | Per-plugin runner loop and continue-on-failure |
| `src/api/routes/volatility.py:86-142` | Plugin discovery via the vol3 Python API |
| `tools/generate_isf.sh` | The two-machine symbol workflow (logic rewritten) |

Two defects in that code are fixed here by construction, not by patching. Both are
covered in "Defects corrected" below.

## Decisions

| Decision | Choice |
| --- | --- |
| Packaging | Portable folder plus `.bat` launcher, not a single `.exe` |
| Build host | macOS. No Windows machine is needed to produce the Windows x64 bundle |
| Output | CSV and JSON per plugin |
| Plugin selection | Curated Windows triage set by default; `--all` and `--plugins` override |
| Symbol pack | Bundle `windows.zip` (800 MB); `--lean` builds without it |
| Missing symbols | Report and stop, with a resume path |
| Parallelism | `--jobs N`, default 1 |
| Engine | Swappable: embedded-Python library, or official `volatility3.exe` |

### Why a folder rather than a single executable

A PyInstaller one-file executable re-extracts roughly 50 MB into `%TEMP%` on every
invocation. A 25-plugin run means 25 extractions, 25 framework cold starts, and 25
process-creation events from an unsigned binary — conspicuous on a monitored forensic
workstation, and frequently quarantined outright. A visible folder is auditable, starts
instantly, and avoids the `%TEMP%` pattern entirely.

Producing a single `.exe` would also require an x64 Windows build host. The available VM
runs Windows on ARM, where PyInstaller would emit an ARM64 binary that will not run on a
standard analyst workstation.

### Why macOS can build a Windows bundle

Verified against the live package index:

- `volatility3` 2.28.0 and its only hard dependency, `pefile`, are pure-Python
  `py3-none-any` wheels.
- Every `volatility3[full]` extra — yara-python, capstone, pycryptodome, pillow — ships a
  prebuilt `win_amd64` wheel, about 9 MB in total.
- The Python 3.12.10 embeddable amd64 distribution is an 11 MB zip.

Nothing requires compilation, so `pip download --platform win_amd64` on macOS retrieves
every Windows binary needed. The build never executes Windows code, which is why the ARM
VM is irrelevant to it.

The embeddable distribution also carries the native modules Volatility depends on:
`_lzma.pyd` (reads `.json.xz` ISF files), `_sqlite3.pyd` with `sqlite3.dll` (symbol
cache), `_ssl.pyd` with `libssl-3.dll` (HTTPS for the internet-side fetch), and
`_hashlib.pyd` (manifest hashing).

## Architecture

```
app/
├─ __main__.py        CLI: triage | fetch-symbols | list-plugins | verify
├─ symbols.py         image -> {pdb_name, GUID, age} -> URL + required ISF path
├─ plugins.py         curated triage set and categories
├─ scheduler.py       bounded subprocess pool, timeouts, per-plugin logs
├─ manifest.py        SHA-256 of image and outputs, run metadata
└─ engine/
   ├─ base.py         VolEngine: list_plugins(), run_plugin(name, img, out, fmt)
   ├─ library.py      embedded Python, volatility3 imported as a library
   └─ binary.py       shells out to the official volatility3.exe
```

Only `engine/` knows which Volatility is in use. `--engine library|exe|auto` selects it;
`auto` prefers `library` when `lib/volatility3` exists, else finds `volatility3.exe`
beside the bundle. Because everything above `engine/` is engine-agnostic, switching
backends is a flag change rather than a rewrite.

Both engines ship. The extra 19 MB is negligible against an 820 MB bundle, and it means
an unfavourable accreditation ruling — "official binaries only" — never blocks the tool.

### Bundle layout

```
Volatility4AirGap/
├─ run-triage.bat            double-click entry point
├─ v4ag.bat                  CLI passthrough
├─ python/                   embedded CPython 3.12.10 x64
│  └─ python312._pth         patched to add ..\lib and ..\app
├─ lib/                      volatility3, pefile, yara, capstone, pycryptodome
├─ app/                      tool code
├─ volatility3.exe           official binary, used by --engine exe
├─ cache/                    APPDATA target; keeps the host profile untouched
├─ symbols/                  windows.zip plus any hand-added ISF files
├─ output/<run-id>/          CSV, JSON, logs, manifest
└─ BUILD-MANIFEST.json       component versions and SHA-256 digests
```

## Execution model

Each plugin runs in its own process. That gives fault isolation — a segmentation fault
inside yara or capstone kills one plugin, not the run — and makes parallelism a
scheduling concern rather than a structural one.

`--jobs N` defaults to 1. `--jobs auto` resolves to `min(cpu_count - 1, 4)`.

**Processes, not threads.** Volatility is CPU-bound Python; threads would contend on the
GIL and gain nothing.

**Plain `subprocess`, not `multiprocessing`.** On Windows, `multiprocessing` uses spawn
semantics that re-import `__main__` and expect `freeze_support()` — fragile inside an
embedded distribution. The parent only needs to start processes and wait, so a bounded
scheduler over `Popen` handles is simpler and has no embedded-Python failure modes.

**Child output goes to files, never pipes:**

```python
with open(out_path, "wb") as so, open(log_path, "wb") as se:
    proc = subprocess.Popen(cmd, stdout=so, stderr=se)
```

With no pipe there is no buffer to fill, no reader thread, and nothing to block on, so
polling `proc.poll()` against a deadline enforces the timeout reliably.

### Contention at `--jobs > 1`

1. **Symbol cache locking.** Volatility caches symbol identifiers in a SQLite database at
   `%APPDATA%\volatility3\identifier.cache`. Concurrent workers populating it produce
   intermittent `database is locked` failures. The scheduler pre-warms the cache once,
   serially, during symbol resolution and before any worker starts. `APPDATA` is pinned
   per child to `<bundle>/cache`, which both shares one warm cache and keeps the
   analyst's roaming profile clean. Volatility exposes no dedicated cache variable;
   `APPDATA` is the documented mechanism on Windows.
2. **Disk I/O.** Every plugin streams the same multi-GB image. On NVMe with sufficient
   RAM the page cache absorbs this and `N=4` is a substantial win. On a USB-attached or
   spinning evidence drive, `N>2` can be slower than `N=1`. The tool warns when the image
   sits on removable media.

Per-plugin logs are written to separate files so parallel output never interleaves. The
console shows a single aggregated progress line.

## Symbol resolution

Volatility constructs the download URL and the ISF filename differently, and conflating
them is the source of the original defect.

- **Download URL:** `http://msdl.microsoft.com/download/symbols/{pdb_name}/{GUID}{age}/{pdb_name}`
  The path segment is the GUID concatenated with the age, no separator. A second attempt
  substitutes a compressed `.pd_` variant.
- **Required ISF:** `symbols/windows/{pdb_name}/{GUID_UPPER}-{age}.json.xz`

The tool derives both from a single scanned `(pdb_name, guid, age)` triple, so they
cannot drift apart.

**Scanning.** With the library engine, `PDBUtility.pdbname_scan()` runs over the layer
stack Volatility builds, which is correct for raw, crashdump, VMware and LiME images
alike. With the exe engine, a standalone RSDS scanner — locate the `RSDS` magic, read a
mixed-endian 16-byte GUID, a 4-byte age and a NUL-terminated name — covers raw, `.vmem`
and `.dmp`, cross-checked against `-vvv` output. Neither path treats scraped text as its
primary source.

**Every match is fetched, not just one.** A scan can legitimately find more than one
kernel build — a hibernation remnant, or a capture spanning a reboot. ISF files are small,
so the request carries a *list* and `fetch-symbols` downloads all of them. Guessing which
build Volatility will select would risk a second round trip to save a few megabytes.

**Presence means available, not merely on disk.** Volatility reads ISF files both as loose
files and as members of zip archives, which is how the bundled 800 MB `windows.zip` is
consumed. Checking only for loose files would send the analyst to fetch symbols the bundle
already contains. `SymbolStore` therefore indexes archive central directories as well,
matching on the `{GUID}-{age}.json.xz` filename because the pack's internal layout is not
contractual.

**On a miss** the tool prints the URLs, writes `symbol_request.json`, and stops without
running plugins. Stopping is deliberate: a partial run of symbol-independent plugins
produces an output set that looks complete but is not.

```json
{
  "schema_version": 1,
  "tool_version": "0.1.0",
  "generated_utc": "2026-08-05T21:14:00Z",
  "image": {
    "path": "C:\\evidence\\image.raw",
    "name": "image.raw",
    "size_bytes": 8589934592,
    "sha256": null
  },
  "kernels": [
    {
      "pdb_name": "ntkrnlmp.pdb",
      "guid": "AF550CAA73AFB287705CC40079D786B4",
      "age": 1,
      "guid_age": "AF550CAA73AFB287705CC40079D786B41",
      "offset": 4096,
      "download": {
        "primary_url": "http://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/AF550CAA73AFB287705CC40079D786B41/ntkrnlmp.pdb",
        "compressed_fallback_url": "http://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/AF550CAA73AFB287705CC40079D786B41/ntkrnlmp.pd_"
      },
      "required_isf": "windows/ntkrnlmp.pdb/AF550CAA73AFB287705CC40079D786B4-1.json.xz",
      "present": false,
      "found_at": null
    }
  ],
  "missing_count": 1
}
```

`image.sha256` is null here because hashing a multi-gigabyte image is expensive; the run
manifest records it instead. Since the RSDS scan already reads every byte, Stage 3 should
compute the digest in that same pass rather than making a second one.

On load, URLs are re-derived from the stored identity rather than trusted, so a
hand-edited or corrupted request cannot silently redirect a download.

**Closing the loop.** On the internet-connected machine, `fetch-symbols
symbol_request.json` downloads the PDB, converts it with `PdbReader`, writes it under the
correct name, then re-opens the ISF and asserts its embedded GUID and age match the
request. `verify` confirms a dropped-in `symbols/` folder satisfies the request before the
analyst returns to the air-gapped room, so a bad conversion costs seconds rather than a
second round trip.

## Defects corrected

**ISF filename (fatal).** `generate_isf.sh:46` extracts the 33-character `{GUID}{age}`
URL segment, treats it as the GUID, and hardcodes `-1`:

| | |
| --- | --- |
| Volatility requires | `AF550CAA73AFB287705CC40079D786B4-1.json.xz` |
| The script writes | `AF550CAA73AFB287705CC40079D786B41-1.json.xz` |

Off by the glued age digit. It cannot match for any image, at any age. The script also
has an unbalanced brace in the f-string at line 98, which would crash the converter
before it got that far.

**Unreachable timeout.** `volatility.py:450-453` calls a blocking `proc.stdout.read()`
before `proc.wait(timeout=3600)`, so a hung plugin blocks in `read()` and the timeout
never fires. Redirecting child output to files removes the pipe, and with it the entire
failure mode.

## Build

`tools/build_portable.py`, run on macOS:

1. Fetch `python-3.12.10-embed-amd64.zip`; verify a pinned SHA-256
2. `pip download --platform win_amd64 --python-version 3.12 --only-binary=:all: 'volatility3[full]'`
3. Unzip the wheels into `lib/` — no build step, as each is pure-Python or a prebuilt binary
4. Patch `python312._pth` to add `..\lib` and `..\app`
5. Copy `app/`, the `.bat` launchers and `volatility3.exe`
6. `--with-symbols` (default) downloads `windows.zip` into `symbols/`
7. Emit `BUILD-MANIFEST.json` with every component's version and SHA-256
8. Zip the bundle

Pinned, hashed inputs make builds reproducible, and `BUILD-MANIFEST.json` is the evidence
package for an approval authority.

## Testing

Nearly all the risky logic is platform-independent and is tested natively on macOS with
pytest: the RSDS scanner, URL and ISF-path derivation, `symbol_request.json`, the plugin
set, manifests, and the scheduler.

Two tests carry most of the weight:

- **Synthetic RSDS fixture.** A few-MB file with a known GUID, age and `ntkrnlmp.pdb`
  planted at a known offset, exercising scan to URL to ISF path with no memory image and
  no Windows.
- **Golden vector.** `AF550CAA73AFB287705CC40079D786B4` with age `1`, pinned to both its
  download URL and `...B4-1.json.xz`. This makes the defect above permanently
  unreintroducible.

A structural test asserts the built zip matches `BUILD-MANIFEST.json` and that `._pth`
resolves.

The Windows-on-ARM VM serves as a smoke-test rig rather than a build host: Windows 11 on
ARM emulates x64, so the bundle's `python.exe` runs there well enough to confirm layout,
imports and CLI wiring. Full end-to-end validation still requires a real image on a real
x64 workstation.

## Scope

Standalone. The tool writes CSV and JSON to disk and does not touch Postgres or
`ingest_volatility.py`. CSV filenames stay compatible with CORE-Respond's ingest
(`windows.pslist.PsList.csv`), so results can be fed in later as a separate step.

## Open items

- Confirm whether the air-gapped network permits a self-assembled bundle or requires
  official binaries. The dual-engine design defers this, but the answer determines which
  engine is the default.
- Choose a small public memory image for end-to-end testing, or capture one from a VM.
- `volatility3.exe` is not Authenticode-signed. Confirm whether that blocks its use.
