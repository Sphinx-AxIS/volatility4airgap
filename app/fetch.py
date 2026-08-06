"""Downloading PDBs and converting them to ISF symbol files.

Runs on the internet-connected machine, driven by a ``symbol_request.json``
carried over from the air-gapped host.

Three details here are not obvious and each has bitten:

1. The conversion must pass ``database_name``. Volatility looks symbols up in a
   SQLite cache keyed ``{pdb_name}|{GUID}|{age}`` before it ever globs the
   filesystem, and builds that key from the ISF's ``metadata.windows.pdb.database``
   field. ``PdbReader`` defaults it to ``unknown.pdb``, which never matches.
2. The compressed ``.pd_`` variant is a Microsoft cabinet. Volatility has no CAB
   handling, so it cannot read one; we expand it ourselves before converting.
3. Every written ISF is read back and checked against the request. A symbol file
   that is subtly wrong is worse than one that is missing, because the analyst has
   already crossed the air gap by the time it fails.
"""

from __future__ import annotations

import json
import lzma
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .symbols import KernelPdb

# Some Microsoft endpoints reject the default urllib agent.
USER_AGENT = "Microsoft-Symbol-Server/10.0.0.0"

TIMEOUT_SECONDS = 300


class FetchError(RuntimeError):
    """A kernel's symbols could not be produced. Never fatal to the whole run."""


@dataclass
class FetchResult:
    kernel: KernelPdb
    isf_path: Path | None = None
    error: str | None = None
    compressed: bool = False
    symbol_count: int = 0

    @property
    def ok(self) -> bool:
        return self.isf_path is not None


def _open(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS)


def download_pdb(kernel: KernelPdb, work_dir: Path, *, log=print) -> tuple[Path, bool]:
    """Fetch a PDB, falling back to the cabinet-compressed variant.

    Returns the downloaded path and whether it is compressed.
    """
    work_dir.mkdir(parents=True, exist_ok=True)

    attempts = [
        (kernel.download_url, kernel.download_filename, False),
        (kernel.compressed_url, kernel.compressed_filename, True),
    ]

    errors = []
    for url, filename, compressed in attempts:
        destination = work_dir / filename
        try:
            log(f"    GET {url}")
            with _open(url) as response, open(destination, "wb") as out:
                shutil.copyfileobj(response, out)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as exc:
            errors.append(f"{filename}: {exc}")
            destination.unlink(missing_ok=True)
            continue

        size = destination.stat().st_size
        if size == 0:
            errors.append(f"{filename}: empty response")
            destination.unlink(missing_ok=True)
            continue

        log(f"    {size / 1e6:.2f} MB")
        return destination, compressed

    raise FetchError("; ".join(errors) or "no download succeeded")


def expand_cab(path: Path, work_dir: Path, *, log=print) -> Path:
    """Expand a ``.pd_`` cabinet.

    Windows always has ``expand.exe``. Elsewhere ``cabextract`` may be installed.
    Neither is bundled, so this fails with an actionable message rather than
    pretending the file is usable.
    """
    out_dir = work_dir / "expanded"
    out_dir.mkdir(parents=True, exist_ok=True)

    for command in (
        ["expand.exe", str(path), "-F:*", str(out_dir)],
        ["expand", str(path), "-F:*", str(out_dir)],
        ["cabextract", "-d", str(out_dir), str(path)],
    ):
        if shutil.which(command[0]) is None:
            continue
        log(f"    expanding cabinet with {command[0]}")
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            produced = sorted(p for p in out_dir.iterdir() if p.is_file())
            if produced:
                return produced[0]

    raise FetchError(
        f"{path.name} is a Microsoft cabinet and no expander was found. "
        "Install cabextract, or run this step on Windows where expand.exe is built in."
    )


def convert_to_isf(pdb_path: Path, kernel: KernelPdb, out_dir: Path, *, log=print) -> Path:
    """Convert a PDB to a compressed ISF at the exact path Volatility expects."""
    try:
        from volatility3.framework import contexts
        from volatility3.framework.symbols.windows import pdbconv
    except ImportError as exc:  # pragma: no cover - bundle always provides it
        raise FetchError(f"volatility3 is required to convert PDBs: {exc}") from exc

    log("    converting PDB to ISF")
    context = contexts.Context()
    reader = pdbconv.PdbReader(
        context,
        pdb_path.absolute().as_uri(),
        # Without this the cache key becomes unknown.pdb|GUID|age and never matches.
        database_name=kernel.pdb_name,
    )
    isf = reader.get_json()

    destination = kernel.isf_path(out_dir)
    destination.parent.mkdir(parents=True, exist_ok=True)

    # Write beside the target then move, so an interrupted run cannot leave a
    # truncated symbol file that looks present.
    temporary = destination.with_suffix(destination.suffix + ".part")
    with lzma.open(temporary, "wt", encoding="utf-8") as handle:
        json.dump(isf, handle)
    temporary.replace(destination)

    return destination


def verify_isf(path: Path, kernel: KernelPdb) -> int:
    """Read the written ISF back and confirm it identifies the requested kernel.

    Returns the symbol count. Raises :class:`FetchError` on any mismatch.
    """
    try:
        with lzma.open(path, "rt", encoding="utf-8") as handle:
            isf = json.load(handle)
    except (lzma.LZMAError, json.JSONDecodeError, OSError) as exc:
        raise FetchError(f"{path.name} is not a readable ISF: {exc}") from exc

    metadata = isf.get("metadata", {}).get("windows", {}).get("pdb", {})
    guid = str(metadata.get("GUID", "")).upper()
    age = metadata.get("age")
    database = metadata.get("database")

    if guid != kernel.guid:
        raise FetchError(f"GUID mismatch: ISF has {guid}, request wants {kernel.guid}")
    if int(age if age is not None else -1) != kernel.age:
        raise FetchError(f"age mismatch: ISF has {age}, request wants {kernel.age}")
    if database != kernel.pdb_name:
        raise FetchError(
            f"database mismatch: ISF has {database!r}, request wants {kernel.pdb_name!r}. "
            "Volatility's cache lookup would miss this file."
        )

    # Identity is not usability. Microsoft serves public (stripped) PDBs for some
    # kernels — chiefly older ones — which carry symbol addresses but no structure
    # definitions. The resulting ISF has the right GUID and age and is useless:
    # Volatility cannot resolve _EPROCESS and fails with "Unable to validate the
    # plugin requirements: ['plugins.Info.kernel.symbol_table_name']", which points
    # nowhere near the cause.
    if not isf.get("user_types"):
        raise FetchError(
            f"{path.name} contains no type information "
            f"({len(isf.get('symbols', {}))} symbols, 0 user_types). Microsoft served a "
            "public (stripped) PDB for this kernel, so the ISF cannot be used. "
            "Use the Volatility community symbol pack instead: "
            "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip "
            "— place it in the symbols folder, or build the bundle without --lean."
        )

    return len(isf.get("symbols", {}))


def fetch_one(kernel: KernelPdb, out_dir: Path, work_dir: Path, *, log=print) -> FetchResult:
    """Download, convert and verify one kernel's symbols."""
    log(f"\n{kernel.pdb_name}  {kernel.guid}  age {kernel.age}")

    existing = kernel.isf_path(out_dir)
    if existing.is_file():
        try:
            count = verify_isf(existing, kernel)
        except FetchError:
            log("    existing file failed verification, replacing")
        else:
            log(f"    already present and valid ({count} symbols)")
            return FetchResult(kernel, existing, symbol_count=count)

    try:
        pdb_path, compressed = download_pdb(kernel, work_dir, log=log)
        if compressed:
            pdb_path = expand_cab(pdb_path, work_dir, log=log)

        isf_path = convert_to_isf(pdb_path, kernel, out_dir, log=log)
        try:
            count = verify_isf(isf_path, kernel)
        except FetchError:
            # Do not leave an unusable ISF behind. It would satisfy every presence
            # check and report "ready to run plugins" while nothing can run.
            isf_path.unlink(missing_ok=True)
            raise
    except FetchError as exc:
        log(f"    FAILED: {exc}")
        return FetchResult(kernel, error=str(exc))
    except Exception as exc:  # noqa: BLE001 - one kernel must not sink the run
        log(f"    FAILED: {type(exc).__name__}: {exc}")
        return FetchResult(kernel, error=f"{type(exc).__name__}: {exc}")

    size_mb = isf_path.stat().st_size / 1e6
    log(f"    wrote {isf_path.name} ({size_mb:.2f} MB, {count} symbols)")
    return FetchResult(kernel, isf_path, compressed=compressed, symbol_count=count)


def fetch_all(
    kernels: list[KernelPdb], out_dir: Path, work_dir: Path, *, log=print
) -> list[FetchResult]:
    return [fetch_one(kernel, out_dir, work_dir, log=log) for kernel in kernels]
