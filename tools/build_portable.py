#!/usr/bin/env python3
"""Assemble the portable Windows x64 bundle.

Runs on macOS or Linux. No Windows machine is involved, and none is needed:
volatility3 and pefile are pure-Python wheels, and every ``[full]`` extra ships a
prebuilt ``win_amd64`` wheel, so nothing requires compilation. ``pip`` is asked for
Windows artifacts explicitly via ``--platform``.

That matters because the only Windows VM available here runs on ARM, where any
interpreter-bundling tool would emit an ARM64 binary that will not run on a standard
analyst workstation.

Every downloaded input is pinned and hashed, and BUILD-MANIFEST.json records what
went in. That file is the evidence package for an approval authority.

Usage:
    python3 tools/build_portable.py                 # full bundle, ~820 MB
    python3 tools/build_portable.py --lean          # ~65 MB, no symbol pack
    python3 tools/build_portable.py --no-zip        # leave the folder, skip archiving
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

BUNDLE_NAME = "Volatility4AirGap"

# Pinned interpreter. The SHA-256 was verified against python.org's published MD5
# for python-3.12.10-embed-amd64.zip (fe8ef205f2e9c3ba44d0cf9954e1abd3) before
# being recorded here. Changing the version means re-verifying the same way.
PYTHON_VERSION = "3.12.10"
PYTHON_TAG = "312"
PYTHON_URL = (
    f"https://www.python.org/ftp/python/{PYTHON_VERSION}"
    f"/python-{PYTHON_VERSION}-embed-amd64.zip"
)
PYTHON_SHA256 = "4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3"

TARGET_PLATFORM = "win_amd64"
TARGET_PY = "3.12"
REQUIREMENT = "volatility3[full]"

SYMBOL_PACK_URL = "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"

# The embeddable distribution ignores PYTHONPATH and the registry when a ._pth file
# is present, so every path the bundle needs must be listed here. Paths resolve
# relative to the directory holding python.exe.
#
# Note ".." — the bundle root — and not "..\app". `python -m app` imports app as a
# package, which requires its *parent* on sys.path. Listing the package directory
# itself makes the modules inside it visible while the package remains invisible,
# and would also break the relative imports in app/. `..\lib` is different: there we
# genuinely want lib/ on the path so `import volatility3` resolves.
PTH_CONTENTS = f"""python{PYTHON_TAG}.zip
.
..
..\\lib
import site
"""

# cmd.exe expects CRLF. A batch file written with Unix line endings parses
# unreliably — it may appear to work and then fail in ways that point nowhere near
# the cause. Built on macOS, so the endings must be forced rather than inherited.
LAUNCHER_BAT = "\r\n".join([
    "@echo off",
    "rem Volatility4AirGap command-line entry point.",
    "rem Runs the bundled interpreter; nothing needs to be installed on this machine.",
    "setlocal",
    'set "V4AG_PY=%~dp0python\\python.exe"',
    'if not exist "%V4AG_PY%" (',
    "    echo ERROR: bundled interpreter not found at %V4AG_PY%",
    "    echo The bundle is incomplete. Re-extract it to a clean folder.",
    "    exit /b 9",
    ")",
    '"%V4AG_PY%" -m app %*',
    "exit /b %ERRORLEVEL%",
    "",
])


def log(message: str) -> None:
    print(f"==> {message}", flush=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, dest: Path, *, expected_sha256: str | None = None) -> str:
    """Fetch a URL to ``dest``, caching by path, and return its SHA-256.

    A pinned hash that does not match is fatal. Silently building a bundle around
    an unexpected interpreter is precisely the outcome pinning exists to prevent.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists():
        actual = sha256_file(dest)
        if expected_sha256 is None or actual == expected_sha256:
            log(f"cached {dest.name} ({dest.stat().st_size / 1e6:.1f} MB)")
            return actual
        log(f"cached {dest.name} failed its hash check, refetching")
        dest.unlink()

    log(f"downloading {url}")
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(url) as response, open(tmp, "wb") as out:
        shutil.copyfileobj(response, out)
    tmp.replace(dest)

    actual = sha256_file(dest)
    if expected_sha256 is not None and actual != expected_sha256:
        dest.unlink()
        raise SystemExit(
            f"hash mismatch for {url}\n  expected {expected_sha256}\n  got      {actual}"
        )

    log(f"fetched {dest.name} ({dest.stat().st_size / 1e6:.1f} MB)")
    return actual


def strip_host_artifacts(root: Path) -> tuple[int, int]:
    """Remove bytecode and scripts that belong to the build host, not the target.

    pip compiles ``.pyc`` with the *host* interpreter. Those carry a magic number
    for the wrong Python version, so the target ignores them — they are dead weight
    that also misleads anyone auditing the bundle. The ``bin/`` directory holds Unix
    ``vol``/``volshell`` shims that cannot run on Windows.
    """
    removed_pyc = 0
    for cache in sorted(root.rglob("__pycache__"), reverse=True):
        removed_pyc += len(list(cache.glob("*.pyc")))
        shutil.rmtree(cache, ignore_errors=True)

    removed_dirs = 0
    for junk in ("bin", "Scripts"):
        target = root / junk
        if target.is_dir():
            shutil.rmtree(target)
            removed_dirs += 1

    return removed_pyc, removed_dirs


def install_dependencies(lib_dir: Path, wheel_cache: Path) -> list[dict]:
    """Fetch Windows wheels, record their hashes, then unpack them into ``lib``.

    Downloading first means the manifest can name every wheel and its digest, and
    a later build can be repeated offline from the same cache.
    """
    wheel_cache.mkdir(parents=True, exist_ok=True)
    platform_args = [
        "--platform", TARGET_PLATFORM,
        "--python-version", TARGET_PY,
        "--only-binary=:all:",
    ]

    log(f"downloading {REQUIREMENT} wheels for {TARGET_PLATFORM}")
    subprocess.run(
        [sys.executable, "-m", "pip", "download", REQUIREMENT,
         "--dest", str(wheel_cache), *platform_args],
        check=True,
        stdout=subprocess.DEVNULL,
    )

    wheels = sorted(wheel_cache.glob("*.whl"))
    if not wheels:
        raise SystemExit("pip download produced no wheels")

    log(f"installing {len(wheels)} wheels into lib/")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", REQUIREMENT,
         "--target", str(lib_dir), "--no-index",
         "--find-links", str(wheel_cache),
         "--no-compile", "--upgrade", *platform_args],
        check=True,
        stdout=subprocess.DEVNULL,
    )

    return [
        {"file": w.name, "size_bytes": w.stat().st_size, "sha256": sha256_file(w)}
        for w in wheels
    ]


def copy_app(source: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(
        source, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")
    )


def write_deterministic_zip(folder: Path, archive: Path) -> None:
    """Archive the bundle so identical inputs yield a byte-identical zip.

    Timestamps and entry order are the usual sources of drift. Fixing both means an
    approver can rebuild and compare digests rather than taking the artifact on
    trust.
    """
    archive.parent.mkdir(parents=True, exist_ok=True)

    def arcname(path: Path) -> str:
        return str(Path(folder.name) / path.relative_to(folder)).replace("\\", "/")

    # Directories are written explicitly. A zip stores none of its own accord, so
    # empty ones — cache/ and output/ — simply vanish on extraction, and Volatility
    # then fails with a bare FileNotFoundError on identifier.cache.
    #
    # One globally sorted pass keeps the archive deterministic, and because a
    # directory entry's trailing "/" sorts before any name inside it, each
    # directory still precedes its contents as extractors expect.
    entries = sorted(
        (arcname(p) + ("/" if p.is_dir() else ""), p) for p in folder.rglob("*")
    )

    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for name, path in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            if path.is_dir():
                info.external_attr = (0o755 << 16) | 0x10  # MS-DOS directory flag
                zf.writestr(info, b"")
                continue

            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            # Streamed, not read_bytes(): the symbol pack alone is 800 MB and
            # reading it whole would spike memory by that much.
            with path.open("rb") as source, zf.open(info, "w") as target:
                shutil.copyfileobj(source, target, 1 << 20)


def directory_stats(root: Path) -> tuple[int, int]:
    files = [p for p in root.rglob("*") if p.is_file()]
    return len(files), sum(p.stat().st_size for p in files)


MANIFEST_NAME = "BUILD-MANIFEST.json"
FILELIST_NAME = "BUILD-FILES.sha256"

#: Excluded from the payload digest because they record it. Including either would
#: be circular: writing the digest would change the value it describes.
_DIGEST_EXCLUDED = frozenset({MANIFEST_NAME, FILELIST_NAME})


def payload_digest(root: Path) -> str:
    """One digest over the bundle's contents, excluding the manifest itself.

    The manifest records the build time, so it differs on every run and the zip can
    never be byte-identical. This digest covers everything else, which makes the
    reproducibility claim checkable: rebuild, compare ``payload_sha256``, and an
    approver knows the contents are identical without trusting the archive.

    It also detects corruption after the bundle has crossed to the air-gapped host.
    """
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative in _DIGEST_EXCLUDED:
            continue
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(sha256_file(path).encode("ascii") + b"\0")
    return digest.hexdigest()


def write_file_list(root: Path) -> Path:
    """Per-file digests, so a mismatch can name the offending file.

    An aggregate digest only says "something changed"; the analyst still has to
    find what. Standard ``sha256sum`` format, so it is also checkable with other
    tools if ours will not start.
    """
    lines = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative in _DIGEST_EXCLUDED:
            continue
        lines.append(f"{sha256_file(path)}  {relative}")

    destination = root / FILELIST_NAME
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return destination


def check_bundle(bundle: Path) -> int:
    """Recompute the payload digest and compare it with the recorded one."""
    manifest_path = bundle / MANIFEST_NAME
    if not manifest_path.is_file():
        print(f"no {MANIFEST_NAME} in {bundle}", file=sys.stderr)
        return 2

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    recorded = manifest.get("payload_sha256")
    actual = payload_digest(bundle)

    print(f"recorded  {recorded}")
    print(f"actual    {actual}")

    if recorded != actual:
        print("\nMISMATCH: bundle contents differ from the manifest.", file=sys.stderr)
        return 1

    print("\nBundle intact.")
    return 0


def build(args: argparse.Namespace) -> Path:
    out_root = Path(args.out).resolve()
    bundle = out_root / BUNDLE_NAME
    cache = out_root / "cache"

    if bundle.exists():
        log(f"clearing {bundle}")
        shutil.rmtree(bundle)
    bundle.mkdir(parents=True)

    # 1. Interpreter
    embed_zip = cache / f"python-{PYTHON_VERSION}-embed-amd64.zip"
    python_sha = download(PYTHON_URL, embed_zip, expected_sha256=PYTHON_SHA256)

    python_dir = bundle / "python"
    python_dir.mkdir()
    log(f"extracting embedded Python {PYTHON_VERSION} (x64)")
    with zipfile.ZipFile(embed_zip) as zf:
        zf.extractall(python_dir)

    pth = python_dir / f"python{PYTHON_TAG}._pth"
    pth.write_text(PTH_CONTENTS, encoding="utf-8")
    log(f"wrote {pth.name} exposing ..\\lib and ..\\app")

    # 2. Dependencies
    lib_dir = bundle / "lib"
    wheels = install_dependencies(lib_dir, cache / "wheels")
    removed_pyc, removed_dirs = strip_host_artifacts(lib_dir)
    log(f"stripped {removed_pyc} host-compiled .pyc and {removed_dirs} unix script dir(s)")

    # 3. Our code and launcher
    copy_app(REPO_ROOT / "app", bundle / "app")
    # newline="" so the CRLF above survives verbatim rather than being translated.
    (bundle / "v4ag.bat").write_bytes(LAUNCHER_BAT.encode("ascii"))
    log("copied app/ and wrote v4ag.bat")

    # The reference has to travel with the bundle. An analyst on an air-gapped
    # workstation cannot open the repository to read it.
    howto = REPO_ROOT / "docs" / "HOWTO.md"
    if howto.is_file():
        shutil.copy2(howto, bundle / "HOWTO.md")
        log("included HOWTO.md")
    else:
        log("WARNING: docs/HOWTO.md not found; bundle will ship without a reference")

    # 4. Optional official binary, for --engine exe
    vol_exe_sha = None
    if args.vol_exe:
        source = Path(args.vol_exe).expanduser().resolve()
        if not source.is_file():
            raise SystemExit(f"volatility3.exe not found: {source}")
        shutil.copy2(source, bundle / "volatility3.exe")
        vol_exe_sha = sha256_file(bundle / "volatility3.exe")
        log(f"included {source.name} for the exe engine")

    # 5. Symbols
    symbols_dir = bundle / "symbols"
    symbols_dir.mkdir()
    symbol_pack_sha = None
    if args.with_symbols:
        pack = cache / "windows.zip"
        symbol_pack_sha = download(SYMBOL_PACK_URL, pack)
        shutil.copy2(pack, symbols_dir / "windows.zip")
        log("included the Windows symbol pack")
    else:
        (symbols_dir / "README.txt").write_text(
            "Place ISF symbol files here, either loose or as a zip pack.\n"
            "Loose files go under windows/<pdb name>/<GUID>-<age>.json.xz\n",
            encoding="utf-8",
        )
        log("lean build: no symbol pack (use fetch-symbols to populate)")

    (bundle / "output").mkdir()
    (bundle / "cache").mkdir()  # APPDATA target, keeps the host profile untouched

    # 6. Manifest
    file_count, total_bytes = directory_stats(bundle)
    manifest = {
        "bundle": BUNDLE_NAME,
        "built_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "built_on": f"{sys.platform} python{sys.version_info.major}.{sys.version_info.minor}",
        "target": "windows x86-64",
        "python": {
            "version": PYTHON_VERSION,
            "url": PYTHON_URL,
            "sha256": python_sha,
        },
        "requirement": REQUIREMENT,
        "wheels": wheels,
        "symbol_pack": (
            {"url": SYMBOL_PACK_URL, "sha256": symbol_pack_sha} if symbol_pack_sha else None
        ),
        "volatility3_exe_sha256": vol_exe_sha,
        "contents": {"files": file_count, "bytes": total_bytes},
        # Stable across rebuilds; built_utc above is not.
        "payload_sha256": payload_digest(bundle),
        "file_list": FILELIST_NAME,
    }
    write_file_list(bundle)
    (bundle / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    file_count, total_bytes = directory_stats(bundle)
    log(f"bundle: {file_count} files, {total_bytes / 1e6:.1f} MB at {bundle}")

    if args.zip:
        archive = out_root / f"{BUNDLE_NAME}.zip"
        log("archiving (deterministic: fixed timestamps, sorted entries)")
        write_deterministic_zip(bundle, archive)
        log(f"archive: {archive} ({archive.stat().st_size / 1e6:.1f} MB)")

    return bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(REPO_ROOT / "build"), help="output directory")
    parser.add_argument(
        "--lean",
        dest="with_symbols",
        action="store_false",
        help="omit the 800 MB Windows symbol pack",
    )
    parser.add_argument("--no-zip", dest="zip", action="store_false", help="skip archiving")
    parser.add_argument(
        "--vol-exe",
        default=None,
        help="path to the official volatility3.exe, for --engine exe",
    )
    parser.add_argument(
        "--check",
        metavar="BUNDLE_DIR",
        default=None,
        help="verify an existing bundle against its manifest instead of building",
    )
    parser.set_defaults(with_symbols=True, zip=True)

    args = parser.parse_args()
    if args.check:
        return check_bundle(Path(args.check).expanduser().resolve())

    build(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
