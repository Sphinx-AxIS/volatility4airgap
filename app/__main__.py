"""Command-line entry point.

Stage 2 ships ``symbols`` and ``verify``, which is enough to exercise the whole
bundle — interpreter, library path, scanner — on a real workstation. ``triage``
and ``fetch-symbols`` arrive with Stage 3.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, symbol_request
from .symbol_store import SymbolStore
from .symbols import scan_image

BUNDLE_ROOT = Path(__file__).resolve().parent.parent


def default_symbols_dir() -> Path:
    return BUNDLE_ROOT / "symbols"


def _print_kernel(index: int, entry: dict, total: int) -> None:
    label = f"[{index}/{total}] " if total > 1 else ""
    print(f"\n{label}{entry['pdb_name']}  GUID {entry['guid']}  age {entry['age']}")

    if entry["present"]:
        print(f"  status    available at {entry['found_at']}")
        return

    print("  status    MISSING")
    print(f"  download  {entry['download']['primary_url']}")
    print(f"  fallback  {entry['download']['compressed_fallback_url']}")
    print(f"  place at  symbols/{entry['required_isf']}")


def cmd_symbols(args: argparse.Namespace) -> int:
    image = Path(args.image).expanduser()
    if not image.is_file():
        print(f"error: image not found: {image}", file=sys.stderr)
        return 2

    symbols_dir = Path(args.symbols).expanduser() if args.symbols else default_symbols_dir()

    print(f"Scanning {image.name} ({image.stat().st_size / 1e9:.2f} GB)...")
    result = scan_image(image, hash_image=not args.no_hash)

    if not result.kernels:
        print("\nNo Windows kernel PDB record found.")
        print("The image may be a non-Windows capture, compressed, or truncated.")
        return 1

    store = SymbolStore(symbols_dir)
    document = symbol_request.build(
        image, result.kernels, store=store, image_sha256=result.sha256
    )

    if result.sha256:
        print(f"SHA-256  {result.sha256}")
    if result.is_ambiguous:
        print(
            f"\nNote: {len(result.kernels)} kernel builds found. "
            "All will be fetched; Volatility selects the one it needs."
        )

    total = len(document["kernels"])
    for index, entry in enumerate(document["kernels"], start=1):
        _print_kernel(index, entry, total)

    missing = document["missing_count"]
    if missing == 0:
        print("\nAll symbols available. Ready to run plugins.")
        return 0

    destination = Path(args.output) if args.output else Path.cwd() / symbol_request.FILENAME
    symbol_request.write(destination, document)

    print(f"\n{missing} of {total} symbol file(s) missing.")
    print(f"Wrote {destination}")
    print("\nOn an internet-connected machine, run:")
    print(f"  v4ag.bat fetch-symbols {destination.name}")
    print("then copy the resulting symbols folder back here and re-run this command.")
    return 3


def cmd_verify(args: argparse.Namespace) -> int:
    document = symbol_request.load(Path(args.request).expanduser())
    symbols_dir = Path(args.symbols).expanduser() if args.symbols else default_symbols_dir()
    store = SymbolStore(symbols_dir)

    kernels = symbol_request.kernels_from(document)
    missing = store.missing(kernels)

    for kernel in kernels:
        located = store.locate(kernel)
        state = f"ok       {located.describe()}" if located else "MISSING"
        print(f"{kernel.pdb_name}  {kernel.guid}-{kernel.age}  {state}")

    if missing:
        print(f"\n{len(missing)} of {len(kernels)} still missing under {symbols_dir}")
        return 3

    print(f"\nAll {len(kernels)} symbol file(s) present. Safe to return to the secure host.")
    return 0


#: Modules the bundle must be able to import. The native ones are easy to lose when
#: assembling a bundle by hand: without _lzma no .json.xz symbol file can be read,
#: and without _sqlite3 Volatility's symbol cache fails.
_REQUIRED = [
    ("volatility3", "the analysis engine"),
    ("pefile", "PE parsing, required by volatility3"),
    ("lzma", "reads .json.xz symbol files"),
    ("sqlite3", "volatility symbol cache"),
    ("ssl", "HTTPS for fetch-symbols"),
    ("hashlib", "custody hashing"),
]
_OPTIONAL = [
    ("yara", "yara scanning plugins"),
    ("capstone", "disassembly plugins"),
    ("Crypto", "hashdump and lsadump"),
    ("PIL", "screenshot plugins"),
]


def _probe(name: str) -> tuple[bool, str]:
    try:
        module = __import__(name)
    except Exception as exc:  # noqa: BLE001 - report anything, never crash the doctor
        return False, f"{type(exc).__name__}: {exc}"
    version = getattr(module, "__version__", "") or ""
    return True, str(version)


def cmd_doctor(args: argparse.Namespace) -> int:
    """Report the bundle's health. Written for a host with no debugger and no network."""
    import platform
    import sysconfig

    # platform.machine() reports the host CPU, which under Windows-on-ARM x64
    # emulation is ARM64 even though the process is x64. sysconfig.get_platform()
    # reports what the interpreter was *built* for, which is the thing that decides
    # whether this bundle can run here at all.
    interpreter_arch = sysconfig.get_platform()
    host_arch = platform.machine()

    print("Volatility4AirGap doctor")
    print(f"  tool          {__version__}")
    print(f"  python        {platform.python_version()}")
    print(f"  interpreter   {interpreter_arch}  <- the bundle's architecture")
    print(f"  host cpu      {host_arch}")
    if interpreter_arch == "win-amd64" and host_arch.upper() == "ARM64":
        print("                (x64 under ARM emulation: fine for testing, not the target)")
    print(f"  executable    {sys.executable}")
    print(f"  bundle root   {BUNDLE_ROOT}")

    print("\nsys.path")
    for entry in sys.path:
        marker = "ok " if entry and Path(entry).exists() else "   "
        print(f"  [{marker}] {entry or '(empty)'}")

    failures = 0
    print("\nrequired")
    for name, why in _REQUIRED:
        ok, detail = _probe(name)
        if not ok:
            failures += 1
        status = "ok     " if ok else "FAILED "
        print(f"  [{status}] {name:14s} {detail or why}")

    print("\noptional")
    for name, why in _OPTIONAL:
        ok, detail = _probe(name)
        print(f"  [{'ok     ' if ok else 'absent '}] {name:14s} {detail or why}")

    symbols_dir = Path(args.symbols).expanduser() if args.symbols else default_symbols_dir()
    print(f"\nsymbols  {symbols_dir}")
    if symbols_dir.is_dir():
        packs = sorted(symbols_dir.rglob("*.zip"))
        loose = sorted(symbols_dir.rglob("*.json.xz"))
        for pack in packs:
            print(f"  pack   {pack.name} ({pack.stat().st_size / 1e6:.0f} MB)")
        print(f"  loose  {len(loose)} ISF file(s)")
        if not packs and not loose:
            print("  empty — run 'symbols' against an image to find out what is needed")
    else:
        print("  missing")

    exe = BUNDLE_ROOT / "volatility3.exe"
    print(f"\nvolatility3.exe  {'present' if exe.is_file() else 'not bundled'}")

    if failures:
        print(f"\n{failures} required component(s) unavailable.")
        return 1

    print("\nAll required components present.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="v4ag", description="Portable Volatility3 triage for air-gapped hosts"
    )
    parser.add_argument("--version", action="version", version=f"v4ag {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    symbols = sub.add_parser(
        "symbols", help="identify the kernel and report the symbols needed"
    )
    symbols.add_argument("--image", required=True, help="path to the memory image")
    symbols.add_argument("--symbols", default=None, help="symbols directory")
    symbols.add_argument("--output", default=None, help="where to write symbol_request.json")
    symbols.add_argument(
        "--no-hash", action="store_true", help="skip the custody SHA-256 for a faster probe"
    )
    symbols.set_defaults(func=cmd_symbols)

    verify = sub.add_parser("verify", help="check a symbol request is satisfied")
    verify.add_argument("request", help="path to symbol_request.json")
    verify.add_argument("--symbols", default=None, help="symbols directory")
    verify.set_defaults(func=cmd_verify)

    doctor = sub.add_parser("doctor", help="report bundle health and import status")
    doctor.add_argument("--symbols", default=None, help="symbols directory")
    doctor.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
