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

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
