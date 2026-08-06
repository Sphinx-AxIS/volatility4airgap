"""Command-line entry point.

The symbol half of the workflow is complete: ``symbols`` on the air-gapped host
identifies what is needed, ``fetch-symbols`` on the connected host produces it,
``verify`` confirms the result before the analyst walks back, and ``doctor``
diagnoses a bundle that will not start. ``triage`` — running plugins — is next.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from . import __version__, symbol_request
from .symbol_store import SymbolStore
from .symbols import scan_image

BUNDLE_ROOT = Path(__file__).resolve().parent.parent


def default_symbols_dir() -> Path:
    return BUNDLE_ROOT / "symbols"


def build_identity() -> str:
    """Identify which build this is, from BUILD-MANIFEST.json.

    The tool version alone cannot distinguish two builds, so an analyst running a
    stale extract gets no hint of it — only a command that does not exist yet.
    The build time and payload digest make that self-diagnosing.
    """
    manifest = BUNDLE_ROOT / "BUILD-MANIFEST.json"
    if not manifest.is_file():
        return "source checkout"
    try:
        import json

        data = json.loads(manifest.read_text(encoding="utf-8"))
        built = data.get("built_utc", "?")
        payload = str(data.get("payload_sha256", ""))[:8] or "?"
        return f"built {built}, payload {payload}"
    except (ValueError, OSError):
        return "unreadable BUILD-MANIFEST.json"


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


def cmd_triage(args: argparse.Namespace) -> int:
    """Run plugins against an image. The main event."""
    from . import engine as engine_mod, manifest, plugins as catalog, scheduler, triage

    image = Path(args.image).expanduser()
    if not image.is_file():
        print(f"error: image not found: {image}", file=sys.stderr)
        return 2

    symbols_dir = Path(args.symbols).expanduser() if args.symbols else default_symbols_dir()

    try:
        jobs = scheduler.resolve_jobs(args.jobs)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    unknown = [f for f in formats if f not in engine_mod.RENDERERS]
    if unknown:
        print(f"error: unknown format(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    try:
        engine = engine_mod.select(args.engine, BUNDLE_ROOT)
    except (engine_mod.EngineUnavailable, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Identify the kernel and hash the image in one pass.
    print(f"Scanning {image.name} ({image.stat().st_size / 1e9:.2f} GB)...")
    scan = scan_image(image, hash_image=not args.no_hash)
    if not scan.kernels:
        print("\nNo Windows kernel PDB record found.")
        return 1
    if scan.sha256:
        print(f"SHA-256  {scan.sha256}")

    store = SymbolStore(symbols_dir)
    missing = store.missing(scan.kernels)
    if missing and not args.force:
        document = symbol_request.build(
            image, scan.kernels, store=store, image_sha256=scan.sha256
        )
        destination = Path(args.output or Path.cwd()) / symbol_request.FILENAME
        symbol_request.write(destination, document)
        print(f"\n{len(missing)} symbol file(s) missing; not running plugins.")
        for kernel in missing:
            print(f"  {kernel.pdb_name}  {kernel.download_url}")
        print(f"\nWrote {destination}. Run 'fetch-symbols' on a connected machine.")
        return 3

    try:
        plugin_names = catalog.resolve(args.plugins, all_plugins=args.all)
    except Exception as exc:  # noqa: BLE001
        print(f"error: could not resolve plugins: {exc}", file=sys.stderr)
        return 2
    if not plugin_names:
        print("error: no plugins selected", file=sys.stderr)
        return 2

    output_dir = Path(args.out).expanduser() if args.out else (
        BUNDLE_ROOT / "output" / f"{image.stem}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    plan = triage.TriagePlan(
        image=image,
        output_dir=output_dir,
        symbols_dir=symbols_dir,
        cache_dir=BUNDLE_ROOT / "cache",
        plugin_names=plugin_names,
        formats=formats,
        jobs=jobs,
        timeout=args.timeout,
    )

    print(f"\nEngine {engine.name}, {len(plugin_names)} plugin(s), "
          f"formats {'+'.join(formats)}, jobs {jobs}")
    print(f"Output {output_dir}")

    started = manifest.utc_now()

    probe = triage.run_probe(plan, engine)
    if not probe.ok and not args.force:
        print("\nProbe failed, so the run would produce nothing useful.")
        print(triage.probe_diagnosis(probe))
        print("\nUse --force to run the plugins anyway.")
        triage.cleanup_probe(plan)
        return 4
    triage.cleanup_probe(plan)
    print("Probe ok.\n")

    tasks = triage.build_tasks(plan, engine)
    done = {"n": 0}
    total = len(tasks)

    def on_finish(result: scheduler.TaskResult) -> None:
        done["n"] += 1
        mark = "ok  " if result.ok else "FAIL"
        print(f"  [{done['n']:>3}/{total}] {mark} {result.task.label} "
              f"({result.duration:.1f}s, {result.output_bytes / 1024:.0f} KB)")

    results = scheduler.run_tasks(
        tasks, jobs=jobs, timeout=plan.timeout, on_finish=on_finish
    )

    outcomes = triage.collect_outcomes(plan, results)
    pruned = triage.prune_empty_outputs(plan, outcomes)

    manifest_path = triage.write_manifest(
        plan, engine, outcomes,
        kernels=scan.kernels, image_sha256=scan.sha256, started_utc=started,
    )

    succeeded = [o for o in outcomes if o.ok]
    failed = [o for o in outcomes if not o.ok]

    print(f"\n{len(succeeded)}/{len(outcomes)} plugin(s) succeeded.")
    if pruned:
        print(f"Removed {pruned} empty output file(s); logs kept.")
    if failed:
        print("\nFailed:")
        for outcome in failed:
            print(f"  {outcome.plugin}: {outcome.status()}")
        print(f"\nPer-plugin logs: {output_dir / 'logs'}")
    print(f"\nManifest {manifest_path}")

    return 0 if not failed else 1


def cmd_fetch_symbols(args: argparse.Namespace) -> int:
    """Download and convert the symbols a request asks for. Internet side."""
    from . import fetch

    request_path = Path(args.request).expanduser()
    if not request_path.is_file():
        print(f"error: request not found: {request_path}", file=sys.stderr)
        return 2

    try:
        document = symbol_request.load(request_path)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out_dir = Path(args.out).expanduser() if args.out else default_symbols_dir()
    kernels = symbol_request.kernels_from(document, missing_only=not args.all)

    if not kernels:
        print("Nothing to fetch: every kernel in the request is already satisfied.")
        return 0

    image = document.get("image", {}).get("name", "unknown")
    print(f"Fetching symbols for {len(kernels)} kernel(s) from {image}")
    print(f"Writing to {out_dir}")

    work_dir = out_dir.parent / ".fetch-work"
    try:
        results = fetch.fetch_all(kernels, out_dir, work_dir)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    succeeded = [r for r in results if r.ok]
    failed = [r for r in results if not r.ok]

    print(f"\n{len(succeeded)} of {len(results)} symbol file(s) ready.")
    for result in failed:
        print(f"  failed: {result.kernel.pdb_name} {result.kernel.guid} — {result.error}")

    if succeeded:
        print(f"\nCopy this folder to the air-gapped machine:\n  {out_dir}")
        print("Then re-run the command that produced this request.")

    return 0 if not failed else 1


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
    print(f"  build         {build_identity()}")
    print(f"  commands      {', '.join(sorted(_COMMANDS))}")
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


#: Listed by doctor so a stale extract is obvious at a glance.
_COMMANDS = ("triage", "symbols", "fetch-symbols", "verify", "doctor")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="v4ag", description="Portable Volatility3 triage for air-gapped hosts"
    )
    parser.add_argument(
        "--version", action="version", version=f"v4ag {__version__} ({build_identity()})"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    triage_cmd = sub.add_parser("triage", help="run plugins against a memory image")
    triage_cmd.add_argument("--image", required=True, help="path to the memory image")
    triage_cmd.add_argument("--symbols", default=None, help="symbols directory")
    triage_cmd.add_argument("--out", default=None, help="output directory")
    triage_cmd.add_argument("--output", default=None, help="where to write symbol_request.json")
    triage_cmd.add_argument(
        "--plugins", default=None,
        help="comma-separated plugin names or categories (default: the triage set)",
    )
    triage_cmd.add_argument(
        "--all", action="store_true", help="run every discovered Windows plugin"
    )
    triage_cmd.add_argument(
        "--format", default="csv,json", help="output formats (default: csv,json)"
    )
    triage_cmd.add_argument(
        "--jobs", default="1", help="plugins to run concurrently, or 'auto' (default: 1)"
    )
    triage_cmd.add_argument(
        "--engine", default="auto", choices=["auto", "library", "exe"],
        help="which Volatility to drive (default: auto)",
    )
    triage_cmd.add_argument(
        "--timeout", type=float, default=3600.0, help="per-plugin timeout in seconds"
    )
    triage_cmd.add_argument(
        "--no-hash", action="store_true", help="skip the custody SHA-256"
    )
    triage_cmd.add_argument(
        "--force", action="store_true",
        help="run even if symbols are missing or the probe fails",
    )
    triage_cmd.set_defaults(func=cmd_triage)

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

    fetch_cmd = sub.add_parser(
        "fetch-symbols", help="download and convert symbols (internet-connected side)"
    )
    fetch_cmd.add_argument("request", help="path to symbol_request.json")
    fetch_cmd.add_argument("--out", default=None, help="where to write the symbols tree")
    fetch_cmd.add_argument(
        "--all", action="store_true", help="refetch every kernel, not only the missing"
    )
    fetch_cmd.set_defaults(func=cmd_fetch_symbols)

    doctor = sub.add_parser("doctor", help="report bundle health and import status")
    doctor.add_argument("--symbols", default=None, help="symbols directory")
    doctor.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
