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
from .symbols import is_kernel, scan_image

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
    role = "required" if entry.get("required") else "optional"
    print(f"\n{label}{entry['pdb_name']}  GUID {entry['guid']}  age {entry['age']}  [{role}]")

    if entry.get("needed_by"):
        print(f"  needed by {', '.join(entry['needed_by'])}")

    if entry["present"]:
        print(f"  status    available at {entry['found_at']}")
        return

    print("  status    MISSING" if entry.get("required") else "  status    missing")
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

    if result.modules:
        print(
            f"Also found {len(result.modules)} module PDB(s) needed by specific plugins."
        )

    store = SymbolStore(symbols_dir)
    document = symbol_request.build(
        image, result.entries, store=store, image_sha256=result.sha256
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

    # Volatility needs exactly one kernel ISF: it scans the mapped kernel's
    # virtual space and asks for that single identity. Extra kernel-named records
    # in a physical scan are stale or coincidental copies, and some of those GUIDs
    # were never published by Microsoft — fetching them can only ever 404.
    kernel_covered = any(
        e["present"] for e in document["kernels"] if e.get("required")
    )

    # Module names for which no copy at all is available; a present copy of the
    # same name usually satisfies the plugin, since the loaded driver is the copy
    # most likely to still be intact in memory.
    by_name: dict[str, list[dict]] = {}
    for e in document["kernels"]:
        if not e.get("required"):
            by_name.setdefault(e["pdb_name"], []).append(e)
    uncovered_modules = {
        name: entries for name, entries in by_name.items()
        if not any(x["present"] for x in entries)
    }

    destination = Path(args.output) if args.output else Path.cwd() / symbol_request.FILENAME
    symbol_request.write(destination, document)

    print(f"\n{missing} of {total} symbol file(s) missing.")
    print(f"Wrote {destination}")

    if kernel_covered and not uncovered_modules:
        print("\nThe kernel symbol Volatility will use is already available, and every")
        print("module has at least one copy covered. The remaining records are extra")
        print("copies found in physical memory (old builds, update payloads, cached")
        print("data); some may not exist on Microsoft's server at all. Fetching them")
        print("is optional — 'triage' can run now.")
        return 0

    if kernel_covered:
        print("\nThe kernel is covered; only these plugins would be affected:")
        for name, entries in uncovered_modules.items():
            plugins = {p for e in entries for p in e.get("needed_by", [])}
            print(f"  {', '.join(sorted(plugins)) or name}")
        print("\nTo collect them, on an internet-connected machine run:")
        print(f"  v4ag.bat fetch-symbols {destination.name}")
        print("then copy the resulting symbols folder back here. 'triage' can run now")
        print("either way; those plugins are skipped-in-effect until the symbols land.")
        return 0

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
    kernels_present = [k for k in scan.kernels if store.has(k)]
    missing_kernels = store.missing(scan.kernels)
    missing_optional = store.missing(scan.modules)

    # A physical scan surfaces every kernel-named RSDS record in RAM, including
    # stale copies from before an update and coincidental data. Volatility itself
    # scans only the mapped kernel's virtual space and will ask for exactly one
    # identity — so one usable kernel ISF is the requirement, and the probe below
    # proves it is the right one. Demanding all of them blocks the run on records
    # Microsoft's server has never heard of.
    if not kernels_present and not args.force:
        document = symbol_request.build(
            image, scan.entries, store=store, image_sha256=scan.sha256
        )
        destination = Path(args.output or Path.cwd()) / symbol_request.FILENAME
        symbol_request.write(destination, document)
        print(f"\nNo usable kernel symbol file for any of the {len(scan.kernels)} "
              "kernel record(s) found; not running plugins.")
        for kernel in missing_kernels:
            print(f"  {kernel.pdb_name}  {kernel.download_url}")
        print(f"\nWrote {destination}. Run 'fetch-symbols' on a connected machine.")
        return 3

    if missing_kernels and kernels_present:
        print(f"\nNote: {len(missing_kernels)} other kernel-named record(s) in the "
              "image have no symbol file. These are usually stale copies in memory; "
              "the probe will confirm the symbols present match the running kernel.")

    if missing_optional:
        # Not fatal: only certain plugins need these. Say which, so the result is
        # not quietly incomplete. Warn hard only for module names with no copy at
        # all — when one copy is present, the run itself will show whether it was
        # the one the loaded driver wanted.
        from .symbols import needed_by as _needed_by

        by_name: dict[str, list] = {}
        for kernel in scan.modules:
            by_name.setdefault(kernel.pdb_name.lower(), []).append(kernel)

        uncovered = {
            name: ks for name, ks in by_name.items()
            if not any(store.has(k) for k in ks)
        }
        if uncovered:
            print("\nSome module symbols are missing. These plugins will fail:")
            for name, ks in uncovered.items():
                plugins_affected = ", ".join(_needed_by(name)) or "unknown"
                print(f"  {name:14s} -> {plugins_affected}")
            print("  Run 'symbols' and 'fetch-symbols' to collect them.")
        partially = sorted(
            name for name, ks in by_name.items()
            if name not in uncovered and any(not store.has(k) for k in ks)
        )
        if partially:
            print("\nNote: extra in-memory copies of "
                  f"{', '.join(partially)} have no symbol file; if the plugin that "
                  "needs the module fails, it wanted one of those copies.")

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

    pagefiles = []
    for raw in args.pagefile or []:
        candidate = Path(raw).expanduser()
        if not candidate.is_file():
            print(f"error: pagefile not found: {candidate}", file=sys.stderr)
            return 2
        pagefiles.append(candidate)

    plan = triage.TriagePlan(
        pagefiles=pagefiles,
        image=image,
        output_dir=output_dir,
        symbols_dir=symbols_dir,
        cache_dir=BUNDLE_ROOT / "cache",
        plugin_names=plugin_names,
        formats=formats,
        jobs=jobs,
        timeout=args.timeout,
    )

    # A zip stores no empty directories, so cache/ and output/ may not have
    # survived extraction. Create them rather than trusting the bundle.
    plan.ensure_directories()

    print(f"\nEngine {engine.name}, {len(plugin_names)} plugin(s), "
          f"formats {'+'.join(formats)}, jobs {jobs}")
    print(f"Output {output_dir}")
    for pagefile in pagefiles:
        print(f"Swap   {pagefile} ({pagefile.stat().st_size / 1e9:.2f} GB)")

    started = manifest.utc_now()

    probe = triage.run_probe(plan, engine)
    if not probe.ok:
        print("\nProbe failed, so the run would produce nothing useful.")
        print(triage.probe_diagnosis(probe))
        # Keep the log either way: it is the only record of the cause, and on a
        # forced run it is the only means of judging whether the output is sound.
        kept = triage.cleanup_probe(plan, keep_log=True)
        if kept is not None:
            print(f"\nFull probe log: {kept}")
        if not args.force:
            print("\nUse --force to run the plugins anyway.")
            return 4
        print("\n--force given: running plugins despite the failed probe. Results may")
        print("be incomplete or wrong; check the probe log above before relying on them.\n")
    else:
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
    dumps = triage.collect_dumps(plan)

    manifest_path = triage.write_manifest(
        plan, engine, outcomes,
        kernels=scan.kernels, image_sha256=scan.sha256, started_utc=started,
    )
    if not dumps:
        triage.prune_empty_dumps(plan)

    succeeded = [o for o in outcomes if o.ok]
    failed = [o for o in outcomes if not o.ok]

    print(f"\n{len(succeeded)}/{len(outcomes)} plugin(s) succeeded.")
    for outcome in succeeded:
        if outcome.rows is not None:
            print(f"  {outcome.rows:>7,} rows  {outcome.plugin}")

    warning = triage.layer_warning(plan, outcomes)
    if warning:
        print(f"\nWARNING: {warning}")
    if pruned:
        print(f"Removed {pruned} empty output file(s); logs kept.")
    if dumps:
        gb = triage.dumps_total_bytes(dumps) / 1e9
        print(f"\n{len(dumps):,} file(s) dumped to {plan.dumps_dir} ({gb:.2f} GB).")
        print("  A dumping plugin — windows.dumpfiles.DumpFiles in the --all set — "
              "carves every")
        print("  cached file object in the image. They are kept with the run, not "
              "written to")
        print("  the directory you launched from. Move or delete them once you have "
              "what you need.")
    if failed:
        print("\nFailed:")
        for outcome in failed:
            print(f"  {outcome.plugin}: {outcome.status()}")
            # Why, in the words that name the fix — so a plugin that merely
            # wanted an argument does not read like a broken image, and the
            # analyst is not sent to the log to find that out.
            note = triage.failure_note(outcome)
            if note:
                for line in note.splitlines():
                    print(f"    {line}")
        print(f"\nPer-plugin logs: {output_dir / 'logs'}")
    print(f"\nManifest {manifest_path}")

    if getattr(args, "follow_up", False):
        # The same analyser the standalone command runs, on the folder just
        # written. The image is already known to match, so the digest check is
        # skipped rather than re-hashing tens of gigabytes.
        print("\n" + "-" * 60)
        analyze_args = argparse.Namespace(
            output_dir=str(output_dir),
            image=str(image),
            rules=None,
            validate_rules=False,
            max_followups=10,
            dump=False,
            # The same swap layers triage just used. Without these the
            # follow-up reads a narrower image than the findings describe.
            pagefile=[str(p) for p in pagefiles] or None,
            no_pagefile=False,
            allow_modified_input=False,
            symbols=args.symbols,
            jobs=args.jobs,
            engine=args.engine,
            timeout=args.timeout,
            no_hash=True,
        )
        code = cmd_analyze(analyze_args)
        if code not in (0, 1):
            return code

    return 0 if not failed else 1


def _read_triage_manifest(output_dir: Path) -> dict | None:
    import json

    from . import manifest

    path = output_dir / manifest.FILENAME
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _resolve_pagefiles(
    output_dir: Path, args: argparse.Namespace
) -> tuple[list[Path], bool]:
    """The swap layers the triage run used, verified against its manifest.

    A follow-up that omits a pagefile reads a different memory image than the
    findings describe. A VAD, DLL or handle that resolved during triage because
    the swap layer supplied the paged-out bytes will simply be absent, and the
    targeted collection quietly contradicts the finding that asked for it.

    So the set is taken from ``run-manifest.json`` rather than from whatever the
    analyst happens to type, and each file is checked against the digest
    recorded there. ``--pagefile`` overrides the recorded *path* — the file may
    well have moved — but not the requirement that its contents match.
    """
    from . import manifest

    document = _read_triage_manifest(output_dir) or {}
    recorded = [p for p in document.get("pagefiles", []) if p.get("sha256")]

    supplied = [Path(raw).expanduser() for raw in (args.pagefile or [])]

    if not recorded:
        if supplied:
            print("\nwarning: the triage run recorded no pagefile, but "
                  f"{len(supplied)} was supplied. The follow-up will read a "
                  "different memory image than the findings describe.",
                  file=sys.stderr)
        return supplied, True

    candidates = supplied or [Path(entry["path"]) for entry in recorded]

    missing = [p for p in candidates if not p.is_file()]
    if missing:
        print(f"\nerror: the triage run used {len(recorded)} pagefile(s) and "
              "the follow-up must use the same one(s).", file=sys.stderr)
        for path in missing:
            print(f"  not found: {path}", file=sys.stderr)
        print("  Supply them with --pagefile PATH, or accept a narrower "
              "follow-up with --no-pagefile.", file=sys.stderr)
        return [], False

    if args.no_hash:
        print(f"\nUsing {len(candidates)} recorded pagefile(s) without "
              "verifying (--no-hash).")
        return candidates, True

    print(f"\nVerifying {len(candidates)} pagefile(s) against the triage "
          "manifest...")
    expected = {entry["sha256"] for entry in recorded}
    actual = {manifest.sha256_file(path) for path in candidates}
    if actual != expected:
        print("\nerror: pagefile contents do not match the triage run.",
              file=sys.stderr)
        for path in candidates:
            digest = manifest.sha256_file(path)
            mark = "ok " if digest in expected else "BAD"
            print(f"  {mark} {path}  {digest}", file=sys.stderr)
        print("  Findings derived from a different swap layer cannot be "
              "followed up against this one.", file=sys.stderr)
        return [], False

    return candidates, True


def _resolve_rule_pack(args: argparse.Namespace, output_dir: Path) -> Path:
    """Explicit pack, then a local override beside the outputs, then the bundled one."""
    from . import rules as rules_mod

    if args.rules:
        return Path(args.rules).expanduser()
    local = output_dir / "rules.json"
    return local if local.is_file() else rules_mod.DEFAULT_PACK


def cmd_analyze(args: argparse.Namespace) -> int:
    """Correlate a finished triage run into findings, and collect what they imply."""
    from . import (
        analysis as analysis_mod,
        engine as engine_mod,
        followup as followup_mod,
        manifest,
        rules as rules_mod,
        scheduler,
    )

    output_dir = Path(args.output_dir).expanduser()
    if not output_dir.is_dir():
        print(f"error: not a directory: {output_dir}", file=sys.stderr)
        return 2

    # Validated here rather than at the slice. A negative cap would otherwise
    # mean "every entity except the least severe" — silently dropping work,
    # which is worse than either an error or no cap at all.
    if args.max_followups < 1:
        print("error: --max-followups must be at least 1", file=sys.stderr)
        return 2

    try:
        jobs = scheduler.resolve_jobs(args.jobs)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    pack_path = _resolve_rule_pack(args, output_dir)
    try:
        pack = rules_mod.load(pack_path, known_actions=set(followup_mod.ACTIONS))
    except rules_mod.RulePackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.validate_rules:
        print(f"{pack_path}\n  {len(pack.rules)} rule(s), no problems found.")
        return 0

    if pack_path != rules_mod.DEFAULT_PACK:
        print(f"Using rules from {pack_path} (sha256 {pack.sha256[:12]}), "
              "not the bundled pack.")
        print("Findings will record this.")

    started = manifest.utc_now()

    # The run manifest hashed every output precisely so a consumer could prove
    # they had not changed. Reading them without checking discards that: the
    # analysis manifest would attest to findings derived from unverified bytes.
    inputs = analysis_mod.verify_inputs(output_dir)
    if inputs.manifest_absent:
        print("\nwarning: no usable digests in run-manifest.json, so the plugin "
              "output cannot be verified against the run that produced it.",
              file=sys.stderr)
    elif not inputs.ok:
        for name in sorted(inputs.modified):
            print(f"\nerror: {name} does not match its digest in "
                  f"{manifest.FILENAME}.", file=sys.stderr)
        for name in sorted(inputs.unattested):
            print(f"\nerror: {name} is not recorded in {manifest.FILENAME}; it "
                  "was added or replaced after the run.", file=sys.stderr)
        if not args.allow_modified_input:
            print("\n  Findings derived from these would not be defensible. "
                  "Re-run triage, or\n  pass --allow-modified-input to analyse "
                  "them anyway (recorded in the manifest).", file=sys.stderr)
            return 6
        print("\nwarning: proceeding with modified input on request. This is "
              "recorded in analysis-manifest.json.", file=sys.stderr)
    else:
        print(f"Verified {len(inputs.verified)} plugin output(s) against "
              f"{manifest.FILENAME}.")

    result = analysis_mod.analyse(output_dir)

    for notice in result.notices:
        # Label each level as itself. Printing an informational notice as
        # "warning:" is how warnings stop being read.
        prefix = {"error": "error: ", "warning": "warning: "}.get(
            notice.level, "note: "
        )
        stream = sys.stderr if notice.level in ("error", "warning") else sys.stdout
        print(f"\n{prefix}{notice.message}", file=stream)
    if any(n.level == "error" for n in result.notices):
        return 1

    findings = rules_mod.evaluate(pack, result)
    findings_dir = output_dir / "findings"

    summary = rules_mod.summarise(findings)
    print(f"\n{len(result.processes)} process(es), {len(result.modules)} module(s) "
          f"and {len(result.services)} service(s) examined, "
          f"{sum(result.plugins_read.values())} rows across "
          f"{len(result.plugins_read)} plugin(s).")

    if not findings:
        skipped = len(result.plugins_missing)
        print(f"No rules matched. {len(result.plugins_read)} plugin(s) evaluated, "
              f"{skipped} unavailable.")
    else:
        print(f"\n{summary['total']} finding(s): "
              + ", ".join(f"{summary[s]} {s}" for s in rules_mod.SEVERITIES if summary[s]))
        for finding in findings:
            print(f"  {finding.finding_id:10s} {finding.severity:8s} "
                  f"{finding.entity.label:34s} {finding.title}")

    blocked = rules_mod.not_evaluated(pack, result)
    for rule_id, reason in sorted(blocked.items()):
        print(f"  not evaluated: {rule_id} ({reason})")

    plan = followup_mod.plan(
        findings, max_followups=args.max_followups, allow_dump=args.dump
    )

    # Selected once, before the image branch: build_tasks needs it to run
    # follow-ups, and render_suggestions needs it to write the commands an
    # analyst runs by hand — which must be produced by the same builder, or the
    # two drift. Only fatal when an image was given and something must actually
    # run; otherwise suggestions degrade to a note and the rest still works.
    # Failure is not raised here: the diagnostics below (pagefile handling, the
    # image digest check) must still be reported in order, and an unavailable
    # engine only actually blocks the point where something has to run.
    engine = None
    engine_error = None
    try:
        engine = engine_mod.select(args.engine, BUNDLE_ROOT)
    except (engine_mod.EngineUnavailable, ValueError) as exc:
        engine_error = str(exc)

    symbols_dir = (
        Path(args.symbols).expanduser() if args.symbols else default_symbols_dir()
    )

    executed = 0
    followup_pagefiles: list[Path] = []
    if plan.pending and args.image:
        image = Path(args.image).expanduser()
        if not image.is_file():
            print(f"error: image not found: {image}", file=sys.stderr)
            return 2

        if not args.no_hash and not _image_matches(output_dir, image):
            return 5

        pagefiles: list[Path] = []
        if args.no_pagefile:
            recorded = (_read_triage_manifest(output_dir) or {}).get("pagefiles")
            if recorded:
                print(f"\nwarning: ignoring the {len(recorded)} pagefile(s) the "
                      "triage run used (--no-pagefile). Paged-out evidence the "
                      "findings rely on may be unreachable.", file=sys.stderr)
        else:
            pagefiles, ok = _resolve_pagefiles(output_dir, args)
            if not ok:
                return 5

        if engine is None:
            print(f"error: {engine_error}", file=sys.stderr)
            return 2

        tasks = followup_mod.build_tasks(
            plan,
            image=image,
            output_dir=output_dir,
            engine=engine,
            symbols_dir=symbols_dir,
            cache_dir=BUNDLE_ROOT / "cache",
            pagefiles=pagefiles,
        )
        followup_pagefiles = pagefiles

        print(f"\nRunning {len(tasks)} follow-up task(s)...")
        done = {"n": 0}

        def on_finish(task_result: scheduler.TaskResult) -> None:
            done["n"] += 1
            mark = "ok  " if task_result.ok else "FAIL"
            print(f"  [{done['n']:>3}/{len(tasks)}] {mark} {task_result.task.label} "
                  f"({task_result.duration:.1f}s)")

        results = scheduler.run_tasks(
            tasks, jobs=jobs, timeout=args.timeout, on_finish=on_finish,
        )
        followup_mod.record_results(plan, results)
        executed = sum(1 for r in results if r.ok)
    elif plan.pending:
        print(f"\n{len(plan.pending)} follow-up task(s) planned but not run.")
        print(f"  Execute with: v4ag analyze {output_dir} --image <image>")

    # Render the manual-collection commands, then write the findings — findings.txt
    # carries them, so it must be written after the plan exists rather than before.
    if plan.suggested:
        if engine is not None:
            followup_mod.render_suggestions(
                plan,
                output_dir=output_dir,
                engine=engine,
                symbols_dir=symbols_dir,
                cache_dir=BUNDLE_ROOT / "cache",
                image=Path(args.image).expanduser() if args.image else None,
                pagefiles=followup_pagefiles or None,
            )
        else:
            plan.notices.append(
                "Suggested dumps could not be written as commands: "
                f"{engine_error}"
            )

    json_path, csv_path = rules_mod.write(findings_dir, pack, result, findings, plan)
    steps_path = followup_mod.write(findings_dir, plan)
    for notice in plan.notices:
        print(f"\n{notice}")

    manifest.write(
        output_dir,
        manifest.build_analysis(
            output_dir=output_dir,
            rule_pack={
                "name": pack.name,
                "version": pack.version,
                "path": str(pack.path),
                "sha256": pack.sha256,
            },
            findings_summary=summary,
            not_evaluated=blocked,
            plugins_missing=result.plugins_missing,
            followups_executed=executed,
            input_check=inputs.as_dict(),
            pagefiles=[str(p) for p in followup_pagefiles],
            started_utc=started,
        ),
        filename=manifest.ANALYSIS_FILENAME,
    )

    print(f"\nFindings  {json_path}")
    print(f"          {csv_path}")
    print(f"          {findings_dir / 'findings.txt'}")
    print(f"Next steps {steps_path}")
    print(f"Manifest  {output_dir / manifest.ANALYSIS_FILENAME}")
    return 0


def _image_matches(output_dir: Path, image: Path) -> bool:
    """Refuse to gather evidence from an image the findings do not describe.

    A follow-up run against a different capture would produce output filed under
    a PID that means something else there, which is worse than no output at all.
    """
    import json

    from . import manifest

    triage_manifest = output_dir / manifest.FILENAME
    if not triage_manifest.is_file():
        print(f"\nwarning: no {manifest.FILENAME} here, so the image cannot be "
              "checked against the findings.", file=sys.stderr)
        return True

    try:
        recorded = json.loads(triage_manifest.read_text(encoding="utf-8"))
        expected = (recorded.get("image") or {}).get("sha256")
    except (OSError, ValueError):
        expected = None

    if not expected:
        print("\nwarning: the triage run recorded no image digest (--no-hash?), "
              "so the image cannot be checked.", file=sys.stderr)
        return True

    print(f"\nVerifying {image.name} against the triage manifest...")
    actual = manifest.sha256_file(image)
    if actual == expected:
        return True

    print("\nerror: this image is not the one triaged (sha256 mismatch).",
          file=sys.stderr)
    print(f"  manifest {expected}\n  supplied {actual}", file=sys.stderr)
    print("  Findings reference a different capture. Skip this check with "
          "--no-hash if that is intended.", file=sys.stderr)
    return False


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
    unavailable = [r for r in results if not r.ok and r.unavailable]
    failed = [r for r in results if not r.ok and not r.unavailable]

    print(f"\n{len(succeeded)} of {len(results)} symbol file(s) ready.")
    for result in failed:
        print(f"  failed: {result.kernel.pdb_name} {result.kernel.guid} — {result.error}")
    for result in unavailable:
        print(f"  unavailable: {result.kernel.pdb_name} {result.kernel.guid} — "
              "not on Microsoft's symbol server")

    if unavailable:
        print("\n'Unavailable' means Microsoft returned 404 for both the .pdb and .pd_")
        print("variants: no build with that GUID was ever published. Such records come")
        print("out of a physical-memory scan routinely (stale pages, update payloads,")
        print("cached data) and are not the copies Volatility asks for at run time.")

    # What matters is coverage, not a clean sweep: Volatility needs one kernel
    # ISF, and one copy per module name is normally the loaded one. Judge the trip
    # back on that, counting both what was already present and what just landed.
    covered = {
        e["pdb_name"].lower() for e in document["kernels"] if e.get("present")
    }
    covered |= {r.kernel.pdb_name.lower() for r in succeeded}
    all_names = {e["pdb_name"].lower() for e in document["kernels"]}
    kernel_covered = any(is_kernel(name) for name in covered)
    uncovered = sorted(
        name for name in all_names if not is_kernel(name) and name not in covered
    )

    if succeeded:
        print(f"\nCopy this folder to the air-gapped machine:\n  {out_dir}")
        print("Then re-run the command that produced this request.")

    if not kernel_covered:
        print("\nNo kernel symbol file could be produced; Volatility cannot run.")
        return 1
    if uncovered:
        print("\nNo copy could be produced for: " + ", ".join(uncovered) + ".")
        print("Only the plugins that need those modules are affected.")
    if failed:
        return 1
    print("\nEvery module Volatility can ask for is covered. Ready to run plugins.")
    return 0


FILELIST_NAME = "BUILD-FILES.sha256"


def cmd_check(args: argparse.Namespace) -> int:
    """Verify every bundled file against the digests recorded at build time.

    Exists because a corrupted bundle otherwise surfaces as an arbitrary downstream
    error — a replaced v4ag.bat reports '{' is not recognized as a command, which
    names nothing useful. Media carried between machines is exactly where silent
    corruption happens, so this must be answerable on the air-gapped host itself.
    """
    import hashlib

    filelist = BUNDLE_ROOT / FILELIST_NAME
    if not filelist.is_file():
        print(f"error: {FILELIST_NAME} not found; this is not a built bundle",
              file=sys.stderr)
        return 2

    expected: dict[str, str] = {}
    for line in filelist.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, _, relative = line.partition("  ")
        expected[relative] = digest

    modified, missing = [], []
    for relative, digest in sorted(expected.items()):
        path = BUNDLE_ROOT.joinpath(*relative.split("/"))
        if not path.is_file():
            missing.append(relative)
            continue
        actual = hashlib.sha256()
        try:
            with open(path, "rb") as handle:
                for block in iter(lambda: handle.read(1 << 20), b""):
                    actual.update(block)
        except OSError as exc:
            modified.append(f"{relative} (unreadable: {exc})")
            continue
        if actual.hexdigest() != digest:
            modified.append(relative)

    print(f"Checked {len(expected)} file(s) against {FILELIST_NAME}")
    print(f"  build   {build_identity()}")

    if not modified and not missing:
        print("\nBundle intact.")
        return 0

    if modified:
        print(f"\nMODIFIED ({len(modified)}):")
        for name in modified[:20]:
            print(f"  {name}")
        if len(modified) > 20:
            print(f"  ... and {len(modified) - 20} more")
    if missing:
        print(f"\nMISSING ({len(missing)}):")
        for name in missing[:20]:
            print(f"  {name}")
        if len(missing) > 20:
            print(f"  ... and {len(missing) - 20} more")

    print("\nRe-extract the bundle to a clean folder.")
    return 1


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

    if not missing:
        print(f"\nAll {len(kernels)} symbol file(s) present. Safe to return to the secure host.")
        return 0

    # The trip back is judged on coverage: one usable kernel ISF, and one copy per
    # module name. Records beyond that are stale or coincidental copies from the
    # physical scan, some of which Microsoft never published — they can stay
    # missing forever without affecting the run.
    kernel_candidates = [k for k in kernels if is_kernel(k.pdb_name)]
    kernel_covered = any(store.has(k) for k in kernel_candidates)
    module_names = {k.pdb_name.lower() for k in kernels if not is_kernel(k.pdb_name)}
    covered_modules = {
        k.pdb_name.lower() for k in kernels
        if not is_kernel(k.pdb_name) and store.has(k)
    }
    uncovered_modules = sorted(module_names - covered_modules)

    print(f"\n{len(missing)} of {len(kernels)} record(s) have no symbol file under {symbols_dir}")

    if kernel_candidates and not kernel_covered:
        print("No kernel symbol file is available; Volatility cannot run. Fetch at")
        print("least one kernel ISF before returning to the secure host.")
        return 3

    if uncovered_modules:
        print("Modules with no copy at all: " + ", ".join(uncovered_modules) + ".")
        print("Only the plugins needing them are affected; everything else can run.")
    else:
        print("The kernel and every module name are covered; the still-missing records")
        print("are extra in-memory copies. Safe to return to the secure host.")
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


def _results_dir(args: argparse.Namespace, image: Path) -> Path:
    """The same default `triage` uses, so everything about one image lands together."""
    return Path(args.out).expanduser() if args.out else BUNDLE_ROOT / "output" / image.stem


def _strings_file(image: Path, strings_dir: Path) -> Path:
    return strings_dir / f"{image.stem}.strings"


def cmd_strings(args: argparse.Namespace) -> int:
    """Write every string in the image, with its true offset, for windows.strings."""
    import time

    from . import manifest, strings as strings_mod

    image = Path(args.image).expanduser()
    if not image.is_file():
        print(f"error: image not found: {image}", file=sys.stderr)
        return 2
    if args.min_length < 1:
        print("error: --min-length must be at least 1", file=sys.stderr)
        return 2

    encodings = {
        "both": strings_mod.ENCODINGS, "ascii": ("ascii",), "unicode": ("unicode",),
    }[args.encoding]

    strings_dir = _results_dir(args, image) / "strings"
    output = _strings_file(image, strings_dir)
    if output.exists() and not args.overwrite:
        print(f"error: {output} already exists "
              f"({output.stat().st_size / 1e9:.2f} GB). Pass --overwrite to replace it.",
              file=sys.stderr)
        return 2
    strings_dir.mkdir(parents=True, exist_ok=True)

    size = image.stat().st_size
    print(f"Scanning {image.name} ({size / 1e9:.2f} GB) for strings of "
          f"{args.min_length}+ characters, {args.encoding}...")
    print(f"Output {output}")

    started = manifest.utc_now()
    clock = time.monotonic()
    shown = {"pct": 0}

    def progress(done: int, total: int, count: int) -> None:
        pct = done * 100 // max(total, 1)
        if pct < shown["pct"] + 10 and done < total:
            return
        shown["pct"] = pct - pct % 10
        elapsed = time.monotonic() - clock
        rate = done / elapsed / 1e6 if elapsed else 0.0
        remaining = (total - done) / (done / elapsed) if done and elapsed else 0.0
        print(f"  {done / 1e9:6.1f} of {total / 1e9:.1f} GB  {pct:3d}%  "
              f"{rate:5.0f} MB/s  {count:>12,} strings  ~{remaining / 60:.0f} min left",
              flush=True)

    result = strings_mod.extract(
        image, output, min_length=args.min_length, encodings=encodings, progress=progress
    )

    sidecar = output.with_name(output.name + ".json")
    manifest.write(
        strings_dir,
        {
            "tool": "v4ag strings",
            "version": __version__,
            "image": str(image),
            "strings_file": output.name,
            "started_utc": started,
            "finished_utc": manifest.utc_now(),
            **result.as_dict(),
        },
        filename=sidecar.name,
    )

    minutes, seconds = divmod(int(result.seconds), 60)
    print(f"\nWrote {output} ({output.stat().st_size / 1e9:.2f} GB): "
          f"{result.strings:,} strings ({result.ascii:,} ascii, {result.unicode:,} unicode) "
          f"in {minutes}m{seconds:02d}s")
    print(f"Next: v4ag strings-hits --image \"{image}\" --strings-file \"{output}\" "
          f"--term TEXT [--term TEXT ...]"
          + (f" --out \"{args.out}\"" if args.out else ""))
    return 0


def _read_terms(args: argparse.Namespace) -> list[str]:
    terms = [t for t in (args.term or []) if t]
    if args.terms_file:
        path = Path(args.terms_file).expanduser()
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                terms.append(line)
    return terms


def cmd_strings_hits(args: argparse.Namespace) -> int:
    """Search a strings file, put its offsets right, and ask the plugin who holds each hit."""
    from . import (
        analysis as analysis_mod,
        engine as engine_mod,
        manifest,
        scheduler,
        strings as strings_mod,
        triage,
    )

    image = Path(args.image).expanduser()
    if not image.is_file():
        print(f"error: image not found: {image}", file=sys.stderr)
        return 2

    results_dir = _results_dir(args, image)
    strings_dir = results_dir / "strings"
    strings_file = (
        Path(args.strings_file).expanduser() if args.strings_file
        else _strings_file(image, strings_dir)
    )
    if not strings_file.is_file():
        print(f"error: no strings file at {strings_file}", file=sys.stderr)
        print("  Make one with 'v4ag strings --image ...', or point --strings-file at "
              "one made by another tool.", file=sys.stderr)
        return 2

    try:
        terms = _read_terms(args)
    except OSError as exc:
        print(f"error: cannot read terms: {exc}", file=sys.stderr)
        return 2
    if not terms:
        print("error: no search terms. Give --term TEXT (repeat for several) or "
              "--terms-file FILE, one per line.", file=sys.stderr)
        return 2
    if args.max_hits < 1:
        print("error: --max-hits must be at least 1", file=sys.stderr)
        return 2

    strings_dir.mkdir(parents=True, exist_ok=True)
    started = manifest.utc_now()

    print(f"Searching {strings_file.name} ({strings_file.stat().st_size / 1e9:.2f} GB) "
          f"for {len(terms)} term(s)...")
    scan = strings_mod.scan_hits(
        strings_file, terms, ignore_case=not args.case_sensitive, max_hits=args.max_hits,
    )
    detail = f", {scan.unparsed} unparseable" if scan.unparsed else ""
    print(f"  {scan.lines:,} line(s); {len(scan.hits):,} matched{detail}")
    if scan.truncated:
        print(f"\nerror: stopped at {args.max_hits:,} hits. Terms this broad would give "
              "the plugin more than it can usefully attribute; narrow them, or raise "
              "--max-hits.", file=sys.stderr)
        return 2
    if not scan.hits:
        print("No line matched. Nothing to run.")
        return 0

    image_size = image.stat().st_size
    location = None
    if args.trust_offsets:
        print("  offsets taken as written (--trust-offsets)")
        lines = strings_mod.plugin_lines(scan.hits, wrapped=False, trust=True)
    else:
        print(f"Checking each hit against {image.name}...")
        location = strings_mod.locate(image, scan.hits)
        if location.wrapped:
            print(f"  {location.relocated} hit(s) are not where their offsets say, but "
                  "exactly a multiple of 4 GiB further on: the file has 32-bit offsets,")
            print("  as Sysinternals strings.exe writes them. Using where the bytes "
                  "actually are.")
        if location.at_stated:
            print(f"  {location.at_stated} hit(s) at their stated offset")
        if location.unresolved:
            print(f"  {location.unresolved} hit(s) not in the image at any candidate "
                  "offset; kept out of the plugin's input, listed in "
                  "strings-hits-unresolved.txt")
        if scan.max_offset < strings_mod.WRAP <= image_size:
            print(f"  (no offset in the file exceeds 4 GiB although the image is "
                  f"{image_size / 2**30:.1f} GiB; the sequence restarts {scan.drops} time(s))")
        if not location.at_stated and not location.relocated:
            # None of the hits resolved. Two different situations look identical
            # here, so tell them apart before crying "wrong file". If the offsets
            # are structurally those of a wrapped 32-bit strings file of THIS image
            # — none above 4 GiB though the image is larger, and the sequence
            # restarting where it folds — the file is almost certainly the right
            # one, and these particular terms simply landed on strings with no
            # stable page of their own (AV-signature buffers, transient scan text).
            # Warn and keep the run rather than reject a good file on an
            # unrepresentative handful of hits. Only with no such evidence is a
            # mismatched file the likely cause, and only then is exit 5 earned.
            wrapped_structure = (
                scan.drops > 0 and scan.max_offset < strings_mod.WRAP <= image_size
            )
            if not wrapped_structure:
                print("\nerror: none of the hits is in this image at its offset or at any "
                      "4 GiB multiple of it. Is this the strings file for this image?",
                      file=sys.stderr)
                return 5
            print("\nwarning: none of these hits resolves to a page in the image, but the "
                  "file's offsets are those of a wrapped 32-bit strings file of this image, "
                  "so it is most likely the right one — these particular strings just have "
                  "no stable location. Search for a term you know is genuinely present.",
                  file=sys.stderr)
        lines = strings_mod.plugin_lines(scan.hits, wrapped=location.wrapped)

    hits_path = strings_dir / "strings-hits.txt"
    hits_payload = b"".join(lines)
    hits_path.write_bytes(hits_payload)
    unresolved_path = strings_dir / "strings-hits-unresolved.txt"
    unresolved = strings_mod.unresolved_lines(scan.hits) if location is not None else []
    if unresolved:
        unresolved_path.write_bytes(b"".join(unresolved))
    elif unresolved_path.exists():
        unresolved_path.unlink()
    print(f"Wrote {hits_path} ({len(lines)} line(s))")

    record: dict = {
        "tool": "v4ag strings-hits",
        "version": __version__,
        "image": str(image),
        "image_size": image_size,
        "strings_file": str(strings_file),
        "strings_file_size": scan.size,
        "terms": terms,
        "ignore_case": not args.case_sensitive,
        "lines_searched": scan.lines,
        "hits": len(scan.hits),
        "offsets": (
            "trusted" if location is None
            else "wrapped, relocated" if location.wrapped
            else "exact"
        ),
        "at_stated_offset": None if location is None else location.at_stated,
        "relocated": None if location is None else location.relocated,
        "unresolved": len(unresolved),
        "plugin_input": {
            "file": hits_path.name,
            "lines": len(lines),
            # Hash the bytes we still hold, not a reopen of the file: this output
            # is nothing but attacker command lines, and the host's own AV
            # quarantines or locks it the instant it lands. A reopen here is what
            # crashed the run before the plugin even started.
            "sha256": manifest.sha256_bytes(hits_payload),
        },
        "started_utc": started,
    }

    code = 0
    if not lines:
        # Only reached via the softened case above: the file looks right, but
        # these terms resolved to nothing the plugin could place. Running it on an
        # empty input would build the whole reverse map to attribute zero lines;
        # the warning already said why.
        print("\nNo hit resolved to a page, so windows.strings was not run — it "
              "would have nothing to attribute.")
    elif not args.no_run:
        try:
            engine = engine_mod.select(args.engine, BUNDLE_ROOT)
        except (engine_mod.EngineUnavailable, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        symbols_dir = (
            Path(args.symbols).expanduser() if args.symbols else default_symbols_dir()
        )
        cache_dir = BUNDLE_ROOT / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)

        # The plugin's own arguments come last, --pid last of all: it takes
        # nargs='+' and would swallow anything after it.
        plugin_args = ["--strings-file", str(hits_path)]
        if args.pid:
            plugin_args += ["--pid", *[str(p) for p in args.pid]]

        task = scheduler.Task(
            key=strings_mod.PLUGIN,
            label=strings_mod.PLUGIN,
            command=engine.command(
                image, strings_mod.PLUGIN, "json",
                symbols_dir=symbols_dir, cache_dir=cache_dir, plugin_args=plugin_args,
            ),
            stdout_path=strings_dir / f"{strings_mod.PLUGIN}.json",
            stderr_path=strings_dir / "logs" / f"{strings_mod.PLUGIN}.json.log",
        )
        print(f"\nRunning {strings_mod.PLUGIN} on {len(lines)} line(s) "
              f"(engine {engine.name}; the reverse map takes a while on a large image)...")
        result = scheduler.run_tasks([task], jobs=1, timeout=args.timeout)[0]
        record["plugin"] = {
            "name": strings_mod.PLUGIN,
            "command": engine_mod.render_command(task.command),
            "status": result.status,
            "seconds": round(result.duration, 1),
            "output": task.stdout_path.name,
            "log": str(task.stderr_path.relative_to(strings_dir)),
        }
        if result.ok:
            print(f"  ok ({result.duration:.1f}s)")
            rows = analysis_mod.load_rows(task.stdout_path)
            record["plugin"]["rows"] = len(rows)
            # The subprocess wrote this one, so its bytes are not in hand; hash it
            # from disk, but never let a late quarantine of it discard a run that
            # has already succeeded.
            try:
                record["plugin"]["sha256"] = manifest.sha256_file(task.stdout_path)
            except OSError:
                record["plugin"]["sha256"] = None

            names: dict[int, str] = {}
            pslist = analysis_mod.output_json_path(results_dir, "windows.pslist.PsList")
            if pslist.is_file():
                try:
                    names = strings_mod.process_names(analysis_mod.load_rows(pslist))
                except ValueError:
                    names = {}

            groups = strings_mod.group_rows(rows, names)
            print()
            for line in strings_mod.report_lines(groups, width=100, per_group=8):
                print(strings_mod.console_safe(line))

            report_path = strings_dir / "strings-hits-report.txt"
            header = [
                f"windows.strings.Strings over {len(lines)} line(s) matching "
                f"{len(terms)} term(s): {', '.join(terms)}",
                f"image {image}",
                f"strings file {strings_file}",
                f"run {record['started_utc']}",
                "",
            ]
            report_bytes = (
                "\n".join(header + strings_mod.report_lines(groups)) + "\n"
            ).encode("utf-8")
            report_path.write_bytes(report_bytes)
            record["report"] = {
                "file": report_path.name,
                # Same reasoning as the hits file: hash what we just wrote, in
                # memory, so the record survives AV touching the report on disk.
                "sha256": manifest.sha256_bytes(report_bytes),
            }
            print(f"\nReport {report_path}")
            print(f"Table  {task.stdout_path}")
        else:
            print(f"  FAIL {result.status}")
            diagnosis = triage.failure_diagnosis(result)
            if diagnosis:
                for line in diagnosis.splitlines():
                    print(f"    {line}")
            print(f"  Log {task.stderr_path}")
            code = 1

    record["finished_utc"] = manifest.utc_now()
    manifest_path = manifest.write(strings_dir, record, filename="strings-hits.json")
    print(f"Record {manifest_path}")
    return code


def cmd_strings_map(args: argparse.Namespace) -> int:
    """Attribute a whole strings file at once, to a grep-able CSV, building the map once."""
    from . import engine as engine_mod, manifest, scheduler, strings as strings_mod, triage

    image = Path(args.image).expanduser()
    if not image.is_file():
        print(f"error: image not found: {image}", file=sys.stderr)
        return 2

    results_dir = _results_dir(args, image)
    strings_dir = results_dir / "strings"
    strings_file = (
        Path(args.strings_file).expanduser() if args.strings_file
        else _strings_file(image, strings_dir)
    )
    if not strings_file.is_file():
        print(f"error: no strings file at {strings_file}", file=sys.stderr)
        print("  Make one with 'v4ag strings --image ...', or point --strings-file at "
              "one made by another tool.", file=sys.stderr)
        return 2

    output = strings_dir / "strings-map.csv"
    if output.exists() and not args.overwrite:
        print(f"error: {output} already exists "
              f"({output.stat().st_size / 1e9:.2f} GB). Pass --overwrite to replace it.",
              file=sys.stderr)
        return 2

    image_size = image.stat().st_size
    print(f"Probing {strings_file.name} "
          f"({strings_file.stat().st_size / 1e9:.2f} GB) offsets...")
    probe = strings_mod.probe_offsets(strings_file)
    if probe.max_offset < 0:
        print("error: no offset:string lines found in this file; is it a strings file?",
              file=sys.stderr)
        return 2
    print(f"  {probe.lines:,} line(s); largest offset {probe.max_offset / 2**30:.1f} GiB")

    # Unlike strings-hits, this run does no per-line offset repair — it cannot, at
    # whole-file scale — so a wrapped 32-bit strings file would attribute every
    # string past 4 GiB to the wrong page. Refuse it: nothing here reaches 4 GiB
    # though the image is larger, which is exactly what a Sysinternals -o file of a
    # large image looks like. --force attributes it as written anyway.
    if probe.max_offset < strings_mod.WRAP <= image_size and not args.force:
        print(f"\nerror: no offset in this file reaches 4 GiB, although the image is "
              f"{image_size / 2**30:.1f} GiB. This is what a Sysinternals 32-bit strings "
              "file looks like; its offsets wrap, and attributing it whole would place "
              "every string past 4 GiB on the wrong process.", file=sys.stderr)
        print("  Regenerate the file with 'v4ag strings' (true offsets at any size), or "
              "pass --force to attribute it exactly as written.", file=sys.stderr)
        return 5

    try:
        engine = engine_mod.select(args.engine, BUNDLE_ROOT)
    except (engine_mod.EngineUnavailable, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    symbols_dir = (
        Path(args.symbols).expanduser() if args.symbols else default_symbols_dir()
    )
    cache_dir = BUNDLE_ROOT / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    strings_dir.mkdir(parents=True, exist_ok=True)

    plugin_args = ["--strings-file", str(strings_file)]
    if args.pid:
        plugin_args += ["--pid", *[str(p) for p in args.pid]]

    started = manifest.utc_now()
    task = scheduler.Task(
        key=strings_mod.PLUGIN,
        label=strings_mod.PLUGIN,
        command=engine.command(
            image, strings_mod.PLUGIN, "csv",
            symbols_dir=symbols_dir, cache_dir=cache_dir, plugin_args=plugin_args,
        ),
        stdout_path=output,
        stderr_path=strings_dir / "logs" / "strings-map.csv.log",
    )
    print(f"\nAttributing all {probe.lines:,} line(s) with {strings_mod.PLUGIN} "
          f"(engine {engine.name}). The reverse map is built once — on a large image "
          "that is the slow part, tens of minutes to an hour.")
    result = scheduler.run_tasks([task], jobs=1, timeout=args.timeout)[0]

    record: dict = {
        "tool": "v4ag strings-map",
        "version": __version__,
        "image": str(image),
        "image_size": image_size,
        "strings_file": str(strings_file),
        "strings_file_size": strings_file.stat().st_size,
        "lines": probe.lines,
        "max_offset": probe.max_offset,
        "offsets": "forced" if args.force else "structural",
        "pids": args.pid or None,
        "output": output.name,
        "status": result.status,
        "seconds": round(result.duration, 1),
        "log": str(task.stderr_path.relative_to(strings_dir)),
        "started_utc": started,
        "finished_utc": manifest.utc_now(),
    }

    code = 0
    if result.ok:
        # The CSV is huge and written by the subprocess, so it is recorded by size,
        # not hashed: a whole-image run makes tens of millions of rows, and reading
        # them all back to hash would add minutes for little custody value on a
        # derived, greppable artifact.
        size = output.stat().st_size if output.exists() else 0
        record["output_size"] = size
        print(f"\nWrote {output} ({size / 1e9:.2f} GB) in {result.duration / 60:.0f} min")
        print("Columns: String, Physical Address, Result (the owner, FREE MEMORY, or "
              "kernel). Grep it for any term now — no more map builds:")
        print(f'  findstr /i "some.ioc" "{output}"')
    else:
        print(f"\nFAIL {result.status}")
        diagnosis = triage.failure_diagnosis(result)
        if diagnosis:
            for line in diagnosis.splitlines():
                print(f"    {line}")
        print(f"  Log {task.stderr_path}")
        code = 1

    manifest_path = manifest.write(strings_dir, record, filename="strings-map.json")
    print(f"Record {manifest_path}")
    return code


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
_COMMANDS = (
    "triage", "analyze", "strings", "strings-hits", "strings-map", "symbols",
    "fetch-symbols", "verify", "doctor", "check",
)


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
        "--pagefile", action="append", default=None, metavar="PATH",
        help="pagefile.sys to include as a swap layer; repeat for several",
    )
    triage_cmd.add_argument(
        "--force", action="store_true",
        help="run even if symbols are missing or the probe fails",
    )
    triage_cmd.add_argument(
        "--follow-up", action="store_true",
        help="analyse the results afterwards and collect the follow-up evidence",
    )
    triage_cmd.set_defaults(func=cmd_triage)

    analyze = sub.add_parser(
        "analyze",
        help="correlate a finished triage run into findings",
        description=(
            "Reads the JSON a triage run wrote, correlates it into one record per "
            "process, and applies a rule pack. Needs no memory image unless "
            "--image is given to collect the follow-up evidence as well."
        ),
    )
    analyze.add_argument("output_dir", help="a triage output directory")
    analyze.add_argument(
        "--image", default=None,
        help="the image that was triaged; supply it to run the follow-ups too",
    )
    analyze.add_argument(
        "--rules", default=None,
        help="rule pack to use (default: rules.json here, else the bundled pack)",
    )
    analyze.add_argument(
        "--validate-rules", action="store_true",
        help="check the rule pack and exit without analysing",
    )
    analyze.add_argument(
        "--max-followups", type=int, default=10, metavar="N",
        help="entities to follow up, most severe first (default: 10)",
    )
    analyze.add_argument(
        "--dump", action="store_true",
        help="also execute dump actions; endpoint protection may quarantine the results",
    )
    analyze.add_argument("--symbols", default=None, help="symbols directory")
    analyze.add_argument(
        "--jobs", default="1", help="follow-ups to run concurrently, or 'auto'"
    )
    analyze.add_argument(
        "--engine", default="auto", choices=["auto", "library", "exe"],
        help="which Volatility to drive (default: auto)",
    )
    analyze.add_argument(
        "--timeout", type=float, default=3600.0, help="per-task timeout in seconds"
    )
    analyze.add_argument(
        "--pagefile", action="append", default=None, metavar="PATH",
        help="where the triage run's pagefile lives now, if it has moved",
    )
    analyze.add_argument(
        "--no-pagefile", action="store_true",
        help="run follow-ups without the swap layer triage used",
    )
    analyze.add_argument(
        "--allow-modified-input", action="store_true",
        help="analyse plugin output that no longer matches the run manifest",
    )
    analyze.add_argument(
        "--no-hash", action="store_true",
        help="skip checking the image and pagefiles against the triage manifest",
    )
    analyze.set_defaults(func=cmd_analyze)

    strings_cmd = sub.add_parser(
        "strings",
        help="write every string in the image, with true offsets, for windows.strings",
        description=(
            "Walks the image once and writes offset:string lines to "
            "<out>\\strings\\<image>.strings — the file windows.strings.Strings takes "
            "as --strings-file. Offsets are exact at any image size, which is the "
            "point: Sysinternals strings.exe prints 32-bit offsets, and on an image "
            "over 4 GiB those wrap and the plugin attributes strings to the wrong "
            "process without any sign of it."
        ),
    )
    strings_cmd.add_argument("--image", required=True, help="path to the memory image")
    strings_cmd.add_argument(
        "--out", default=None, help="results directory (default: output\\<image>)"
    )
    strings_cmd.add_argument(
        "--min-length", type=int, default=4, metavar="N",
        help="shortest string to keep, in characters (default: 4)",
    )
    strings_cmd.add_argument(
        "--encoding", default="both", choices=["both", "ascii", "unicode"],
        help="ASCII, UTF-16LE, or both (default: both)",
    )
    strings_cmd.add_argument(
        "--overwrite", action="store_true", help="replace an existing strings file"
    )
    strings_cmd.set_defaults(func=cmd_strings)

    hits = sub.add_parser(
        "strings-hits",
        help="search a strings file for terms and ask windows.strings who holds each hit",
        description=(
            "Searches a strings file for your terms, checks every hit against the "
            "image — which finds and corrects the wrapped 32-bit offsets a "
            "Sysinternals strings file has on a large image — writes the plugin-ready "
            "hits to <out>\\strings\\strings-hits.txt, and runs "
            "windows.strings.Strings on it to say which process, kernel region or "
            "free page each hit is in."
        ),
    )
    hits.add_argument("--image", required=True, help="path to the memory image")
    hits.add_argument(
        "--strings-file", default=None,
        help="the strings file to search (default: the one 'strings' wrote for this image)",
    )
    hits.add_argument(
        "--term", action="append", default=None, metavar="TEXT",
        help="text to look for; repeat for several",
    )
    hits.add_argument(
        "--terms-file", default=None, metavar="FILE",
        help="a file of terms, one per line; # starts a comment",
    )
    hits.add_argument(
        "--case-sensitive", action="store_true", help="match case (default: ignore it)"
    )
    hits.add_argument(
        "--max-hits", type=int, default=50000, metavar="N",
        help="stop if more lines than this match (default: 50000)",
    )
    hits.add_argument(
        "--trust-offsets", action="store_true",
        help="do not check the hits against the image; pass the file's offsets through",
    )
    hits.add_argument(
        "--out", default=None, help="results directory (default: output\\<image>)"
    )
    hits.add_argument(
        "--no-run", action="store_true", help="write the hits file but do not run the plugin"
    )
    hits.add_argument(
        "--pid", action="append", type=int, default=None, metavar="PID",
        help="map only these processes (faster; other hits then show as FREE MEMORY)",
    )
    hits.add_argument("--symbols", default=None, help="symbols directory")
    hits.add_argument(
        "--engine", default="auto", choices=["auto", "library", "exe"],
        help="which Volatility to drive (default: auto)",
    )
    hits.add_argument(
        "--timeout", type=float, default=3600.0, help="plugin timeout in seconds"
    )
    hits.set_defaults(func=cmd_strings_hits)

    strings_map = sub.add_parser(
        "strings-map",
        help="attribute a whole strings file at once to a grep-able CSV",
        description=(
            "Runs windows.strings.Strings over the entire strings file in one pass "
            "and writes <out>\\strings\\strings-map.csv (columns String, Physical "
            "Address, Result). The reverse map that says which process, kernel region "
            "or free page holds each string is built once, so a hundred later greps "
            "cost nothing — where 'strings-hits' rebuilds it per search. The whole-file "
            "run does no offset repair, so it needs a true-offset file: this tool's "
            "'strings' output, or GNU 'strings -td'. A wrapped Sysinternals file is "
            "refused unless --force, because its offsets would misattribute everything "
            "past 4 GiB."
        ),
    )
    strings_map.add_argument("--image", required=True, help="path to the memory image")
    strings_map.add_argument(
        "--strings-file", default=None,
        help="the strings file to attribute (default: the one 'strings' wrote for this image)",
    )
    strings_map.add_argument(
        "--out", default=None, help="results directory (default: output\\<image>)"
    )
    strings_map.add_argument(
        "--force", action="store_true",
        help="attribute even a file whose offsets look wrapped (32-bit); offsets used as written",
    )
    strings_map.add_argument(
        "--overwrite", action="store_true", help="replace an existing strings-map.csv"
    )
    strings_map.add_argument(
        "--pid", action="append", type=int, default=None, metavar="PID",
        help="map only these processes (faster; other strings then show as FREE MEMORY)",
    )
    strings_map.add_argument("--symbols", default=None, help="symbols directory")
    strings_map.add_argument(
        "--engine", default="auto", choices=["auto", "library", "exe"],
        help="which Volatility to drive (default: auto)",
    )
    strings_map.add_argument(
        "--timeout", type=float, default=14400.0, help="plugin timeout in seconds"
    )
    strings_map.set_defaults(func=cmd_strings_map)

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

    check = sub.add_parser("check", help="verify bundled files against their build digests")
    check.set_defaults(func=cmd_check)

    doctor = sub.add_parser("doctor", help="report bundle health and import status")
    doctor.add_argument("--symbols", default=None, help="symbols directory")
    doctor.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
