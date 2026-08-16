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

    manifest_path = triage.write_manifest(
        plan, engine, outcomes,
        kernels=scan.kernels, image_sha256=scan.sha256, started_utc=started,
    )

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
    if failed:
        print("\nFailed:")
        for outcome in failed:
            print(f"  {outcome.plugin}: {outcome.status()}")
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
        prefix = "error: " if notice.level == "error" else "warning: "
        print(f"\n{prefix}{notice.message}", file=sys.stderr)
    if any(n.level == "error" for n in result.notices):
        return 1

    findings = rules_mod.evaluate(pack, result)
    findings_dir = output_dir / "findings"
    json_path, csv_path = rules_mod.write(findings_dir, pack, result, findings)

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

        try:
            engine = engine_mod.select(args.engine, BUNDLE_ROOT)
        except (engine_mod.EngineUnavailable, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        symbols_dir = (
            Path(args.symbols).expanduser() if args.symbols else default_symbols_dir()
        )
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
    "triage", "analyze", "symbols", "fetch-symbols", "verify", "doctor", "check"
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
