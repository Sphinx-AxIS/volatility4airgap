"""The triage run: probe, then plugins, then a manifest.

Order matters here. Before committing to a long run the tool executes one cheap
plugin on its own. That does two jobs at once:

- It proves symbols actually resolve. If they do not, the analyst gets a single
  clear error instead of twenty-nine confusing ones.
- It warms Volatility's SQLite cache. That is not merely an optimisation: the
  bundled 800 MB ``windows.zip`` is only reachable *through* the cache, because
  the path-based lookup globs for a zip named after the symbol and never matches
  a pack. Warming must also happen serially — concurrent workers populating the
  same SQLite file produce intermittent "database is locked" failures.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import manifest, plugins as plugin_catalog, scheduler
from .engine import VolEngine, render_command
from .symbols import KernelPdb


@dataclass
class TriagePlan:
    image: Path
    output_dir: Path
    symbols_dir: Path
    cache_dir: Path
    plugin_names: list[str]
    formats: list[str]
    jobs: int = 1
    timeout: float = 3600.0
    pagefiles: list[Path] = field(default_factory=list)

    def ensure_directories(self) -> None:
        """Create the directories a run writes into.

        Never assume the bundle shipped them. A zip archive stores no entry for an
        empty directory, so ``cache/`` and ``output/`` do not survive extraction —
        and Volatility fails with a bare ``FileNotFoundError`` on
        ``identifier.cache`` rather than anything an analyst could act on. Copying
        a bundle with tools that skip empty directories has the same effect.
        """
        for directory in (self.output_dir, self.cache_dir):
            directory.mkdir(parents=True, exist_ok=True)


def count_rows(path: Path) -> int:
    """Data rows in a CSV output, excluding the header.

    A plugin can exit 0 having produced only a header. For pslist on a Windows
    image that means the layer is not mapping memory — commonly a .vmem opened
    without its .vmss/.vmsn companion — and reporting it as success hides the one
    fact the analyst needs.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return max(0, sum(1 for _ in handle) - 1)
    except OSError:
        return 0


@dataclass
class PluginOutcome:
    plugin: str
    results: dict = field(default_factory=dict)  # format -> TaskResult
    rows: int | None = None

    @property
    def ok(self) -> bool:
        return bool(self.results) and all(r.ok for r in self.results.values())

    @property
    def duration(self) -> float:
        return max((r.duration for r in self.results.values()), default=0.0)

    def status(self) -> str:
        if self.ok:
            return "ok"
        broken = [f"{fmt}: {r.status}" for fmt, r in self.results.items() if not r.ok]
        return "; ".join(broken) or "no output"


def output_path(output_dir: Path, plugin: str, fmt: str) -> Path:
    """Filenames match CORE-Respond's ingest convention, e.g.
    ``windows.pslist.PsList.csv``."""
    safe = plugin.replace("/", "_").replace("\\", "_")
    return output_dir / f"{safe}.{fmt}"


def log_path(output_dir: Path, plugin: str, fmt: str) -> Path:
    safe = plugin.replace("/", "_").replace("\\", "_")
    return output_dir / "logs" / f"{safe}.{fmt}.log"


def build_tasks(plan: TriagePlan, engine: VolEngine) -> list[scheduler.Task]:
    tasks = []
    for plugin in plan.plugin_names:
        for fmt in plan.formats:
            tasks.append(
                scheduler.Task(
                    key=f"{plugin}:{fmt}",
                    label=f"{plugin} ({fmt})",
                    command=engine.command(
                        plan.image,
                        plugin,
                        fmt,
                        symbols_dir=plan.symbols_dir,
                        cache_dir=plan.cache_dir,
                        swap_files=plan.pagefiles,
                    ),
                    stdout_path=output_path(plan.output_dir, plugin, fmt),
                    stderr_path=log_path(plan.output_dir, plugin, fmt),
                )
            )
    return tasks


def run_probe(plan: TriagePlan, engine: VolEngine, *, log=print) -> scheduler.TaskResult:
    """Run one plugin serially to validate symbols and warm the cache."""
    probe_dir = plan.output_dir / ".probe"
    task = scheduler.Task(
        key="probe",
        label=plugin_catalog.PROBE,
        command=engine.command(
            plan.image,
            plugin_catalog.PROBE,
            "json",
            symbols_dir=plan.symbols_dir,
            cache_dir=plan.cache_dir,
            swap_files=plan.pagefiles,
        ),
        stdout_path=probe_dir / "probe.json",
        stderr_path=probe_dir / "probe.log",
    )

    log(f"Probing with {plugin_catalog.PROBE} (validates symbols, warms the cache)...")

    # Indexing the 800 MB symbol pack takes minutes and prints nothing while it
    # happens. Unannounced, that reads as a hang and invites a Ctrl-C at exactly
    # the wrong moment. It is paid once per bundle location.
    cache_db = plan.cache_dir / "identifier.cache"
    if not cache_db.exists() and any(plan.symbols_dir.rglob("*.zip")):
        log("  First run with a symbol pack: indexing it may take a few minutes.")
        log("  This happens once. Subsequent runs start immediately.")
    (result,) = scheduler.run_tasks([task], jobs=1, timeout=plan.timeout)
    return result


#: Root causes Volatility reports as a *warning* partway through its log, while the
#: final line states only the consequence — usually "Unable to validate the plugin
#: requirements: ['plugins.Info.kernel.layer_name', ...]". Reading just the last line
#: therefore reports the symptom and throws away the answer, which is precisely what a
#: stuck analyst needs. Each entry maps a fragment of Volatility's own message to an
#: explanation that names the fix.
_KNOWN_CAUSES: tuple[tuple[str, str], ...] = (
    (
        "no metadata file found alongside vmem",
        "This VMEM has no VMSS/VMSN metadata file that Volatility could pair with it.\n"
        "  The companion must be in the SAME folder with the SAME basename:\n"
        "      image.vmem  ->  image.vmss   (tried first)\n"
        "      image.vmem  ->  image.vmsn   (tried only if no .vmss)\n"
        "  Volatility derives the name by replacing the extension, so renaming the\n"
        "  VMEM without renaming its companion breaks the pairing. A VMSN belonging\n"
        "  to a different snapshot will not match either.\n"
        "  The metadata carries the guest's memory-region map. Without it the file\n"
        "  cannot be translated above the 4 GB PCI hole, so no kernel layer is built.",
    ),
    (
        "invalid vmware",
        "The VMSS/VMSN beside this VMEM could not be parsed. It may be truncated, or\n"
        "  may belong to a different snapshot than the VMEM.",
    ),
    # crashinfo logs this and then does a bare `raise`, so the last line of its
    # log is "RuntimeError: No active exception to reraise" — which quoted on
    # its own reads as a bug rather than the plain fact that this image is not
    # a crash dump.
    (
        "this plugin requires a windows crash dump",
        "reads the header of a Windows crash dump (.dmp) only. This image is not "
        "one, so there is nothing for it to report; not a fault.",
    ),
)

#: Plugins whose options are all optional to argparse but which cannot run
#: without one of them, so they start, log this, and fall over. Each entry maps
#: the log fragment to the option to suggest — the same fix as an argparse
#: refusal, reached by a different route.
_ARGUMENT_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # vadyarascan / yarascan: --yara-file, --yara-string or --yara-compiled-file
    # would each do; the file is the one an analyst usually has.
    ("no yara rules, nor yara rules file were specified", ("--yara-file",)),
)


#: argparse's refusal, when a plugin declares a required option and none was
#: given: "error: the following arguments are required: --strings-file". This is
#: how a plugin that takes an input of its own fails under triage, which passes
#: none — and it is the commonest failure under --all, where every such plugin
#: is run.
_ARGS_REQUIRED = re.compile(r"the following arguments are required:\s*(.+)$", re.I | re.M)

#: The other route to the same fact: a requirement the CLI could not turn into
#: an option, reported after the fact as "Unable to validate the plugin
#: requirements: ['plugins.Strings.strings_file']".
_UNSATISFIED = re.compile(r"plugin requirements:\s*\[([^\]]*)\]", re.I)

#: Requirement path components that belong to the image and its symbols rather
#: than to the plugin. An unsatisfied one of these means Volatility could not
#: build the kernel layer; anything else names an argument the plugin wanted.
_LAYER_COMPONENTS = frozenset(
    {"kernel", "primary", "memory_layer", "layer_name", "nt_symbols",
     "symbol_table_name"}
)


def missing_arguments(log_text: str) -> list[str]:
    """The plugin's own options a failed run went without, as ``--flags``.

    Empty when the failure was something else — including an unsatisfied
    requirement that belongs to the image, which is a different problem with a
    different fix.
    """
    found: list[str] = []
    for match in _ARGS_REQUIRED.finditer(log_text):
        for flag in match.group(1).split(","):
            flag = flag.strip()
            if flag.startswith("-") and flag not in found:
                found.append(flag)
    if found:
        return found

    match = _UNSATISFIED.search(log_text)
    if match:
        for raw in match.group(1).split(","):
            path = raw.strip().strip("'\"")
            parts = path.split(".")
            if not parts or set(parts) & _LAYER_COMPONENTS:
                continue
            flag = "--" + parts[-1].replace("_", "-")
            if flag not in found:
                found.append(flag)
    if found:
        return found

    lowered = log_text.lower()
    for needle, flags in _ARGUMENT_HINTS:
        if needle in lowered:
            found.extend(f for f in flags if f not in found)
    return found


def _read_log(result: scheduler.TaskResult) -> str:
    try:
        return result.task.stderr_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def failure_diagnosis(result: scheduler.TaskResult) -> str:
    """Why a Volatility invocation failed, in words that name the fix.

    Shared by the probe and by every plugin in the main run. Returns ``""`` when
    the log holds nothing recognisable and nothing worth quoting.
    """
    text = _read_log(result)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    detail = lines[-1] if lines else ""

    # A named root cause beats the generic consequence on the last line.
    whole_log = text.lower()
    for needle, explanation in _KNOWN_CAUSES:
        if needle in whole_log:
            return explanation

    # A plugin that wants an argument triage does not pass. Checked before the
    # requirement branch below, which would otherwise read the same failure as
    # an unidentifiable image and send the analyst back to the evidence.
    missing = missing_arguments(text)
    if missing:
        flags = " and ".join(missing) if len(missing) == 2 else ", ".join(missing)
        those = "those arguments" if len(missing) > 1 else "that argument"
        return (
            f"needs {flags}, which triage does not pass. The plugin takes an "
            f"input of its own; run it by hand with {those}."
        )

    lowered = detail.lower()

    # Order matters, and so does word boundary. "unsatisfied" contains "isf", so a
    # naive substring test reports Volatility's commonest error — it could not
    # identify the image — as a symbol problem, sending the analyst back across the
    # air gap for symbols they already have.
    if "unsatisfied" in lowered or "requirement" in lowered:
        hint = ""
        if str(result.task.command[-3:]).lower().count(".vmem") or ".vmem" in whole_log:
            hint = (
                "\n  This is a VMEM: check that its VMSS/VMSN companion sits in the "
                "same\n  folder with the same basename."
            )
        return (
            "Volatility could not identify the image. It may not be a supported "
            f"Windows memory capture.{hint}\n  {detail}"
        )
    if "symbol" in lowered or re.search(r"\bisf\b", lowered):
        return (
            "Volatility could not load symbols. Run 'symbols' to confirm what is "
            f"needed.\n  {detail}"
        )
    return detail


def probe_diagnosis(result: scheduler.TaskResult) -> str:
    """Turn a failed probe into something actionable."""
    if result.timed_out:
        return "The probe timed out. The image may be very large or on slow media."
    return failure_diagnosis(result) or "no diagnostic output"


def by_hand_command(result: scheduler.TaskResult, missing: list[str]) -> str:
    """The failed invocation again, with a placeholder for each missing option.

    The exact argv that ran, so it carries the image, symbols, cache and swap
    layers triage used; only the plugin's own argument is left for the analyst
    to fill in. It writes to the console where triage wrote to a file, so a
    redirection is the analyst's to add.
    """
    argv = list(result.task.command)
    for flag in missing:
        argv += [flag, f"<{flag.lstrip('-').upper().replace('-', '_')}>"]
    return render_command(argv)


def failure_note(outcome: PluginOutcome) -> str:
    """What to print under a failed plugin's status line, or ``""``.

    One diagnosis per plugin, not per format: both renderers ran the same
    invocation and failed the same way, and saying it twice reads as two
    problems. Timeouts are left to the status line, which already says so.
    """
    failed = [r for r in outcome.results.values() if not r.ok and not r.timed_out]
    if not failed:
        return ""
    result = failed[0]
    diagnosis = failure_diagnosis(result)
    if not diagnosis:
        return ""
    missing = missing_arguments(_read_log(result))
    if missing:
        diagnosis += f"\n  {by_hand_command(result, missing)}"
    return diagnosis


def collect_outcomes(
    plan: TriagePlan, results: list[scheduler.TaskResult]
) -> list[PluginOutcome]:
    by_plugin: dict[str, PluginOutcome] = {}
    for result in results:
        plugin, _, fmt = result.task.key.rpartition(":")
        outcome = by_plugin.setdefault(plugin, PluginOutcome(plugin))
        outcome.results[fmt] = result

    ordered = [by_plugin[name] for name in plan.plugin_names if name in by_plugin]
    for outcome in ordered:
        if "csv" in outcome.results and outcome.results["csv"].ok:
            outcome.rows = count_rows(output_path(plan.output_dir, outcome.plugin, "csv"))
    return ordered


def layer_warning(plan: TriagePlan, outcomes: list[PluginOutcome]) -> str | None:
    """Explain a run where every plugin succeeded but produced no rows.

    That pattern means Volatility read the file but could not map memory, so the
    plugins walk empty structures and exit cleanly. Without an explanation it
    looks like a clean image with nothing on it.
    """
    counted = [o for o in outcomes if o.rows is not None]
    if not counted or any(o.rows for o in counted):
        return None

    hint = ""
    for outcome in outcomes:
        for fmt in outcome.results:
            try:
                text = log_path(plan.output_dir, outcome.plugin, fmt).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                continue
            if "vmware" in text.lower() and "metadata" in text.lower():
                hint = (
                    "\n  Volatility warned that this VMEM has no VMSS/VMSN metadata "
                    "beside it.\n  Either place the companion file next to the image "
                    "(same basename), or\n  copy the image to a .raw extension to force "
                    "the raw physical layer."
                )
                break
        if hint:
            break

    return (
        "Every plugin succeeded but returned zero rows. Volatility read the image "
        "yet could not map its memory, so nothing was found to report." + hint
    )


def prune_empty_outputs(plan: TriagePlan, outcomes: list[PluginOutcome]) -> int:
    """Delete zero-byte outputs left by failed plugins.

    An empty ``windows.netscan.NetScan.csv`` in the results folder reads as
    "no network artefacts found" when it actually means the plugin failed. The
    log is kept either way, so nothing diagnostic is lost.
    """
    removed = 0
    for outcome in outcomes:
        for fmt, result in outcome.results.items():
            if result.ok and result.output_bytes > 0:
                continue
            path = output_path(plan.output_dir, outcome.plugin, fmt)
            try:
                if path.is_file() and path.stat().st_size == 0:
                    path.unlink()
                    removed += 1
            except OSError:
                pass
    return removed


def plugin_records(outcomes: list[PluginOutcome]) -> list[dict]:
    records = []
    for outcome in outcomes:
        records.append(
            {
                "plugin": outcome.plugin,
                "status": "ok" if outcome.ok else "failed",
                "detail": None if outcome.ok else outcome.status(),
                # The same words the console showed, so the manifest can be read
                # later without the console and without opening the log.
                "diagnosis": None if outcome.ok else (failure_note(outcome) or None),
                "rows": outcome.rows,
                "seconds": round(outcome.duration, 2),
                "formats": {
                    fmt: {
                        "status": result.status,
                        "bytes": result.output_bytes,
                        "seconds": round(result.duration, 2),
                    }
                    for fmt, result in outcome.results.items()
                },
            }
        )
    return records


def cleanup_probe(plan: TriagePlan, *, keep_log: bool = False) -> Path | None:
    """Remove the probe's scratch directory, optionally preserving its log.

    When the probe fails, that log is the only record of *why*. Volatility states the
    cause as a warning partway through and only the consequence at the end, so an
    analyst who needs to read the whole thing must be able to find it — deleting it
    along with the scratch directory leaves them with the symptom and nothing else.
    """
    probe_dir = plan.output_dir / ".probe"
    kept: Path | None = None

    if keep_log:
        source = probe_dir / "probe.log"
        if source.is_file():
            kept = plan.output_dir / "logs" / "probe.log"
            kept.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(source, kept)
            except OSError:
                kept = None

    shutil.rmtree(probe_dir, ignore_errors=True)
    return kept


def write_manifest(
    plan: TriagePlan,
    engine: VolEngine,
    outcomes: list[PluginOutcome],
    *,
    kernels: list[KernelPdb],
    image_sha256: str | None,
    started_utc: str,
) -> Path:
    document = manifest.build(
        image=plan.image,
        image_sha256=image_sha256,
        kernels=kernels,
        engine_name=engine.name,
        jobs=plan.jobs,
        pagefiles=plan.pagefiles,
        output_dir=plan.output_dir,
        plugin_records=plugin_records(outcomes),
        started_utc=started_utc,
    )
    return manifest.write(plan.output_dir, document)
