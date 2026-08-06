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
from .engine import VolEngine
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


@dataclass
class PluginOutcome:
    plugin: str
    results: dict = field(default_factory=dict)  # format -> TaskResult

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
        ),
        stdout_path=probe_dir / "probe.json",
        stderr_path=probe_dir / "probe.log",
    )

    log(f"Probing with {plugin_catalog.PROBE} (validates symbols, warms the cache)...")
    (result,) = scheduler.run_tasks([task], jobs=1, timeout=plan.timeout)
    return result


def probe_diagnosis(result: scheduler.TaskResult) -> str:
    """Turn a failed probe into something actionable."""
    detail = ""
    try:
        text = result.task.stderr_path.read_text(encoding="utf-8", errors="replace")
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        detail = lines[-1] if lines else ""
    except OSError:
        pass

    if result.timed_out:
        return "The probe timed out. The image may be very large or on slow media."

    lowered = detail.lower()

    # Order matters, and so does word boundary. "unsatisfied" contains "isf", so a
    # naive substring test reports Volatility's commonest error — it could not
    # identify the image — as a symbol problem, sending the analyst back across the
    # air gap for symbols they already have.
    if "unsatisfied" in lowered or "requirement" in lowered:
        return (
            "Volatility could not identify the image. It may not be a supported "
            f"Windows memory capture.\n  {detail}"
        )
    if "symbol" in lowered or re.search(r"\bisf\b", lowered):
        return (
            "Volatility could not load symbols. Run 'symbols' to confirm what is "
            f"needed.\n  {detail}"
        )
    return detail or "no diagnostic output"


def collect_outcomes(
    plan: TriagePlan, results: list[scheduler.TaskResult]
) -> list[PluginOutcome]:
    by_plugin: dict[str, PluginOutcome] = {}
    for result in results:
        plugin, _, fmt = result.task.key.rpartition(":")
        outcome = by_plugin.setdefault(plugin, PluginOutcome(plugin))
        outcome.results[fmt] = result
    return [by_plugin[name] for name in plan.plugin_names if name in by_plugin]


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


def cleanup_probe(plan: TriagePlan) -> None:
    shutil.rmtree(plan.output_dir / ".probe", ignore_errors=True)


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
        output_dir=plan.output_dir,
        plugin_records=plugin_records(outcomes),
        started_utc=started_utc,
    )
    return manifest.write(plan.output_dir, document)
