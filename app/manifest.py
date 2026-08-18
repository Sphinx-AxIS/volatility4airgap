"""The run manifest: what was analysed, with what, and what came out.

Written alongside the outputs so a run can be attested to later. Records the
image digest, the tool and engine used, every plugin's outcome, and a SHA-256 for
each output file so a downstream consumer can prove nothing changed in transit.
"""

from __future__ import annotations

import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

SCHEMA_VERSION = 1
FILENAME = "run-manifest.json"
ANALYSIS_FILENAME = "analysis-manifest.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Digest bytes already in hand, without reopening a file to read them back.

    Preferred over ``sha256_file`` for output this process just produced. A
    strings-hits file is nothing but attacker command lines, and the analysis
    host's own antivirus quarantines or locks it in the instant between writing
    it and reopening it — a reopen there crashed the run before the plugin even
    started. Hashing the bytes we still hold records the same digest with no
    second open for endpoint protection to fail.
    """
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build(
    *,
    image: Path,
    image_sha256: str | None,
    kernels: list,
    engine_name: str,
    jobs: int,
    pagefiles: list | None = None,
    output_dir: Path,
    dumps_dir: Path | None = None,
    plugin_records: list[dict],
    started_utc: str,
    finished_utc: str | None = None,
) -> dict:
    outputs = []
    dump_files = []
    for path in sorted(p for p in output_dir.rglob("*") if p.is_file()):
        if path.name == FILENAME:
            continue
        # Carved files (windows.dumpfiles.DumpFiles under --all) are recorded as
        # a count and total size, not hashed one by one: an --all run can carve
        # thousands of multi-megabyte files, and hashing them inline would
        # dominate the run and bloat this manifest. The plugin *output* that
        # analyse verifies lives at the top level, not in dumps/.
        if dumps_dir is not None and dumps_dir in path.parents:
            dump_files.append(path)
            continue
        try:
            outputs.append(
                {
                    "file": path.relative_to(output_dir).as_posix(),
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
        except OSError:
            continue

    dumps = None
    if dump_files:
        total = 0
        for path in dump_files:
            try:
                total += path.stat().st_size
            except OSError:
                continue
        dumps = {
            "dir": dumps_dir.relative_to(output_dir).as_posix(),
            "files": len(dump_files),
            "total_bytes": total,
        }

    succeeded = sum(1 for r in plugin_records if r["status"] == "ok")

    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "started_utc": started_utc,
        "finished_utc": finished_utc or utc_now(),
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "image": {
            "path": str(image),
            "name": image.name,
            "size_bytes": image.stat().st_size if image.exists() else None,
            "sha256": image_sha256,
        },
        "kernels": [k.as_dict() for k in kernels],
        # Hashed like the image: a pagefile contributes to the findings, so it
        # belongs in the custody record.
        "pagefiles": [
            {
                "path": str(p),
                "size_bytes": p.stat().st_size if p.exists() else None,
                "sha256": sha256_file(p) if p.exists() else None,
            }
            for p in (pagefiles or [])
        ],
        "engine": engine_name,
        "jobs": jobs,
        "plugins": plugin_records,
        "summary": {
            "total": len(plugin_records),
            "succeeded": succeeded,
            "failed": len(plugin_records) - succeeded,
        },
        "outputs": outputs,
        # None unless a plugin carved files; see the loop above.
        "dumps": dumps,
    }


def write(output_dir: Path, document: dict, *, filename: str = FILENAME) -> Path:
    path = output_dir / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def build_analysis(
    *,
    output_dir: Path,
    rule_pack: dict,
    findings_summary: dict,
    not_evaluated: dict,
    plugins_missing: dict,
    followups_executed: int,
    input_check: dict,
    pagefiles: list,
    started_utc: str,
) -> dict:
    """The analysis manifest, written beside the run manifest rather than into it.

    ``build`` above hashes every file under the output directory, so writing
    ``findings/`` and ``followup/`` into that tree leaves ``run-manifest.json``
    describing a directory that no longer exists as recorded. Rewriting it would
    also lose the distinction between what triage collected and what analysis
    derived. Referencing it by digest keeps both intact and makes the stronger
    claim: these findings came from *that* run, provably.
    """
    triage_manifest = output_dir / FILENAME
    derived = []
    for sub in ("findings", "followup"):
        root = output_dir / sub
        if not root.is_dir():
            continue
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            try:
                derived.append(
                    {
                        "file": path.relative_to(output_dir).as_posix(),
                        "size_bytes": path.stat().st_size,
                        "sha256": sha256_file(path),
                    }
                )
            except OSError:
                continue

    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "started_utc": started_utc,
        "finished_utc": utc_now(),
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "triage_run": {
            "manifest": FILENAME,
            "sha256": (
                sha256_file(triage_manifest) if triage_manifest.is_file() else None
            ),
            # Naming the manifest proves which run was referenced. This proves
            # the plugin output beside it still matched what that run attested.
            "inputs": input_check,
        },
        # The swap layers the follow-ups actually read. Omitting one that triage
        # used makes the collected evidence narrower than the findings assume.
        "pagefiles": pagefiles,
        "rule_pack": rule_pack,
        "findings": findings_summary,
        "rules_not_evaluated": not_evaluated,
        "plugins_missing": plugins_missing,
        "followup_tasks_executed": followups_executed,
        "outputs": derived,
    }
