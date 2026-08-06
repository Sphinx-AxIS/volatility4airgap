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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build(
    *,
    image: Path,
    image_sha256: str | None,
    kernels: list,
    engine_name: str,
    jobs: int,
    output_dir: Path,
    plugin_records: list[dict],
    started_utc: str,
    finished_utc: str | None = None,
) -> dict:
    outputs = []
    for path in sorted(p for p in output_dir.rglob("*") if p.is_file()):
        if path.name == FILENAME:
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
        "engine": engine_name,
        "jobs": jobs,
        "plugins": plugin_records,
        "summary": {
            "total": len(plugin_records),
            "succeeded": succeeded,
            "failed": len(plugin_records) - succeeded,
        },
        "outputs": outputs,
    }


def write(output_dir: Path, document: dict) -> Path:
    path = output_dir / FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path
