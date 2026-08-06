"""The symbol_request.json handoff document.

Written on the air-gapped machine when symbols are missing; read on the
internet-connected machine by ``fetch-symbols``. This file is the entire interface
between the two halves of the workflow, so it carries everything needed to fetch
and place the symbols without the analyst retyping anything.

It always describes a *list* of kernels. An image can legitimately contain more
than one kernel build — a hibernation remnant, or a capture spanning a reboot —
and ISF files are small, so every match is fetched rather than guessing which one
Volatility will want.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .symbols import KernelPdb, is_kernel, needed_by
from .symbol_store import SymbolStore

SCHEMA_VERSION = 1

FILENAME = "symbol_request.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build(
    image: Path | str,
    kernels: list[KernelPdb],
    *,
    store: SymbolStore | None = None,
    image_sha256: str | None = None,
    generated_utc: str | None = None,
) -> dict:
    """Assemble the request document.

    ``store`` marks which kernels are already satisfied, so the analyst fetches
    only what is genuinely absent. ``image_sha256`` is optional because hashing a
    multi-gigabyte image is expensive; the run manifest records it instead.
    """
    image = Path(image)

    try:
        size = image.stat().st_size
    except OSError:
        size = None

    entries = []
    for kernel in kernels:
        located = store.locate(kernel) if store is not None else None
        entries.append(
            {
                **kernel.as_dict(),
                "offset": kernel.offset,
                "download": {
                    "primary_url": kernel.download_url,
                    "compressed_fallback_url": kernel.compressed_url,
                },
                "required_isf": kernel.isf_relative_path,
                # The kernel is required: without it nothing runs. Other modules are
                # needed only by particular plugins, so a missing one degrades the
                # run rather than blocking it.
                "required": is_kernel(kernel.pdb_name),
                "needed_by": list(needed_by(kernel.pdb_name)),
                "present": located is not None,
                "found_at": located.describe() if located is not None else None,
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "generated_utc": generated_utc or _utc_now(),
        "image": {
            "path": str(image),
            "name": image.name,
            "size_bytes": size,
            "sha256": image_sha256,
        },
        "kernels": entries,
        "missing_count": sum(1 for e in entries if not e["present"]),
        "missing_required_count": sum(
            1 for e in entries if not e["present"] and e["required"]
        ),
    }


def write(path: Path | str, document: dict) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def load(path: Path | str) -> dict:
    """Read a request document, rejecting a schema this build cannot honour."""
    document = json.loads(Path(path).read_text(encoding="utf-8"))

    version = document.get("schema_version")
    if version != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported symbol_request schema version {version!r}; "
            f"this build understands version {SCHEMA_VERSION}"
        )
    if not isinstance(document.get("kernels"), list):
        raise ValueError("symbol_request is missing its 'kernels' list")

    return document


def kernels_from(document: dict, *, missing_only: bool = False) -> list[KernelPdb]:
    """Reconstruct KernelPdb objects, re-deriving URLs rather than trusting them.

    The stored URLs are for the analyst to read. Rebuilding them from the identity
    means a hand-edited or truncated request cannot silently redirect a download.
    """
    kernels = []
    for entry in document["kernels"]:
        if missing_only and entry.get("present"):
            continue
        kernels.append(
            KernelPdb(
                pdb_name=entry["pdb_name"],
                guid=entry["guid"],
                age=int(entry["age"]),
                offset=entry.get("offset"),
            )
        )
    return kernels
