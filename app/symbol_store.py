"""Locating ISF symbol files on disk.

Volatility reads ISF files both as loose files under the symbols directory and as
members of zip archives in it — which is how the 800 MB ``windows.zip`` pack is
consumed. A tool that only checked for loose files would tell the analyst to fetch
symbols that are already present in the bundle, costing a pointless trip to the
internet-connected machine.

Archive members are matched on the ``{GUID}-{age}.json.xz`` filename rather than a
full path, because the pack's internal directory layout is not guaranteed.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path

from .symbols import KernelPdb

#: An ISF with no user_types has symbol addresses but no structure definitions.
#: Volatility cannot build a kernel symbol table from one, so it must not count as
#: available — otherwise the tool reports "ready to run plugins" and every plugin
#: then fails with an error that names a requirement rather than a cause.
def isf_has_types(path: Path) -> bool:
    """Whether a loose ISF carries the type information Volatility needs."""
    import json
    import lzma

    try:
        opener = lzma.open if path.suffix == ".xz" else open
        with opener(path, "rt", encoding="utf-8") as handle:
            document = json.load(handle)
    except Exception:  # noqa: BLE001 - unreadable is as unusable as type-less
        return False
    return bool(document.get("user_types"))


@dataclass(frozen=True)
class Located:
    """Where a symbol file was found."""

    kernel: KernelPdb
    container: Path
    member: str | None = None
    usable: bool = True
    reason: str | None = None

    @property
    def in_archive(self) -> bool:
        return self.member is not None

    def describe(self) -> str:
        if self.member is None:
            return str(self.container)
        return f"{self.container}!{self.member}"


class SymbolStore:
    """Read-only view of a symbols directory, covering loose files and zips."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self._archive_index: dict[str, tuple[Path, str]] | None = None

    def _index_archives(self) -> dict[str, tuple[Path, str]]:
        """Map ISF basename to the archive and member holding it.

        Reads only each zip's central directory, so this stays fast even for the
        800 MB pack. A corrupt or unreadable archive is skipped rather than fatal —
        a bad zip should not stop the analyst from using loose symbols.
        """
        if self._archive_index is not None:
            return self._archive_index

        index: dict[str, tuple[Path, str]] = {}
        if self.root.is_dir():
            for archive in sorted(self.root.rglob("*.zip")):
                try:
                    with zipfile.ZipFile(archive) as zf:
                        for member in zf.namelist():
                            if member.endswith(".json.xz"):
                                index.setdefault(member.rsplit("/", 1)[-1], (archive, member))
                except (zipfile.BadZipFile, OSError):
                    continue

        self._archive_index = index
        return index

    def locate(self, kernel: KernelPdb) -> Located | None:
        """Return where this kernel's ISF lives, or ``None`` if it is absent."""
        loose = kernel.isf_path(self.root)
        if loose.is_file():
            if not isf_has_types(loose):
                return Located(
                    kernel, loose, usable=False,
                    reason="contains no type information (stripped PDB); unusable",
                )
            return Located(kernel, loose)

        filename = kernel.isf_relative_path.rsplit("/", 1)[-1]
        found = self._index_archives().get(filename)
        if found is not None:
            archive, member = found
            return Located(kernel, archive, member)

        return None

    def has(self, kernel: KernelPdb) -> bool:
        located = self.locate(kernel)
        return located is not None and located.usable

    def missing(self, kernels: list[KernelPdb]) -> list[KernelPdb]:
        """Kernels with no ISF available, in the order given."""
        return [k for k in kernels if not self.has(k)]

    def unusable(self, kernels: list[KernelPdb]) -> list[Located]:
        """Symbols that exist but cannot be used, with the reason."""
        found = [self.locate(k) for k in kernels]
        return [loc for loc in found if loc is not None and not loc.usable]

    def invalidate(self) -> None:
        """Drop the cached archive index, after symbols have been added."""
        self._archive_index = None
