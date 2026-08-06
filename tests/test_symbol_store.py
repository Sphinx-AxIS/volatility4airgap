"""Tests for locating ISF files across loose files and zip archives."""

from __future__ import annotations

import lzma
import zipfile

import pytest

from app.symbol_store import SymbolStore
from app.symbols import KernelPdb

from .test_symbols import GOLDEN_GUID, GOLDEN_NAME

OTHER_GUID = "0123456789ABCDEF0123456789ABCDEF"


@pytest.fixture
def kernel() -> KernelPdb:
    return KernelPdb(GOLDEN_NAME, GOLDEN_GUID, 1)


def write_loose_isf(root, kernel: KernelPdb) -> None:
    path = kernel.isf_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with lzma.open(path, "wt") as handle:
        handle.write("{}")


def write_pack(root, members: list[str], name: str = "windows.zip") -> None:
    root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(root / name, "w") as zf:
        for member in members:
            zf.writestr(member, b"\xfd7zXZ")


class TestLooseFiles:
    def test_finds_a_loose_isf(self, tmp_path, kernel: KernelPdb) -> None:
        write_loose_isf(tmp_path, kernel)
        located = SymbolStore(tmp_path).locate(kernel)

        assert located is not None
        assert located.in_archive is False
        assert located.container == kernel.isf_path(tmp_path)

    def test_absent_when_nothing_present(self, tmp_path, kernel: KernelPdb) -> None:
        assert SymbolStore(tmp_path).locate(kernel) is None

    def test_absent_when_only_another_guid_present(self, tmp_path, kernel: KernelPdb) -> None:
        write_loose_isf(tmp_path, KernelPdb(GOLDEN_NAME, OTHER_GUID, 1))
        assert SymbolStore(tmp_path).locate(kernel) is None

    def test_age_must_match(self, tmp_path, kernel: KernelPdb) -> None:
        write_loose_isf(tmp_path, KernelPdb(GOLDEN_NAME, GOLDEN_GUID, 2))
        assert SymbolStore(tmp_path).locate(kernel) is None

    def test_missing_root_is_not_an_error(self, tmp_path, kernel: KernelPdb) -> None:
        assert SymbolStore(tmp_path / "absent").locate(kernel) is None


class TestArchives:
    """The bundled windows.zip must count as present."""

    def test_finds_an_isf_inside_a_zip(self, tmp_path, kernel: KernelPdb) -> None:
        write_pack(tmp_path, [f"windows/{GOLDEN_NAME}/{GOLDEN_GUID}-1.json.xz"])
        located = SymbolStore(tmp_path).locate(kernel)

        assert located is not None
        assert located.in_archive is True
        assert located.container.name == "windows.zip"
        assert "!" in located.describe()

    def test_matches_regardless_of_internal_layout(self, tmp_path, kernel: KernelPdb) -> None:
        # The pack's directory structure is not contractual, so match on filename.
        write_pack(tmp_path, [f"some/other/prefix/{GOLDEN_GUID}-1.json.xz"])
        assert SymbolStore(tmp_path).has(kernel)

    def test_matches_a_member_at_the_zip_root(self, tmp_path, kernel: KernelPdb) -> None:
        write_pack(tmp_path, [f"{GOLDEN_GUID}-1.json.xz"])
        assert SymbolStore(tmp_path).has(kernel)

    def test_does_not_match_a_different_age(self, tmp_path, kernel: KernelPdb) -> None:
        write_pack(tmp_path, [f"windows/{GOLDEN_NAME}/{GOLDEN_GUID}-2.json.xz"])
        assert not SymbolStore(tmp_path).has(kernel)

    def test_does_not_match_the_buggy_historical_name(self, tmp_path, kernel: KernelPdb) -> None:
        """A file named the way generate_isf.sh named it must not count as present."""
        write_pack(tmp_path, [f"windows/{GOLDEN_NAME}/{GOLDEN_GUID}1-1.json.xz"])
        assert not SymbolStore(tmp_path).has(kernel)

    def test_searches_nested_directories(self, tmp_path, kernel: KernelPdb) -> None:
        nested = tmp_path / "packs" / "vendor"
        write_pack(nested, [f"windows/{GOLDEN_NAME}/{GOLDEN_GUID}-1.json.xz"])
        assert SymbolStore(tmp_path).has(kernel)

    def test_a_corrupt_archive_is_skipped(self, tmp_path, kernel: KernelPdb) -> None:
        (tmp_path).mkdir(parents=True, exist_ok=True)
        (tmp_path / "broken.zip").write_bytes(b"definitely not a zip")
        write_pack(tmp_path, [f"windows/{GOLDEN_NAME}/{GOLDEN_GUID}-1.json.xz"], name="good.zip")

        # A bad archive must not prevent finding symbols in a good one.
        assert SymbolStore(tmp_path).has(kernel)

    def test_loose_file_wins_over_archive(self, tmp_path, kernel: KernelPdb) -> None:
        write_pack(tmp_path, [f"windows/{GOLDEN_NAME}/{GOLDEN_GUID}-1.json.xz"])
        write_loose_isf(tmp_path, kernel)

        located = SymbolStore(tmp_path).locate(kernel)
        assert located is not None and located.in_archive is False


class TestMissing:
    def test_reports_only_absent_kernels_in_order(self, tmp_path) -> None:
        present = KernelPdb(GOLDEN_NAME, GOLDEN_GUID, 1)
        absent_a = KernelPdb("ntoskrnl.pdb", OTHER_GUID, 3)
        absent_b = KernelPdb("ntkrpamp.pdb", "F" * 32, 7)
        write_loose_isf(tmp_path, present)

        missing = SymbolStore(tmp_path).missing([absent_a, present, absent_b])
        assert missing == [absent_a, absent_b]

    def test_nothing_missing_when_all_present(self, tmp_path) -> None:
        kernels = [
            KernelPdb(GOLDEN_NAME, GOLDEN_GUID, 1),
            KernelPdb("ntoskrnl.pdb", OTHER_GUID, 3),
        ]
        for k in kernels:
            write_loose_isf(tmp_path, k)

        assert SymbolStore(tmp_path).missing(kernels) == []


class TestCaching:
    def test_invalidate_picks_up_a_newly_added_pack(self, tmp_path, kernel: KernelPdb) -> None:
        store = SymbolStore(tmp_path)
        assert not store.has(kernel)  # populates the cache

        write_pack(tmp_path, [f"windows/{GOLDEN_NAME}/{GOLDEN_GUID}-1.json.xz"])
        store.invalidate()

        assert store.has(kernel)
