"""Tests for downloading and converting symbols.

Network is not used by default. The real Microsoft round trip is covered by a
test marked ``network``, deselected unless asked for, because the suite must run
on a machine with no connectivity.

verify_isf carries the most weight here: it is the last check before an analyst
crosses the air gap, and a subtly wrong symbol file is worse than a missing one.
"""

from __future__ import annotations

import io
import json
import lzma
import urllib.error

import pytest

from app import fetch
from app.symbols import KernelPdb

from .test_symbols import GOLDEN_GUID, GOLDEN_NAME


@pytest.fixture
def kernel() -> KernelPdb:
    return KernelPdb(GOLDEN_NAME, GOLDEN_GUID, 1)


def write_isf(path, *, guid=GOLDEN_GUID, age=1, database=GOLDEN_NAME, symbols=None,
              user_types=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "metadata": {"windows": {"pdb": {"GUID": guid, "age": age, "database": database}}},
        "symbols": symbols if symbols is not None else {"a": {}, "b": {}},
        "user_types": (
            user_types if user_types is not None else {"_EPROCESS": {"kind": "struct"}}
        ),
    }
    with lzma.open(path, "wt", encoding="utf-8") as handle:
        json.dump(document, handle)
    return path


class TestVerifyIsf:
    def test_accepts_a_matching_file(self, tmp_path, kernel) -> None:
        path = write_isf(kernel.isf_path(tmp_path))
        assert fetch.verify_isf(path, kernel) == 2

    def test_rejects_a_guid_mismatch(self, tmp_path, kernel) -> None:
        path = write_isf(kernel.isf_path(tmp_path), guid="0" * 32)
        with pytest.raises(fetch.FetchError, match="GUID mismatch"):
            fetch.verify_isf(path, kernel)

    def test_rejects_an_age_mismatch(self, tmp_path, kernel) -> None:
        path = write_isf(kernel.isf_path(tmp_path), age=7)
        with pytest.raises(fetch.FetchError, match="age mismatch"):
            fetch.verify_isf(path, kernel)

    def test_rejects_the_default_database_name(self, tmp_path, kernel) -> None:
        """PdbReader's default would silently break volatility's cache lookup."""
        path = write_isf(kernel.isf_path(tmp_path), database="unknown.pdb")
        with pytest.raises(fetch.FetchError, match="database mismatch"):
            fetch.verify_isf(path, kernel)

    def test_rejects_a_corrupt_archive(self, tmp_path, kernel) -> None:
        path = kernel.isf_path(tmp_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"not xz at all")

        with pytest.raises(fetch.FetchError, match="not a readable ISF"):
            fetch.verify_isf(path, kernel)

    def test_rejects_missing_metadata(self, tmp_path, kernel) -> None:
        path = kernel.isf_path(tmp_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with lzma.open(path, "wt", encoding="utf-8") as handle:
            json.dump({"symbols": {}}, handle)

        with pytest.raises(fetch.FetchError):
            fetch.verify_isf(path, kernel)


class TestDownload:
    def test_falls_back_to_the_compressed_variant(self, tmp_path, kernel, monkeypatch) -> None:
        seen = []

        def fake_open(url):
            seen.append(url)
            if url.endswith(".pdb"):
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
            return io.BytesIO(b"MSCF fake cabinet")

        monkeypatch.setattr(fetch, "_open", fake_open)
        path, compressed = fetch.download_pdb(kernel, tmp_path, log=lambda *_: None)

        assert compressed is True
        assert path.name == kernel.compressed_filename
        assert seen == [kernel.download_url, kernel.compressed_url]

    def test_prefers_the_uncompressed_pdb(self, tmp_path, kernel, monkeypatch) -> None:
        monkeypatch.setattr(fetch, "_open", lambda url: io.BytesIO(b"MSVC pdb"))
        path, compressed = fetch.download_pdb(kernel, tmp_path, log=lambda *_: None)

        assert compressed is False
        assert path.name == kernel.download_filename

    def test_raises_when_both_fail(self, tmp_path, kernel, monkeypatch) -> None:
        def fake_open(url):
            raise urllib.error.URLError("no route to host")

        monkeypatch.setattr(fetch, "_open", fake_open)
        with pytest.raises(fetch.FetchError):
            fetch.download_pdb(kernel, tmp_path, log=lambda *_: None)

    def test_an_empty_response_is_not_accepted(self, tmp_path, kernel, monkeypatch) -> None:
        monkeypatch.setattr(fetch, "_open", lambda url: io.BytesIO(b""))
        with pytest.raises(fetch.FetchError):
            fetch.download_pdb(kernel, tmp_path, log=lambda *_: None)


class TestFetchOne:
    def test_reuses_an_existing_valid_file(self, tmp_path, kernel, monkeypatch) -> None:
        out = tmp_path / "symbols"
        write_isf(kernel.isf_path(out))

        def explode(*args, **kwargs):
            raise AssertionError("should not download when a valid file exists")

        monkeypatch.setattr(fetch, "download_pdb", explode)
        result = fetch.fetch_one(kernel, out, tmp_path / "work", log=lambda *_: None)

        assert result.ok
        assert result.symbol_count == 2

    def test_replaces_an_existing_invalid_file(self, tmp_path, kernel, monkeypatch) -> None:
        out = tmp_path / "symbols"
        write_isf(kernel.isf_path(out), database="unknown.pdb")
        called = []

        def fake_download(*args, **kwargs):
            called.append(1)
            source = tmp_path / "x.pdb"
            source.write_bytes(b"MSVC pdb")
            return source, False  # download_pdb returns (path, compressed)

        monkeypatch.setattr(fetch, "download_pdb", fake_download)
        monkeypatch.setattr(
            fetch, "convert_to_isf",
            lambda *a, **k: write_isf(kernel.isf_path(out)),
        )
        result = fetch.fetch_one(kernel, out, tmp_path / "work", log=lambda *_: None)

        assert called, "an invalid existing file must be refetched"
        assert result.ok

    def test_a_failure_is_reported_not_raised(self, tmp_path, kernel, monkeypatch) -> None:
        """One kernel failing must never sink a multi-kernel run."""
        def explode(*args, **kwargs):
            raise fetch.FetchError("server said no")

        monkeypatch.setattr(fetch, "download_pdb", explode)
        result = fetch.fetch_one(kernel, tmp_path / "s", tmp_path / "w", log=lambda *_: None)

        assert not result.ok
        assert "server said no" in result.error

    def test_an_unexpected_exception_is_contained(self, tmp_path, kernel, monkeypatch) -> None:
        def explode(*args, **kwargs):
            raise ZeroDivisionError("boom")

        monkeypatch.setattr(fetch, "download_pdb", explode)
        result = fetch.fetch_one(kernel, tmp_path / "s", tmp_path / "w", log=lambda *_: None)

        assert not result.ok
        assert "ZeroDivisionError" in result.error


class TestFetchAll:
    def test_continues_past_a_failure(self, tmp_path, monkeypatch) -> None:
        good = KernelPdb(GOLDEN_NAME, GOLDEN_GUID, 1)
        bad = KernelPdb("ntoskrnl.pdb", "1" * 32, 2)
        out = tmp_path / "symbols"
        write_isf(good.isf_path(out))

        def explode(kernel, *args, **kwargs):
            raise fetch.FetchError("unavailable")

        monkeypatch.setattr(fetch, "download_pdb", explode)
        results = fetch.fetch_all([good, bad], out, tmp_path / "w", log=lambda *_: None)

        assert [r.ok for r in results] == [True, False]


class TestExpandCab:
    def test_reports_actionably_when_no_expander_exists(
        self, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.setattr(fetch.shutil, "which", lambda _: None)
        cab = tmp_path / "ntkrnlmp.pd_"
        cab.write_bytes(b"MSCF")

        with pytest.raises(fetch.FetchError, match="cabextract"):
            fetch.expand_cab(cab, tmp_path, log=lambda *_: None)


@pytest.mark.network
class TestRealSymbolServer:
    """The genuine round trip. Deselected by default; run with -m network."""

    def test_fetches_and_converts_a_real_kernel(self, tmp_path) -> None:
        pytest.importorskip("volatility3")
        # ntkrnlpa.pdb from 0zapftis.vmem, a public Windows XP sample.
        kernel = KernelPdb("ntkrnlpa.pdb", "BD8F451F3E754ED8A34B50560CEB08E3", 1)

        result = fetch.fetch_one(kernel, tmp_path / "symbols", tmp_path / "work")

        assert result.ok, result.error
        assert result.symbol_count > 10_000
        assert result.isf_path == kernel.isf_path(tmp_path / "symbols")

        # And the file must satisfy volatility's cache lookup, not merely exist.
        from volatility3.framework.automagic.symbol_cache import WindowsIdentifier

        with lzma.open(result.isf_path, "rt", encoding="utf-8") as handle:
            isf = json.load(handle)
        assert WindowsIdentifier.get_identifier(isf) == kernel.cache_identifier


class TestStrippedPdbDetection:
    """Microsoft serves public PDBs for some kernels — addresses, no structures.

    The resulting ISF has the correct GUID, age and database, and is useless.
    Volatility fails with "Unable to validate the plugin requirements:
    ['plugins.Info.kernel.symbol_table_name']", which names a requirement rather
    than a cause. Catching it at fetch time is the only place it is cheap.
    """

    def test_rejects_an_isf_with_no_types(self, tmp_path, kernel) -> None:
        path = write_isf(kernel.isf_path(tmp_path), user_types={})
        with pytest.raises(fetch.FetchError, match="no type information"):
            fetch.verify_isf(path, kernel)

    def test_the_message_points_at_the_symbol_pack(self, tmp_path, kernel) -> None:
        path = write_isf(kernel.isf_path(tmp_path), user_types={})
        with pytest.raises(fetch.FetchError, match="windows.zip"):
            fetch.verify_isf(path, kernel)

    def test_identity_alone_is_not_enough(self, tmp_path, kernel) -> None:
        """Every identity field matches; only the types are absent."""
        path = write_isf(
            kernel.isf_path(tmp_path),
            guid=kernel.guid, age=kernel.age, database=kernel.pdb_name,
            user_types={},
        )
        with pytest.raises(fetch.FetchError):
            fetch.verify_isf(path, kernel)

    def test_an_unusable_isf_is_not_left_on_disk(self, tmp_path, kernel, monkeypatch) -> None:
        """Leaving it would satisfy every presence check while nothing can run."""
        out = tmp_path / "symbols"

        def fake_download(*args, **kwargs):
            source = tmp_path / "x.pdb"
            source.write_bytes(b"MSVC pdb")
            return source, False

        monkeypatch.setattr(fetch, "download_pdb", fake_download)
        monkeypatch.setattr(
            fetch, "convert_to_isf",
            lambda *a, **k: write_isf(kernel.isf_path(out), user_types={}),
        )

        result = fetch.fetch_one(kernel, out, tmp_path / "work", log=lambda *_: None)

        assert not result.ok
        assert "no type information" in result.error
        assert not kernel.isf_path(out).exists()
