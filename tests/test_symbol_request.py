"""Tests for the symbol_request.json handoff document."""

from __future__ import annotations

import json

import pytest

from app import symbol_request
from app.symbol_store import SymbolStore
from app.symbols import KernelPdb

from .test_symbol_store import OTHER_GUID, write_loose_isf
from .test_symbols import GOLDEN_GUID, GOLDEN_NAME

FIXED_TIME = "2026-08-05T21:14:00Z"


@pytest.fixture
def kernels() -> list[KernelPdb]:
    return [
        KernelPdb(GOLDEN_NAME, GOLDEN_GUID, 1, offset=4096),
        KernelPdb("ntoskrnl.pdb", OTHER_GUID, 3, offset=99999),
    ]


@pytest.fixture
def image(tmp_path):
    path = tmp_path / "evidence" / "image.raw"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\xcc" * 2048)
    return path


class TestBuild:
    def test_carries_every_kernel(self, image, kernels) -> None:
        doc = symbol_request.build(image, kernels, generated_utc=FIXED_TIME)
        assert len(doc["kernels"]) == 2
        assert [k["pdb_name"] for k in doc["kernels"]] == [GOLDEN_NAME, "ntoskrnl.pdb"]

    def test_records_both_urls_and_the_isf_path(self, image, kernels) -> None:
        entry = symbol_request.build(image, kernels, generated_utc=FIXED_TIME)["kernels"][0]

        assert entry["download"]["primary_url"] == kernels[0].download_url
        assert entry["download"]["compressed_fallback_url"] == kernels[0].compressed_url
        assert entry["required_isf"] == kernels[0].isf_relative_path

    def test_distinguishes_guid_from_guid_age(self, image, kernels) -> None:
        entry = symbol_request.build(image, kernels, generated_utc=FIXED_TIME)["kernels"][0]

        assert entry["guid"] == GOLDEN_GUID
        assert entry["guid_age"] == GOLDEN_GUID + "1"
        assert entry["guid"] not in entry["required_isf"].rsplit("/", 1)[-1].replace(
            f"{GOLDEN_GUID}-", ""
        )

    def test_records_image_metadata(self, image, kernels) -> None:
        doc = symbol_request.build(image, kernels, generated_utc=FIXED_TIME)

        assert doc["image"]["name"] == "image.raw"
        assert doc["image"]["size_bytes"] == 2048
        assert doc["image"]["sha256"] is None
        assert doc["generated_utc"] == FIXED_TIME
        assert doc["schema_version"] == symbol_request.SCHEMA_VERSION

    def test_accepts_a_supplied_hash(self, image, kernels) -> None:
        doc = symbol_request.build(
            image, kernels, image_sha256="ab" * 32, generated_utc=FIXED_TIME
        )
        assert doc["image"]["sha256"] == "ab" * 32

    def test_a_missing_image_does_not_raise(self, tmp_path, kernels) -> None:
        doc = symbol_request.build(tmp_path / "gone.raw", kernels, generated_utc=FIXED_TIME)
        assert doc["image"]["size_bytes"] is None

    def test_generates_a_timestamp_when_none_given(self, image, kernels) -> None:
        doc = symbol_request.build(image, kernels)
        assert doc["generated_utc"].endswith("Z")


class TestPresence:
    def test_marks_present_kernels_and_counts_only_the_missing(
        self, tmp_path, image, kernels
    ) -> None:
        symbols = tmp_path / "symbols"
        write_loose_isf(symbols, kernels[0])

        doc = symbol_request.build(
            image, kernels, store=SymbolStore(symbols), generated_utc=FIXED_TIME
        )

        assert doc["kernels"][0]["present"] is True
        assert doc["kernels"][1]["present"] is False
        assert doc["missing_count"] == 1
        assert doc["kernels"][0]["found_at"] is not None
        assert doc["kernels"][1]["found_at"] is None

    def test_everything_missing_without_a_store(self, image, kernels) -> None:
        doc = symbol_request.build(image, kernels, generated_utc=FIXED_TIME)
        assert doc["missing_count"] == 2

    def test_nothing_missing_when_all_present(self, tmp_path, image, kernels) -> None:
        symbols = tmp_path / "symbols"
        for k in kernels:
            write_loose_isf(symbols, k)

        doc = symbol_request.build(
            image, kernels, store=SymbolStore(symbols), generated_utc=FIXED_TIME
        )
        assert doc["missing_count"] == 0


class TestRoundTrip:
    def test_write_then_load(self, tmp_path, image, kernels) -> None:
        doc = symbol_request.build(image, kernels, generated_utc=FIXED_TIME)
        path = symbol_request.write(tmp_path / "out" / symbol_request.FILENAME, doc)

        assert path.is_file()
        assert symbol_request.load(path) == doc

    def test_recovers_kernels_intact(self, tmp_path, image, kernels) -> None:
        doc = symbol_request.build(image, kernels, generated_utc=FIXED_TIME)
        path = symbol_request.write(tmp_path / symbol_request.FILENAME, doc)

        recovered = symbol_request.kernels_from(symbol_request.load(path))
        assert [(k.pdb_name, k.guid, k.age) for k in recovered] == [
            (k.pdb_name, k.guid, k.age) for k in kernels
        ]

    def test_missing_only_filters_present_kernels(self, tmp_path, image, kernels) -> None:
        symbols = tmp_path / "symbols"
        write_loose_isf(symbols, kernels[0])
        doc = symbol_request.build(
            image, kernels, store=SymbolStore(symbols), generated_utc=FIXED_TIME
        )

        recovered = symbol_request.kernels_from(doc, missing_only=True)
        assert [k.guid for k in recovered] == [OTHER_GUID]

    def test_urls_are_rederived_not_trusted(self, tmp_path, image, kernels) -> None:
        """A tampered URL in the file must not redirect the download."""
        doc = symbol_request.build(image, kernels, generated_utc=FIXED_TIME)
        doc["kernels"][0]["download"]["primary_url"] = "http://evil.example/payload.pdb"
        path = symbol_request.write(tmp_path / symbol_request.FILENAME, doc)

        recovered = symbol_request.kernels_from(symbol_request.load(path))
        assert recovered[0].download_url == kernels[0].download_url
        assert "evil.example" not in recovered[0].download_url


class TestSchemaGuard:
    def test_rejects_an_unknown_schema_version(self, tmp_path, image, kernels) -> None:
        doc = symbol_request.build(image, kernels, generated_utc=FIXED_TIME)
        doc["schema_version"] = 99
        path = tmp_path / symbol_request.FILENAME
        path.write_text(json.dumps(doc), encoding="utf-8")

        with pytest.raises(ValueError, match="unsupported symbol_request schema"):
            symbol_request.load(path)

    def test_rejects_a_document_without_kernels(self, tmp_path) -> None:
        path = tmp_path / symbol_request.FILENAME
        path.write_text(
            json.dumps({"schema_version": symbol_request.SCHEMA_VERSION}), encoding="utf-8"
        )

        with pytest.raises(ValueError, match="missing its 'kernels' list"):
            symbol_request.load(path)
