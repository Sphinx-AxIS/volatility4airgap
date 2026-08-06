"""Tests for kernel symbol identification.

The golden-vector tests are the important ones. They pin the two derived strings
that the original CORE-Respond `generate_isf.sh` conflated, so that defect cannot
reappear.
"""

from __future__ import annotations

import io
import struct

import pytest

from app.symbols import (
    KERNEL_PDB_NAMES,
    RSDS_MAGIC,
    KernelPdb,
    decode_guid,
    encode_guid,
    iter_rsds,
    parse_rsds,
    parse_symbol_server_url,
    scan_image,
)

# Taken from the example URL in the original tools/generate_isf.sh help text.
GOLDEN_GUID = "AF550CAA73AFB287705CC40079D786B4"
GOLDEN_AGE = 1
GOLDEN_NAME = "ntkrnlmp.pdb"

GOLDEN_URL = (
    "http://msdl.microsoft.com/download/symbols"
    "/ntkrnlmp.pdb/AF550CAA73AFB287705CC40079D786B41/ntkrnlmp.pdb"
)
GOLDEN_COMPRESSED_URL = (
    "http://msdl.microsoft.com/download/symbols"
    "/ntkrnlmp.pdb/AF550CAA73AFB287705CC40079D786B41/ntkrnlmp.pd_"
)
GOLDEN_ISF = "windows/ntkrnlmp.pdb/AF550CAA73AFB287705CC40079D786B4-1.json.xz"

# What generate_isf.sh actually wrote: the age digit glued onto the GUID, then a
# hardcoded "-1". Volatility can never match this.
BUGGY_ISF = "windows/ntkrnlmp.pdb/AF550CAA73AFB287705CC40079D786B41-1.json.xz"


def rsds_record(guid: str, age: int, name: str) -> bytes:
    """Build a CV_INFO_PDB70 record, the inverse of what the scanner parses."""
    return RSDS_MAGIC + encode_guid(guid) + struct.pack("<I", age) + name.encode() + b"\x00"


def image_with(record: bytes, *, offset: int, total: int) -> bytes:
    """Synthetic image: filler that cannot contain RSDS, with a record planted."""
    assert offset + len(record) <= total
    filler = b"\xcc"
    return (
        filler * offset + record + filler * (total - offset - len(record))
    )


@pytest.fixture
def golden() -> KernelPdb:
    return KernelPdb(pdb_name=GOLDEN_NAME, guid=GOLDEN_GUID, age=GOLDEN_AGE)


class TestGoldenVector:
    """The regression fence around the original defect."""

    def test_download_url(self, golden: KernelPdb) -> None:
        assert golden.download_url == GOLDEN_URL

    def test_compressed_fallback_url(self, golden: KernelPdb) -> None:
        assert golden.compressed_url == GOLDEN_COMPRESSED_URL

    def test_isf_path(self, golden: KernelPdb) -> None:
        assert golden.isf_relative_path == GOLDEN_ISF

    def test_isf_path_is_not_the_historical_bug(self, golden: KernelPdb) -> None:
        assert golden.isf_relative_path != BUGGY_ISF

    def test_url_segment_is_one_longer_than_the_guid(self, golden: KernelPdb) -> None:
        # The distinction the original script missed.
        assert len(golden.guid) == 32
        assert golden.guid_age == golden.guid + "1"
        assert len(golden.guid_age) == 33

    def test_isf_filename_carries_the_bare_guid(self, golden: KernelPdb) -> None:
        filename = golden.isf_relative_path.rsplit("/", 1)[-1]
        assert filename.startswith(GOLDEN_GUID + "-")
        assert not filename.startswith(golden.guid_age)


class TestAgeIsNotHardcoded:
    """generate_isf.sh assumed age 1. Ages above 9 also change the segment length."""

    @pytest.mark.parametrize("age", [0, 1, 2, 7, 12, 255])
    def test_age_appears_in_both_derivations(self, age: int) -> None:
        pdb = KernelPdb(GOLDEN_NAME, GOLDEN_GUID, age)
        assert pdb.guid_age == f"{GOLDEN_GUID}{age}"
        assert pdb.isf_relative_path.endswith(f"{GOLDEN_GUID}-{age}.json.xz")
        assert f"/{GOLDEN_GUID}{age}/" in pdb.download_url

    def test_two_digit_age_lengthens_the_segment(self) -> None:
        pdb = KernelPdb(GOLDEN_NAME, GOLDEN_GUID, 12)
        assert len(pdb.guid_age) == 34


class TestGuidCodec:
    def test_round_trip(self) -> None:
        assert decode_guid(encode_guid(GOLDEN_GUID)) == GOLDEN_GUID

    def test_mixed_endian_order(self) -> None:
        # Data1 is little-endian on disk, so the first four raw bytes reverse.
        raw = encode_guid("00112233" + "4455" + "6677" + "8899AABBCCDDEEFF")
        assert raw[:4] == bytes([0x33, 0x22, 0x11, 0x00])
        assert raw[4:6] == bytes([0x55, 0x44])
        assert raw[6:8] == bytes([0x77, 0x66])
        assert raw[8:] == bytes([0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])

    @pytest.mark.parametrize("bad", ["", "ABCD", GOLDEN_GUID + "1", "Z" * 32])
    def test_rejects_malformed(self, bad: str) -> None:
        with pytest.raises(ValueError):
            encode_guid(bad)

    def test_decode_requires_sixteen_bytes(self) -> None:
        with pytest.raises(ValueError):
            decode_guid(b"\x00" * 15)


class TestUrlParsing:
    def test_splits_guid_from_age(self) -> None:
        pdb = parse_symbol_server_url(GOLDEN_URL)
        assert pdb.guid == GOLDEN_GUID
        assert pdb.age == GOLDEN_AGE
        assert pdb.pdb_name == GOLDEN_NAME

    def test_round_trips_through_the_url(self, golden: KernelPdb) -> None:
        assert parse_symbol_server_url(golden.download_url).isf_relative_path == GOLDEN_ISF

    def test_recovers_a_two_digit_age(self) -> None:
        pdb = KernelPdb(GOLDEN_NAME, GOLDEN_GUID, 12)
        assert parse_symbol_server_url(pdb.download_url).age == 12

    def test_rejects_a_segment_that_is_only_a_guid(self) -> None:
        with pytest.raises(ValueError):
            parse_symbol_server_url(
                f"http://msdl.microsoft.com/download/symbols/{GOLDEN_NAME}"
                f"/{GOLDEN_GUID}/{GOLDEN_NAME}"
            )


class TestValidation:
    @pytest.mark.parametrize("guid", ["af550caa73afb287705cc40079d786b4", "ABC", ""])
    def test_rejects_non_canonical_guid(self, guid: str) -> None:
        with pytest.raises(ValueError):
            KernelPdb(GOLDEN_NAME, guid, 1)

    def test_rejects_negative_age(self) -> None:
        with pytest.raises(ValueError):
            KernelPdb(GOLDEN_NAME, GOLDEN_GUID, -1)

    def test_rejects_implausible_name(self) -> None:
        with pytest.raises(ValueError):
            KernelPdb("nt krnl\x01.pdb", GOLDEN_GUID, 1)


class TestRecordParsing:
    def test_parses_a_planted_record(self) -> None:
        buf = rsds_record(GOLDEN_GUID, GOLDEN_AGE, GOLDEN_NAME)
        pdb = parse_rsds(buf, 0)
        assert pdb is not None
        assert (pdb.pdb_name, pdb.guid, pdb.age) == (GOLDEN_NAME, GOLDEN_GUID, GOLDEN_AGE)

    def test_rejects_a_coincidental_magic(self) -> None:
        # RSDS followed by bytes that do not form a valid record.
        assert parse_rsds(RSDS_MAGIC + b"\xcc" * 512, 0) is None

    def test_rejects_a_truncated_record(self) -> None:
        record = rsds_record(GOLDEN_GUID, GOLDEN_AGE, GOLDEN_NAME)
        assert parse_rsds(record[:12], 0) is None

    def test_returns_none_when_magic_absent(self) -> None:
        assert parse_rsds(b"\xcc" * 64, 0) is None


class TestScanning:
    def test_finds_a_planted_kernel_record(self) -> None:
        record = rsds_record(GOLDEN_GUID, GOLDEN_AGE, GOLDEN_NAME)
        data = image_with(record, offset=4096, total=1 << 20)

        found = list(iter_rsds(io.BytesIO(data)))
        assert len(found) == 1
        assert found[0].offset == 4096
        assert found[0].isf_relative_path == GOLDEN_ISF

    def test_finds_a_record_straddling_a_chunk_boundary(self) -> None:
        chunk = 0x8000
        record = rsds_record(GOLDEN_GUID, GOLDEN_AGE, GOLDEN_NAME)
        # Start ten bytes before the first chunk ends.
        data = image_with(record, offset=chunk - 10, total=chunk * 3)

        found = list(iter_rsds(io.BytesIO(data), chunk_size=chunk))
        assert len(found) == 1
        assert found[0].offset == chunk - 10
        assert found[0].guid == GOLDEN_GUID

    def test_reports_each_distinct_record_once(self) -> None:
        record = rsds_record(GOLDEN_GUID, GOLDEN_AGE, GOLDEN_NAME)
        data = image_with(record, offset=1000, total=1 << 20)
        # Same identity planted twice; it is one kernel, so report it once.
        data = data[:60000] + record + data[60000 + len(record) :]

        assert len(list(iter_rsds(io.BytesIO(data)))) == 1

    def test_distinguishes_different_ages(self) -> None:
        first = rsds_record(GOLDEN_GUID, 1, GOLDEN_NAME)
        second = rsds_record(GOLDEN_GUID, 2, GOLDEN_NAME)
        data = image_with(first, offset=1000, total=1 << 20)
        data = data[:60000] + second + data[60000 + len(second) :]

        assert sorted(p.age for p in iter_rsds(io.BytesIO(data))) == [1, 2]

    def test_filters_out_non_kernel_pdbs(self) -> None:
        kernel = rsds_record(GOLDEN_GUID, GOLDEN_AGE, GOLDEN_NAME)
        other = rsds_record("0" * 31 + "1", 3, "kernel32.pdb")
        data = image_with(kernel, offset=1000, total=1 << 20)
        data = data[:60000] + other + data[60000 + len(other) :]

        assert [p.pdb_name for p in iter_rsds(io.BytesIO(data))] == [GOLDEN_NAME]

    def test_accepts_every_pdb_when_unfiltered(self) -> None:
        kernel = rsds_record(GOLDEN_GUID, GOLDEN_AGE, GOLDEN_NAME)
        other = rsds_record("0" * 31 + "1", 3, "kernel32.pdb")
        data = image_with(kernel, offset=1000, total=1 << 20)
        data = data[:60000] + other + data[60000 + len(other) :]

        names = {p.pdb_name for p in iter_rsds(io.BytesIO(data), pdb_names=None)}
        assert names == {GOLDEN_NAME, "kernel32.pdb"}

    @pytest.mark.parametrize("name", [n.decode() for n in KERNEL_PDB_NAMES])
    def test_recognises_every_kernel_variant(self, name: str) -> None:
        record = rsds_record(GOLDEN_GUID, GOLDEN_AGE, name)
        data = image_with(record, offset=2048, total=1 << 19)

        assert [p.pdb_name for p in iter_rsds(io.BytesIO(data))] == [name]

    def test_finds_nothing_in_an_image_without_a_kernel(self) -> None:
        assert list(iter_rsds(io.BytesIO(b"\xcc" * (1 << 20)))) == []

    def test_rejects_a_chunk_size_below_the_overlap(self) -> None:
        with pytest.raises(ValueError):
            list(iter_rsds(io.BytesIO(b""), chunk_size=1024))


class TestScanImage:
    def test_scans_a_file_on_disk(self, tmp_path) -> None:
        record = rsds_record(GOLDEN_GUID, GOLDEN_AGE, GOLDEN_NAME)
        image = tmp_path / "image.raw"
        image.write_bytes(image_with(record, offset=8192, total=1 << 20))

        found = scan_image(image)
        assert len(found) == 1
        assert found[0].download_url == GOLDEN_URL
        assert found[0].isf_path(tmp_path / "symbols").name == (
            f"{GOLDEN_GUID}-{GOLDEN_AGE}.json.xz"
        )
