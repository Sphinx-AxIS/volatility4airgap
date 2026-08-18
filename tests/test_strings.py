"""Tests for the strings extractor, the hits search, and the two commands over them.

The extractor is checked against a plain-Python reference across many chunk
sizes, because chunk boundaries are where a streaming strings tool goes wrong:
a string cut in two, or emitted twice, or a UTF-16 pair split between reads.
"""

from __future__ import annotations

import codecs
import json
import os
import random
import sys
from pathlib import Path

import pytest

from app import strings as S
from app.__main__ import main


# --------------------------------------------------------------- reference model


def _printable(byte: int) -> bool:
    return 0x20 <= byte <= 0x7E or byte == 0x09


def reference(data: bytes, min_length: int) -> list[tuple[int, bytes]]:
    """What ``strings`` means, written the slow obvious way."""
    found: list[tuple[int, bytes]] = []
    i, n = 0, len(data)
    while i < n:
        if _printable(data[i]):
            j = i
            while j < n and _printable(data[j]):
                j += 1
            if j - i >= min_length:
                found.append((i, data[i:j]))
            i = j
        else:
            i += 1
    i = 0
    while i < n:
        if i + 1 < n and _printable(data[i]) and data[i + 1] == 0:
            j = i
            while j + 1 < n and _printable(data[j]) and data[j + 1] == 0:
                j += 2
            if (j - i) // 2 >= min_length:
                found.append((i, data[i:j:2]))
                i = j
            else:
                i += 1
        else:
            i += 1
    return sorted(found)


def extracted(tmp_path: Path, data: bytes, **kwargs) -> list[tuple[int, bytes]]:
    image = tmp_path / "image.raw"
    output = tmp_path / "image.strings"
    image.write_bytes(data)
    S.extract(image, output, **kwargs)
    result = []
    for line in output.read_bytes().split(b"\n"):
        if line:
            offset, text = line.split(b":", 1)
            result.append((int(offset), text))
    return sorted(result)


class TestExtractor:
    def test_ascii_string_offset_and_text(self, tmp_path) -> None:
        data = b"\x00\x00hello world\x00\xffab\x00"
        assert extracted(tmp_path, data) == [(2, b"hello world")]

    def test_min_length_is_in_characters(self, tmp_path) -> None:
        data = b"\x00abc\x00abcd\x00"
        assert extracted(tmp_path, data, min_length=4) == [(5, b"abcd")]
        assert extracted(tmp_path, data, min_length=3) == [(1, b"abc"), (5, b"abcd")]

    def test_tab_counts_as_printable(self, tmp_path) -> None:
        assert extracted(tmp_path, b"\x00a\tb\tc\x00") == [(1, b"a\tb\tc")]

    def test_utf16_string_is_decoded_at_its_true_offset(self, tmp_path) -> None:
        data = b"\x00\x01" + "wide text".encode("utf-16-le") + b"\x00\x00\x02"
        assert extracted(tmp_path, data) == [(2, b"wide text")]

    def test_utf16_at_an_odd_offset(self, tmp_path) -> None:
        data = b"\x00" + "odd".encode("utf-16-le") + b"\x00"
        assert extracted(tmp_path, data, min_length=3) == [(1, b"odd")]

    def test_a_wide_string_needs_real_nuls_not_any_non_printable(self, tmp_path) -> None:
        """``a\\xffb\\xffc\\xffd\\xff`` is not UTF-16."""
        data = b"a\xffb\xffc\xffd\xff"
        assert extracted(tmp_path, data) == []

    def test_lines_are_decimal_offset_colon_string(self, tmp_path) -> None:
        image = tmp_path / "i.raw"
        output = tmp_path / "i.strings"
        image.write_bytes(b"\x00" * 1000 + b"marker!" + b"\x00")
        S.extract(image, output)
        assert output.read_bytes() == b"1000:marker!\n"

    def test_only_selected_encodings_are_scanned(self, tmp_path) -> None:
        data = b"ascii-run\x00\x00" + "wide-run".encode("utf-16-le")
        assert extracted(tmp_path, data, encodings=("ascii",)) == [(0, b"ascii-run")]
        assert extracted(tmp_path, data, encodings=("unicode",)) == [(11, b"wide-run")]

    def test_result_counts(self, tmp_path) -> None:
        image = tmp_path / "i.raw"
        image.write_bytes(b"one!\x00two!\x00" + "wide".encode("utf-16-le"))
        result = S.extract(image, tmp_path / "o")
        assert (result.strings, result.ascii, result.unicode) == (3, 2, 1)
        assert result.image_size == image.stat().st_size
        assert result.as_dict()["offsets"] == "exact"

    def test_empty_image_gives_empty_output(self, tmp_path) -> None:
        assert extracted(tmp_path, b"") == []

    def test_rejects_bad_options(self, tmp_path) -> None:
        image = tmp_path / "i.raw"
        image.write_bytes(b"x")
        with pytest.raises(ValueError):
            S.extract(image, tmp_path / "o", min_length=0)
        with pytest.raises(ValueError):
            S.extract(image, tmp_path / "o", encodings=("ebcdic",))
        with pytest.raises(ValueError):
            S.extract(image, tmp_path / "o", encodings=())

    def test_progress_is_reported_per_chunk(self, tmp_path) -> None:
        image = tmp_path / "i.raw"
        image.write_bytes(b"\x00" * 10)
        seen = []
        S.extract(image, tmp_path / "o", chunk_size=4, progress=lambda d, t, c: seen.append((d, t)))
        assert seen == [(4, 10), (8, 10), (10, 10)]


class TestChunkBoundaries:
    """The extractor must be indifferent to where reads happen to end."""

    def test_string_across_a_boundary_comes_out_once_and_whole(self, tmp_path) -> None:
        data = b"\x00\x00\x00abcdefgh\x00"
        for chunk in range(1, 14):
            assert extracted(tmp_path, data, chunk_size=chunk) == [(3, b"abcdefgh")], chunk

    def test_wide_pair_split_between_chunks(self, tmp_path) -> None:
        """The character byte in one read, its NUL in the next."""
        data = "split".encode("utf-16-le")
        for chunk in range(1, 12):
            assert extracted(tmp_path, data, chunk_size=chunk) == [(0, b"split")], chunk

    def test_short_tail_joins_the_next_chunk(self, tmp_path) -> None:
        """Two printable bytes at a chunk's end are not a string yet, but with
        the next chunk's first bytes they are one."""
        data = b"\x00\x00ab" + b"cd\x00\x00"
        assert extracted(tmp_path, data, chunk_size=4) == [(2, b"abcd")]

    def test_agrees_with_the_reference_for_every_chunk_size(self, tmp_path) -> None:
        rng = random.Random(7)
        alphabet = [b"A", b"b", b"\x00", b"\x00", b"\xff", b"\t", b" ", b"Z\x00", b"q\x00", b"\x01"]
        for _ in range(60):
            data = b"".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
            for min_length in (1, 2, 4):
                expected = reference(data, min_length)
                for chunk in (1, 2, 3, 5, 8, 64):
                    got = extracted(tmp_path, data, min_length=min_length, chunk_size=chunk)
                    assert got == expected, (data, min_length, chunk)

    def test_a_run_past_the_carry_limit_is_cut_not_lost(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(S, "MAX_CARRY", 8)
        text = bytes(range(0x41, 0x41 + 26)) * 2  # 52 printable bytes
        pieces = extracted(tmp_path, b"\x00" + text + b"\x00", chunk_size=8)
        assert len(pieces) > 1
        assert b"".join(t for _, t in pieces) == text
        # each piece starts where the previous ended
        assert all(pieces[i][0] + len(pieces[i][1]) == pieces[i + 1][0] for i in range(len(pieces) - 1))
        assert pieces[0][0] == 1

    def test_a_wide_run_past_the_carry_limit_is_cut_not_lost(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(S, "MAX_CARRY", 8)
        text = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        pieces = extracted(tmp_path, b"\x00" + text.decode().encode("utf-16-le"), chunk_size=8)
        assert len(pieces) > 1
        assert b"".join(t for _, t in pieces) == text

    def test_cut_pieces_cover_each_reference_string_exactly(self, tmp_path, monkeypatch) -> None:
        """With the carry limit tiny, every string still comes out — as
        consecutive pieces that reassemble it, and nothing besides."""
        rng = random.Random(11)
        alphabet = [b"A", b"b", b"\x00", b"\x00", b"\xff", b"\t", b" ", b"Z\x00", b"q\x00", b"\x01"]

        def uncovered(data: bytes, pieces: list, expected: list) -> str | None:
            remaining = list(pieces)
            for offset, text in expected:
                width = 1 if data[offset : offset + len(text)] == text else 2
                stop = offset + len(text) * width
                position = offset
                while position < stop:
                    fits = [
                        p for p in remaining
                        if p[0] == position
                        and position + len(p[1]) * width <= stop
                        and data[position : position + len(p[1]) * width : width] == p[1]
                    ]
                    fits.sort(key=lambda p: -len(p[1]))
                    if not fits:
                        return f"gap at {position} in {(offset, text)}"
                    remaining.remove(fits[0])
                    position += len(fits[0][1]) * width
            return f"extra {remaining}" if remaining else None

        for _ in range(40):
            data = b"".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
            for min_length in (2, 4):
                expected = reference(data, min_length)
                for chunk in (1, 3, 8):
                    for carry in (1, 3, 6):
                        monkeypatch.setattr(S, "MAX_CARRY", carry)
                        pieces = extracted(tmp_path, data, min_length=min_length, chunk_size=chunk)
                        problem = uncovered(data, pieces, expected)
                        assert problem is None, (data, min_length, chunk, carry, problem)


# ------------------------------------------------------------------------- hits


class TestParseLine:
    def test_this_tools_and_sysinternals_shape(self) -> None:
        assert S.parse_line(b"12345:text here\n") == (12345, b"text here")

    def test_leading_spaces_of_the_string_survive(self) -> None:
        assert S.parse_line(b"7:        Host Application = x\r\n") == (7, b"        Host Application = x")

    def test_gnu_strings_shape(self) -> None:
        assert S.parse_line(b"    123 text\n") == (123, b"text")

    def test_garbage_is_none(self) -> None:
        assert S.parse_line(b"FINDSTR: Line 5173 is too long.") is None
        assert S.parse_line(b"") is None


def write_strings(path: Path, lines: list[bytes], *, newline: bytes = b"\n", prefix: bytes = b"") -> Path:
    path.write_bytes(prefix + newline.join(lines) + newline)
    return path


class TestScanHits:
    def test_finds_lines_containing_a_term_case_insensitively(self, tmp_path) -> None:
        path = write_strings(tmp_path / "s", [b"10:nothing", b"20:The NEEDLE here", b"30:needle again"])
        scan = S.scan_hits(path, ["needle"])
        assert [(h.stated, h.string) for h in scan.hits] == [
            (20, b"The NEEDLE here"), (30, b"needle again"),
        ]
        assert scan.lines == 3

    def test_case_sensitive_when_asked(self, tmp_path) -> None:
        path = write_strings(tmp_path / "s", [b"20:The NEEDLE here", b"30:needle again"])
        scan = S.scan_hits(path, ["needle"], ignore_case=False)
        assert [h.stated for h in scan.hits] == [30]

    def test_a_line_matching_two_terms_is_one_hit(self, tmp_path) -> None:
        path = write_strings(tmp_path / "s", [b"5:alpha and beta"])
        scan = S.scan_hits(path, ["alpha", "beta"])
        assert len(scan.hits) == 1

    def test_crlf_lines(self, tmp_path) -> None:
        path = write_strings(tmp_path / "s", [b"5:needle one", b"9:other"], newline=b"\r\n")
        scan = S.scan_hits(path, ["needle"])
        assert scan.hits[0].string == b"needle one"
        assert scan.hits[0].line == b"5:needle one"

    def test_block_boundaries_do_not_split_lines(self, tmp_path) -> None:
        lines = [b"%d:filler line number %d" % (i * 10, i) for i in range(200)]
        lines[77] = b"770:the needle line"
        lines[150] = b"1500:another needle"
        path = write_strings(tmp_path / "s", lines)
        for block in (7, 16, 33, 100, 4096):
            scan = S.scan_hits(path, ["needle"], block_size=block)
            assert [h.stated for h in scan.hits] == [770, 1500], block
            assert scan.lines == 200

    def test_last_line_without_newline(self, tmp_path) -> None:
        (tmp_path / "s").write_bytes(b"1:first\n2:needle at end")
        scan = S.scan_hits(tmp_path / "s", ["needle"])
        assert [h.stated for h in scan.hits] == [2]
        assert scan.lines == 2

    def test_utf16_file_with_bom_is_transcoded(self, tmp_path) -> None:
        """PowerShell 5's redirection writes UTF-16; the file must still search."""
        text = "10:plain\n20:needle in utf16\n"
        (tmp_path / "s").write_bytes(codecs.BOM_UTF16_LE + text.encode("utf-16-le"))
        scan = S.scan_hits(tmp_path / "s", ["NEEDLE"])
        assert [(h.stated, h.string) for h in scan.hits] == [(20, b"needle in utf16")]

    def test_utf8_bom_is_skipped(self, tmp_path) -> None:
        (tmp_path / "s").write_bytes(codecs.BOM_UTF8 + b"10:needle first\n")
        scan = S.scan_hits(tmp_path / "s", ["needle"])
        assert [h.stated for h in scan.hits] == [10]

    def test_max_hits_stops_the_scan(self, tmp_path) -> None:
        path = write_strings(tmp_path / "s", [b"%d:needle %d" % (i, i) for i in range(50)])
        scan = S.scan_hits(path, ["needle"], max_hits=10)
        assert scan.truncated is True
        assert len(scan.hits) == 10

    def test_unparseable_matching_lines_are_counted(self, tmp_path) -> None:
        path = write_strings(tmp_path / "s", [b"FINDSTR: needle too long", b"5:needle"])
        scan = S.scan_hits(path, ["needle"])
        assert scan.unparsed == 1
        assert [h.stated for h in scan.hits] == [5]

    def test_offset_statistics_see_a_wrapped_file(self, tmp_path) -> None:
        """Offsets that never pass 4 GiB and restart from near zero."""
        lines = [b"100:a", b"4000000000:b", b"200:needle", b"4100000000:c", b"50:needle"]
        scan = S.scan_hits(write_strings(tmp_path / "s", lines), ["needle"], block_size=8)
        assert scan.max_offset == 4100000000
        assert scan.drops == 2

    def test_no_terms_is_an_error(self, tmp_path) -> None:
        with pytest.raises(ValueError):
            S.scan_hits(write_strings(tmp_path / "s", [b"1:x"]), [""])


WRAP = 1 << 16


def build_image(path: Path, size: int, placements: dict[int, bytes]) -> Path:
    """An image of ``size`` zero bytes with byte strings placed at offsets."""
    buffer = bytearray(size)
    for offset, data in placements.items():
        buffer[offset : offset + len(data)] = data
    path.write_bytes(bytes(buffer))
    return path


class TestLocate:
    def test_a_hit_at_its_stated_offset(self, tmp_path) -> None:
        image = build_image(tmp_path / "i", 3 * WRAP, {1000: b"exact string"})
        hits = [S.Hit(1000, b"exact string", b"1000:exact string")]
        location = S.locate(image, hits, wrap=WRAP)
        assert hits[0].located == [1000]
        assert (location.at_stated, location.relocated, location.unresolved) == (1, 0, 0)
        assert location.wrapped is False

    def test_a_wrapped_hit_is_found_a_multiple_of_the_wrap_on(self, tmp_path) -> None:
        image = build_image(tmp_path / "i", 3 * WRAP, {2 * WRAP + 500: b"folded string"})
        hits = [S.Hit(500, b"folded string", b"500:folded string")]
        location = S.locate(image, hits, wrap=WRAP)
        assert hits[0].located == [2 * WRAP + 500]
        assert location.relocated == 1
        assert location.wrapped is True

    def test_a_string_present_at_two_candidates_yields_both(self, tmp_path) -> None:
        image = build_image(tmp_path / "i", 3 * WRAP, {700: b"twice", WRAP + 700: b"twice"})
        hits = [S.Hit(700, b"twice", b"700:twice")]
        location = S.locate(image, hits, wrap=WRAP)
        assert hits[0].located == [700, WRAP + 700]
        # present where it says it is: not evidence of wrapping
        assert location.wrapped is False

    def test_a_utf16_string_in_memory_matches_its_decoded_line(self, tmp_path) -> None:
        image = build_image(tmp_path / "i", WRAP, {300: "wide one".encode("utf-16-le")})
        hits = [S.Hit(300, b"wide one", b"300:wide one")]
        S.locate(image, hits, wrap=WRAP)
        assert hits[0].located == [300]

    def test_unresolved_when_the_bytes_are_nowhere(self, tmp_path) -> None:
        image = build_image(tmp_path / "i", 2 * WRAP, {})
        hits = [S.Hit(10, b"absent", b"10:absent"), S.Hit(5 * WRAP, b"beyond", b"x")]
        location = S.locate(image, hits, wrap=WRAP)
        assert location.unresolved == 2
        assert S.unresolved_lines(hits) == [b"10:absent\n", b"x\n"]

    def test_only_the_probe_prefix_need_match(self, tmp_path) -> None:
        long = b"x" * 200
        image = build_image(tmp_path / "i", WRAP, {40: long})
        hits = [S.Hit(40, long + b"tail that memory lacks", b"")]
        S.locate(image, hits, wrap=WRAP)
        assert hits[0].located == [40]

    def test_an_image_smaller_than_the_wrap_has_one_candidate(self, tmp_path) -> None:
        image = build_image(tmp_path / "i", 100, {10: b"here"})
        hits = [S.Hit(10, b"here", b"")]
        S.locate(image, hits, wrap=WRAP)
        assert hits[0].located == [10]

    def test_relocation_survives_the_real_wrap_constant(self) -> None:
        assert S.WRAP == 2**32


class TestPluginLines:
    def _hits(self):
        a = S.Hit(100, b"alpha", b"", located=[100])
        b = S.Hit(200, b"beta", b"", located=[WRAP + 200])
        c = S.Hit(300, b"gamma", b"", located=[300, 2 * WRAP + 300])
        d = S.Hit(400, b"delta", b"", located=[])
        return [a, b, c, d]

    def test_exact_file_keeps_stated_offsets_only(self) -> None:
        assert S.plugin_lines(self._hits(), wrapped=False) == [
            b"100:alpha\n", b"300:gamma\n",
        ]

    def test_wrapped_file_keeps_every_verified_location(self) -> None:
        assert S.plugin_lines(self._hits(), wrapped=True) == [
            b"100:alpha\n", b"300:gamma\n", b"%d:beta\n" % (WRAP + 200),
            b"%d:gamma\n" % (2 * WRAP + 300),
        ]

    def test_trust_passes_the_file_through(self) -> None:
        lines = S.plugin_lines(self._hits(), wrapped=False, trust=True)
        assert lines == [b"100:alpha\n", b"200:beta\n", b"300:gamma\n", b"400:delta\n"]

    def test_duplicates_collapse(self) -> None:
        hits = [S.Hit(1, b"same", b"", located=[1]), S.Hit(1, b"same", b"", located=[1])]
        assert S.plugin_lines(hits, wrapped=True) == [b"1:same\n"]


class TestReport:
    ROWS = [
        {"String": "cmd one", "Physical Address": 4096, "Result": "Process 4180:0x1b2c3d4e"},
        {"String": "cmd two", "Physical Address": 8192, "Result": "Process 4180:0x1b2c4000"},
        {"String": "kern", "Physical Address": 12, "Result": "kernel:0xfffff80000000000"},
        {"String": "gone", "Physical Address": 99, "Result": "FREE MEMORY"},
        {"String": "shared", "Physical Address": 5, "Result": "Process 4180:0x1, Process 900:0x2"},
    ]

    def test_groups_by_owner_most_hits_first(self) -> None:
        groups = S.group_rows(self.ROWS, {4180: "powershell.exe"})
        assert [g.label for g in groups] == [
            "Process 4180 powershell.exe", "FREE MEMORY", "Process 4180 powershell.exe, Process 900",
            "kernel",
        ]
        assert len(groups[0].rows) == 2

    def test_process_names_from_pslist_rows(self) -> None:
        names = S.process_names([{"PID": 4, "ImageFileName": "System"}, {"PID": "x"}])
        assert names == {4: "System"}

    def test_report_lines_show_offset_and_string(self) -> None:
        lines = S.report_lines(S.group_rows(self.ROWS[:1]))
        assert lines[0] == "Process 4180  (1 hit)"
        assert lines[1].strip() == "0x1000  cmd one"

    def test_report_truncates_when_asked(self) -> None:
        rows = [{"String": "y" * 50, "Physical Address": 1, "Result": "kernel:0x1"}] * 3
        lines = S.report_lines(S.group_rows(rows), width=20, per_group=2)
        assert lines[1].endswith("y" * 17 + "...")
        assert lines[-1].strip() == "... 1 more"

    def test_console_safe_drops_what_a_console_cannot_show(self) -> None:
        assert S.console_safe("café – x") == "caf? ? x"


# ------------------------------------------------------------------------- CLI


@pytest.fixture
def image(tmp_path):
    """A small 'memory image' with strings placed in three 64 KiB 'passes'."""
    return build_image(
        tmp_path / "mem.raw",
        3 * WRAP,
        {
            100: b"needle in the first pass",
            WRAP + 100: b"needle in the second pass",
            2 * WRAP + 100: "wide needle".encode("utf-16-le"),
            2 * WRAP + 900: b"unrelated text here",
        },
    )


class TestStringsCommand:
    def test_writes_the_strings_file_and_its_sidecar(self, tmp_path, image, capsys) -> None:
        out = tmp_path / "results"
        assert main(["strings", "--image", str(image), "--out", str(out)]) == 0
        strings_file = out / "strings" / "mem.strings"
        assert strings_file.is_file()
        text = strings_file.read_bytes()
        assert b"100:needle in the first pass\n" in text
        assert b"%d:wide needle\n" % (2 * WRAP + 100) in text
        sidecar = json.loads((out / "strings" / "mem.strings.json").read_text())
        assert sidecar["offsets"] == "exact"
        assert sidecar["strings"] == 4
        assert "strings-hits" in capsys.readouterr().out

    def test_refuses_to_overwrite_unless_told(self, tmp_path, image, capsys) -> None:
        out = tmp_path / "results"
        assert main(["strings", "--image", str(image), "--out", str(out)]) == 0
        assert main(["strings", "--image", str(image), "--out", str(out)]) == 2
        assert "--overwrite" in capsys.readouterr().err
        assert main(["strings", "--image", str(image), "--out", str(out), "--overwrite"]) == 0

    def test_encoding_and_min_length_options(self, tmp_path, image) -> None:
        out = tmp_path / "results"
        main(["strings", "--image", str(image), "--out", str(out), "--encoding", "unicode"])
        assert (out / "strings" / "mem.strings").read_bytes() == b"%d:wide needle\n" % (2 * WRAP + 100)
        main(["strings", "--image", str(image), "--out", str(out), "--overwrite", "--min-length", "20"])
        text = (out / "strings" / "mem.strings").read_bytes()
        assert b"needle in the first pass" in text and b"wide needle" not in text

    def test_bad_input_exits_two(self, tmp_path, image, capsys) -> None:
        assert main(["strings", "--image", str(tmp_path / "missing.raw")]) == 2
        assert main(["strings", "--image", str(image), "--out", str(tmp_path), "--min-length", "0"]) == 2


class FakeEngine:
    """Stands in for Volatility: records the argv it was asked for and emits rows."""

    name = "fake"

    def __init__(self, rows=None, *, fail: bool = False):
        self.rows = rows if rows is not None else []
        self.fail = fail
        self.calls: list[dict] = []

    def command(self, image, plugin, renderer, **kwargs) -> list[str]:
        self.calls.append({"image": image, "plugin": plugin, "renderer": renderer, **kwargs})
        if self.fail:
            code = "import sys; sys.stderr.write('boom\\n'); raise SystemExit(1)"
        else:
            code = f"import json; print(json.dumps({json.dumps(self.rows)}))"
        return [sys.executable, "-c", code]


@pytest.fixture
def fake_engine(monkeypatch):
    from app import engine as engine_mod

    fake = FakeEngine()
    monkeypatch.setattr(engine_mod, "select", lambda preference, root: fake)
    return fake


@pytest.fixture
def wrapped_strings(tmp_path, image):
    """A Sysinternals-style file for ``image``: offsets folded at WRAP, passes in turn."""
    lines = [
        b"100:needle in the first pass\r\n",
        b"100:needle in the second pass\r\n",
        b"100:wide needle\r\n",
        b"900:unrelated text here\r\n",
    ]
    path = tmp_path / "sysinternals.strings"
    path.write_bytes(b"".join(lines))
    return path


class TestStringsHitsCommand:
    def test_relocates_wrapped_offsets_and_runs_the_plugin(
        self, tmp_path, image, wrapped_strings, fake_engine, monkeypatch, capsys
    ) -> None:
        monkeypatch.setattr(S, "WRAP", WRAP)
        fake_engine.rows = [
            {"String": "needle in the second pass", "Physical Address": WRAP + 100,
             "Result": "Process 4180:0x7ff600001000"},
            {"String": "needle in the first pass", "Physical Address": 100, "Result": "FREE MEMORY"},
        ]
        out = tmp_path / "results"
        code = main([
            "strings-hits", "--image", str(image), "--strings-file", str(wrapped_strings),
            "--out", str(out), "--term", "NEEDLE",
        ])
        assert code == 0
        printed = capsys.readouterr().out
        assert "32-bit offsets" in printed
        assert "2 hit(s) are not where their offsets say" in printed

        hits = (out / "strings" / "strings-hits.txt").read_bytes()
        assert hits == (
            b"100:needle in the first pass\n"
            + b"%d:needle in the second pass\n" % (WRAP + 100)
            + b"%d:wide needle\n" % (2 * WRAP + 100)
        )
        # the plugin got exactly that file, and nothing else after it
        call = fake_engine.calls[0]
        assert call["plugin"] == "windows.strings.Strings"
        assert call["plugin_args"] == ["--strings-file", str(out / "strings" / "strings-hits.txt")]
        assert "swap_files" not in call

        assert "Process 4180  (1 hit)" in printed
        assert "FREE MEMORY  (1 hit)" in printed
        report = (out / "strings" / "strings-hits-report.txt").read_text()
        assert "needle in the second pass" in report
        record = json.loads((out / "strings" / "strings-hits.json").read_text())
        assert record["offsets"] == "wrapped, relocated"
        assert record["relocated"] == 2 and record["at_stated_offset"] == 1
        assert record["plugin"]["status"] == "ok" and record["plugin"]["rows"] == 2
        assert (out / "strings" / "windows.strings.Strings.json").is_file()

    def test_uses_pslist_names_when_a_triage_run_is_beside_it(
        self, tmp_path, image, wrapped_strings, fake_engine, monkeypatch, capsys
    ) -> None:
        monkeypatch.setattr(S, "WRAP", WRAP)
        out = tmp_path / "results"
        out.mkdir()
        (out / "windows.pslist.PsList.json").write_text(
            json.dumps([{"PID": 4180, "ImageFileName": "powershell.exe"}])
        )
        fake_engine.rows = [{"String": "x", "Physical Address": 1, "Result": "Process 4180:0x1"}]
        main(["strings-hits", "--image", str(image), "--strings-file", str(wrapped_strings),
              "--out", str(out), "--term", "needle"])
        assert "Process 4180 powershell.exe  (1 hit)" in capsys.readouterr().out

    def test_default_strings_file_is_the_one_strings_wrote(
        self, tmp_path, image, fake_engine, capsys
    ) -> None:
        out = tmp_path / "results"
        assert main(["strings", "--image", str(image), "--out", str(out)]) == 0
        assert main(["strings-hits", "--image", str(image), "--out", str(out),
                     "--term", "second pass", "--no-run"]) == 0
        printed = capsys.readouterr().out
        assert "at their stated offset" in printed
        assert (out / "strings" / "strings-hits.txt").read_bytes() == (
            b"%d:needle in the second pass\n" % (WRAP + 100)
        )
        assert fake_engine.calls == []
        record = json.loads((out / "strings" / "strings-hits.json").read_text())
        assert record["offsets"] == "exact" and "plugin" not in record

    def test_missing_strings_file_says_how_to_make_one(self, tmp_path, image, capsys) -> None:
        assert main(["strings-hits", "--image", str(image), "--out", str(tmp_path / "r"),
                     "--term", "x"]) == 2
        err = capsys.readouterr().err
        assert "v4ag strings --image" in err and "--strings-file" in err

    def test_no_terms_exits_two(self, tmp_path, image, wrapped_strings, capsys) -> None:
        assert main(["strings-hits", "--image", str(image), "--strings-file",
                     str(wrapped_strings), "--out", str(tmp_path / "r")]) == 2
        assert "--term" in capsys.readouterr().err

    def test_terms_file_with_comments(self, tmp_path, image, wrapped_strings, fake_engine, monkeypatch) -> None:
        monkeypatch.setattr(S, "WRAP", WRAP)
        terms = tmp_path / "terms.txt"
        terms.write_text("# things to look for\nsecond pass\n\nwide\n", encoding="utf-8")
        out = tmp_path / "r"
        assert main(["strings-hits", "--image", str(image), "--strings-file", str(wrapped_strings),
                     "--out", str(out), "--terms-file", str(terms), "--no-run"]) == 0
        hits = (out / "strings" / "strings-hits.txt").read_bytes()
        assert hits.count(b"\n") == 2
        assert json.loads((out / "strings" / "strings-hits.json").read_text())["terms"] == [
            "second pass", "wide",
        ]

    def test_no_match_is_not_a_failure(self, tmp_path, image, wrapped_strings, fake_engine, capsys) -> None:
        assert main(["strings-hits", "--image", str(image), "--strings-file", str(wrapped_strings),
                     "--out", str(tmp_path / "r"), "--term", "zzz-not-there"]) == 0
        assert "No line matched" in capsys.readouterr().out
        assert fake_engine.calls == []

    def test_unresolved_hits_are_kept_out_and_listed(self, tmp_path, image, fake_engine, monkeypatch, capsys) -> None:
        monkeypatch.setattr(S, "WRAP", WRAP)
        strings_file = tmp_path / "s.strings"
        strings_file.write_bytes(b"100:needle in the first pass\n555:needle nowhere in memory\n")
        out = tmp_path / "r"
        assert main(["strings-hits", "--image", str(image), "--strings-file", str(strings_file),
                     "--out", str(out), "--term", "needle", "--no-run"]) == 0
        assert (out / "strings" / "strings-hits.txt").read_bytes() == b"100:needle in the first pass\n"
        assert (out / "strings" / "strings-hits-unresolved.txt").read_bytes() == b"555:needle nowhere in memory\n"
        assert "1 hit(s) not in the image" in capsys.readouterr().out

    def test_a_strings_file_for_another_image_exits_five(self, tmp_path, image, fake_engine, capsys) -> None:
        strings_file = tmp_path / "s.strings"
        strings_file.write_bytes(b"100:needle from some other machine\n")
        assert main(["strings-hits", "--image", str(image), "--strings-file", str(strings_file),
                     "--out", str(tmp_path / "r"), "--term", "needle"]) == 5
        assert "Is this the strings file for this image" in capsys.readouterr().err

    def test_all_unresolved_but_wrapped_structure_warns_not_exit_five(
        self, tmp_path, image, fake_engine, monkeypatch, capsys
    ) -> None:
        # A wrapped Sysinternals file of a >4 GiB image whose only matches are
        # strings with no stable page (signature fragments, transient text): the
        # offsets are structurally right, so it must not be rejected as the wrong
        # file. Small WRAP/DROP let the tiny fixture stand in for a large image:
        # the first line sits near the wrap, the matched line restarts near zero.
        monkeypatch.setattr(S, "WRAP", WRAP)
        monkeypatch.setattr(S, "DROP", 1 << 14)
        strings_file = tmp_path / "s.strings"
        strings_file.write_bytes(
            b"60000:high offset filler that does not match\n"
            b"100:phantom string absent from memory\n"
        )
        out = tmp_path / "r"
        assert main(["strings-hits", "--image", str(image), "--strings-file",
                     str(strings_file), "--out", str(out), "--term", "phantom"]) == 0
        captured = capsys.readouterr()
        assert "most likely the right one" in captured.err
        assert "Is this the strings file for this image" not in captured.err
        assert "No hit resolved" in captured.out
        # nothing resolved, so the plugin never ran and the hits file is empty
        assert fake_engine.calls == []
        assert (out / "strings" / "strings-hits.txt").read_bytes() == b""
        assert (out / "strings" / "strings-hits-unresolved.txt").read_bytes() == (
            b"100:phantom string absent from memory\n"
        )
        record = json.loads((out / "strings" / "strings-hits.json").read_text())
        assert record["at_stated_offset"] == 0 and record["relocated"] == 0
        assert record["unresolved"] == 1 and "plugin" not in record

    def test_trust_offsets_skips_the_check(self, tmp_path, image, fake_engine, capsys) -> None:
        strings_file = tmp_path / "s.strings"
        strings_file.write_bytes(b"555:needle nowhere in memory\n")
        out = tmp_path / "r"
        assert main(["strings-hits", "--image", str(image), "--strings-file", str(strings_file),
                     "--out", str(out), "--term", "needle", "--no-run", "--trust-offsets"]) == 0
        assert (out / "strings" / "strings-hits.txt").read_bytes() == b"555:needle nowhere in memory\n"
        assert json.loads((out / "strings" / "strings-hits.json").read_text())["offsets"] == "trusted"

    def test_pid_is_passed_last(self, tmp_path, image, wrapped_strings, fake_engine, monkeypatch) -> None:
        monkeypatch.setattr(S, "WRAP", WRAP)
        main(["strings-hits", "--image", str(image), "--strings-file", str(wrapped_strings),
              "--out", str(tmp_path / "r"), "--term", "needle", "--pid", "4180", "--pid", "900"])
        args = fake_engine.calls[0]["plugin_args"]
        assert args[:2] == ["--strings-file", str(tmp_path / "r" / "strings" / "strings-hits.txt")]
        assert args[2:] == ["--pid", "4180", "900"]

    def test_plugin_failure_exits_one_and_names_the_log(
        self, tmp_path, image, wrapped_strings, fake_engine, monkeypatch, capsys
    ) -> None:
        monkeypatch.setattr(S, "WRAP", WRAP)
        fake_engine.fail = True
        out = tmp_path / "r"
        assert main(["strings-hits", "--image", str(image), "--strings-file", str(wrapped_strings),
                     "--out", str(out), "--term", "needle"]) == 1
        printed = capsys.readouterr().out
        assert "FAIL exit 1" in printed
        assert str(out / "strings" / "logs" / "windows.strings.Strings.json.log") in printed
        record = json.loads((out / "strings" / "strings-hits.json").read_text())
        assert record["plugin"]["status"] == "exit 1"

    def test_too_many_hits_stops(self, tmp_path, image, wrapped_strings, fake_engine, capsys) -> None:
        assert main(["strings-hits", "--image", str(image), "--strings-file", str(wrapped_strings),
                     "--out", str(tmp_path / "r"), "--term", "e", "--max-hits", "2"]) == 2
        assert "--max-hits" in capsys.readouterr().err

    def test_bad_input_exits_two(self, tmp_path, image, wrapped_strings, capsys) -> None:
        assert main(["strings-hits", "--image", str(tmp_path / "no.raw"), "--term", "x"]) == 2
        assert main(["strings-hits", "--image", str(image), "--strings-file", str(wrapped_strings),
                     "--out", str(tmp_path / "r"), "--term", "x", "--max-hits", "0"]) == 2
