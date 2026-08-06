"""Tests for the command-line entry point.

Exit codes are part of the contract, since the analyst workflow is a loop:
run, fetch symbols if told to, run again.

    0  ready / satisfied
    1  no kernel found
    2  bad input
    3  symbols missing, request written
"""

from __future__ import annotations

import lzma
import struct

import pytest

from app.__main__ import main
from app.symbols import RSDS_MAGIC, KernelPdb, encode_guid

from .test_symbols import GOLDEN_AGE, GOLDEN_GUID, GOLDEN_NAME


@pytest.fixture
def image(tmp_path):
    record = (
        RSDS_MAGIC
        + encode_guid(GOLDEN_GUID)
        + struct.pack("<I", GOLDEN_AGE)
        + GOLDEN_NAME.encode()
        + b"\x00"
    )
    path = tmp_path / "image.raw"
    total, offset = 1 << 20, 4096
    path.write_bytes(b"\xcc" * offset + record + b"\xcc" * (total - offset - len(record)))
    return path


@pytest.fixture
def empty_image(tmp_path):
    path = tmp_path / "blank.raw"
    path.write_bytes(b"\xcc" * (1 << 19))
    return path


def place_isf(symbols_dir, kernel: KernelPdb) -> None:
    path = kernel.isf_path(symbols_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with lzma.open(path, "wt") as handle:
        handle.write("{}")


class TestSymbolsCommand:
    def test_missing_symbols_writes_a_request_and_exits_three(
        self, tmp_path, image, capsys
    ) -> None:
        request = tmp_path / "symbol_request.json"
        code = main(
            [
                "symbols",
                "--image", str(image),
                "--symbols", str(tmp_path / "symbols"),
                "--output", str(request),
            ]
        )

        assert code == 3
        assert request.is_file()

        out = capsys.readouterr().out
        assert "MISSING" in out
        assert f"/{GOLDEN_GUID}{GOLDEN_AGE}/" in out          # URL uses GUID+age
        assert f"{GOLDEN_GUID}-{GOLDEN_AGE}.json.xz" in out   # ISF uses GUID-age

    def test_present_symbols_exit_zero(self, tmp_path, image, capsys) -> None:
        symbols = tmp_path / "symbols"
        place_isf(symbols, KernelPdb(GOLDEN_NAME, GOLDEN_GUID, GOLDEN_AGE))

        code = main(["symbols", "--image", str(image), "--symbols", str(symbols)])

        assert code == 0
        assert "Ready to run plugins" in capsys.readouterr().out

    def test_reports_the_custody_hash(self, tmp_path, image, capsys) -> None:
        import hashlib

        main(["symbols", "--image", str(image), "--symbols", str(tmp_path / "s"),
              "--output", str(tmp_path / "r.json")])

        expected = hashlib.sha256(image.read_bytes()).hexdigest()
        assert expected in capsys.readouterr().out

    def test_no_hash_skips_the_digest(self, tmp_path, image, capsys) -> None:
        main(["symbols", "--image", str(image), "--symbols", str(tmp_path / "s"),
              "--no-hash", "--output", str(tmp_path / "r.json")])

        assert "SHA-256" not in capsys.readouterr().out

    def test_missing_image_exits_two(self, tmp_path, capsys) -> None:
        code = main(["symbols", "--image", str(tmp_path / "absent.raw")])

        assert code == 2
        assert "not found" in capsys.readouterr().err

    def test_no_kernel_found_exits_one(self, tmp_path, empty_image, capsys) -> None:
        code = main(["symbols", "--image", str(empty_image), "--symbols", str(tmp_path / "s")])

        assert code == 1
        assert "No Windows kernel PDB record found" in capsys.readouterr().out

    def test_no_request_written_when_nothing_missing(self, tmp_path, image) -> None:
        symbols = tmp_path / "symbols"
        place_isf(symbols, KernelPdb(GOLDEN_NAME, GOLDEN_GUID, GOLDEN_AGE))
        request = tmp_path / "symbol_request.json"

        main(["symbols", "--image", str(image), "--symbols", str(symbols),
              "--output", str(request)])

        assert not request.exists()


class TestVerifyCommand:
    def test_reports_satisfied(self, tmp_path, image, capsys) -> None:
        request = tmp_path / "symbol_request.json"
        symbols = tmp_path / "symbols"
        main(["symbols", "--image", str(image), "--symbols", str(symbols),
              "--output", str(request)])

        place_isf(symbols, KernelPdb(GOLDEN_NAME, GOLDEN_GUID, GOLDEN_AGE))
        code = main(["verify", str(request), "--symbols", str(symbols)])

        assert code == 0
        assert "Safe to return to the secure host" in capsys.readouterr().out

    def test_reports_still_missing(self, tmp_path, image, capsys) -> None:
        request = tmp_path / "symbol_request.json"
        symbols = tmp_path / "symbols"
        main(["symbols", "--image", str(image), "--symbols", str(symbols),
              "--output", str(request)])

        code = main(["verify", str(request), "--symbols", str(symbols)])

        assert code == 3
        assert "still missing" in capsys.readouterr().out


class TestParser:
    def test_version(self, capsys) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--version"])
        assert excinfo.value.code == 0
        assert "v4ag" in capsys.readouterr().out

    def test_a_subcommand_is_required(self) -> None:
        with pytest.raises(SystemExit):
            main([])


class TestDoctor:
    """Doctor exists to diagnose a host we cannot reach, so it must never crash."""

    def test_reports_the_interpreter_architecture(self, capsys) -> None:
        """The host CPU is not the process architecture; the bundle's arch is what matters."""
        assert main(["doctor"]) in (0, 1)

        out = capsys.readouterr().out
        assert "interpreter" in out
        assert "host cpu" in out

    def test_reports_required_components(self, capsys) -> None:
        main(["doctor"])
        out = capsys.readouterr().out

        for name in ("lzma", "sqlite3", "ssl", "hashlib", "pefile"):
            assert name in out

    def test_survives_a_missing_symbols_directory(self, tmp_path, capsys) -> None:
        code = main(["doctor", "--symbols", str(tmp_path / "nope")])
        assert code in (0, 1)
        assert "missing" in capsys.readouterr().out

    def test_reports_an_empty_symbols_directory(self, tmp_path, capsys) -> None:
        (tmp_path / "symbols").mkdir()
        main(["doctor", "--symbols", str(tmp_path / "symbols")])
        assert "empty" in capsys.readouterr().out

    def test_an_unimportable_optional_module_is_not_fatal(self, capsys) -> None:
        """Optional components absent must not fail the check."""
        import app.__main__ as cli

        original = cli._OPTIONAL
        cli._OPTIONAL = [("definitely_not_installed_xyz", "nonexistent")]
        try:
            code = main(["doctor"])
        finally:
            cli._OPTIONAL = original

        assert code in (0, 1)
        assert "absent" in capsys.readouterr().out
