"""Tests for command construction and backend selection.

The flags asserted here are not cosmetic. ``--offline`` is what stops an
air-gapped host waiting out a doomed symbol download on every plugin, and
``--parallelism off`` is what stops N concurrent plugins each fanning out
internally and oversubscribing the machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app import engine as engine_mod


@pytest.fixture
def lib(tmp_path) -> engine_mod.LibraryEngine:
    python = tmp_path / "python.exe"
    python.write_bytes(b"MZ")
    return engine_mod.LibraryEngine(python)


class TestCommandConstruction:
    def test_includes_image_renderer_and_plugin(self, lib, tmp_path) -> None:
        argv = lib.command(tmp_path / "image.raw", "windows.pslist.PsList", "csv")

        assert "-f" in argv and str(tmp_path / "image.raw") in argv
        assert argv[argv.index("-r") + 1] == "csv"
        assert argv[-1] == "windows.pslist.PsList", "plugin must come last"

    def test_offline_is_on_by_default(self, lib, tmp_path) -> None:
        """Without this an air-gapped host waits for a doomed download per plugin."""
        assert "--offline" in lib.command(tmp_path / "i", "p", "csv")

    def test_parallelism_is_disabled_by_default(self, lib, tmp_path) -> None:
        """Volatility's own fan-out would multiply against --jobs."""
        argv = lib.command(tmp_path / "i", "p", "csv")
        assert argv[argv.index("--parallelism") + 1] == "off"

    def test_symbols_directory_is_passed(self, lib, tmp_path) -> None:
        argv = lib.command(tmp_path / "i", "p", "csv", symbols_dir=tmp_path / "syms")
        assert argv[argv.index("-s") + 1] == str(tmp_path / "syms")

    def test_cache_path_is_passed(self, lib, tmp_path) -> None:
        """A dedicated flag, so the analyst's roaming profile is untouched."""
        argv = lib.command(tmp_path / "i", "p", "csv", cache_dir=tmp_path / "cache")
        assert argv[argv.index("--cache-path") + 1] == str(tmp_path / "cache")

    def test_json_renderer(self, lib, tmp_path) -> None:
        argv = lib.command(tmp_path / "i", "p", "json")
        assert argv[argv.index("-r") + 1] == "json"

    def test_rejects_an_unknown_renderer(self, lib, tmp_path) -> None:
        with pytest.raises(ValueError):
            lib.command(tmp_path / "i", "p", "xml")

    def test_offline_can_be_disabled(self, lib, tmp_path) -> None:
        assert "--offline" not in lib.command(tmp_path / "i", "p", "csv", offline=False)


class TestLibraryEngine:
    def test_goes_through_our_shim(self, lib, tmp_path) -> None:
        """volatility3.cli has no __main__, so -m volatility3.cli cannot work."""
        argv = lib.command(tmp_path / "i", "p", "csv")
        assert argv[1:3] == ["-m", "app.volrunner"]

    def test_uses_the_given_interpreter(self, lib, tmp_path) -> None:
        assert lib.command(tmp_path / "i", "p", "csv")[0] == str(tmp_path / "python.exe")


class TestBinaryEngine:
    def test_invokes_the_executable_directly(self, tmp_path) -> None:
        exe = tmp_path / "volatility3.exe"
        exe.write_bytes(b"MZ")
        argv = engine_mod.BinaryEngine(exe).command(tmp_path / "i", "p", "csv")

        assert argv[0] == str(exe)
        assert "-m" not in argv

    def test_unavailable_when_absent(self, tmp_path) -> None:
        assert not engine_mod.BinaryEngine(tmp_path / "nope.exe").available()


class TestSelection:
    def test_explicit_exe_requires_the_binary(self, tmp_path) -> None:
        with pytest.raises(engine_mod.EngineUnavailable):
            engine_mod.select("exe", tmp_path)

    def test_finds_a_bundled_binary(self, tmp_path) -> None:
        (tmp_path / "volatility3.exe").write_bytes(b"MZ")
        assert engine_mod.select("exe", tmp_path).name == "exe"

    def test_auto_prefers_the_library(self, tmp_path) -> None:
        """The exe re-extracts to %TEMP% per invocation; the library does not."""
        pytest.importorskip("volatility3")
        (tmp_path / "volatility3.exe").write_bytes(b"MZ")
        assert engine_mod.select("auto", tmp_path).name == "library"

    def test_rejects_an_unknown_preference(self, tmp_path) -> None:
        with pytest.raises(ValueError):
            engine_mod.select("magic", tmp_path)

    def test_find_binary_returns_none_when_absent(self, tmp_path) -> None:
        assert engine_mod.find_binary(tmp_path) is None


class TestSwapLayers:
    """Windows pages memory out; --single-swap-locations reads it back.

    The option takes nargs='*', so its position is load-bearing: placed
    immediately before the plugin name, argparse consumes the plugin as a swap
    path and Volatility runs with no plugin at all.
    """

    def test_swap_paths_are_passed(self, lib, tmp_path) -> None:
        argv = lib.command(
            tmp_path / "i", "p", "csv", swap_files=[tmp_path / "pagefile.sys"]
        )
        assert "--single-swap-locations" in argv
        assert str(tmp_path / "pagefile.sys") in argv

    def test_several_swap_files_are_supported(self, lib, tmp_path) -> None:
        argv = lib.command(
            tmp_path / "i", "p", "csv",
            swap_files=[tmp_path / "pagefile.sys", tmp_path / "swapfile.sys"],
        )
        start = argv.index("--single-swap-locations")
        assert argv[start + 1 : start + 3] == [
            str(tmp_path / "pagefile.sys"), str(tmp_path / "swapfile.sys")
        ]

    def test_the_plugin_is_never_adjacent_to_the_swap_list(self, lib, tmp_path) -> None:
        """The regression this ordering exists to prevent."""
        argv = lib.command(
            tmp_path / "i", "windows.pslist.PsList", "csv",
            swap_files=[tmp_path / "pagefile.sys"],
        )
        assert argv[-1] == "windows.pslist.PsList"
        swap_index = argv.index("--single-swap-locations")
        assert swap_index < len(argv) - 2
        # An option must terminate the nargs='*' list before the plugin.
        following = argv[swap_index + 1 :]
        assert any(token.startswith("-") for token in following)

    def test_absent_when_no_pagefile_given(self, lib, tmp_path) -> None:
        assert "--single-swap-locations" not in lib.command(tmp_path / "i", "p", "csv")

    def test_the_binary_engine_supports_it_too(self, tmp_path) -> None:
        exe = tmp_path / "volatility3.exe"
        exe.write_bytes(b"MZ")
        argv = engine_mod.BinaryEngine(exe).command(
            tmp_path / "i", "p", "csv", swap_files=[tmp_path / "pagefile.sys"]
        )
        assert "--single-swap-locations" in argv
