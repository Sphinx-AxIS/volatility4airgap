"""Tests for the bundle build machinery.

The build script is not importable as a package, so it is loaded by path.
"""

from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module():
    path = REPO_ROOT / "tools" / "build_portable.py"
    spec = importlib.util.spec_from_file_location("build_portable", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bp = _load_module()


def make_tree(root: Path, files: dict[str, bytes]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return root


BASE = {
    "app/__main__.py": b"print('hi')",
    "lib/volatility3/__init__.py": b"# vol",
    "python/python.exe": b"MZ fake",
    "v4ag.bat": b"@echo off",
}


class TestPayloadDigest:
    def test_identical_trees_agree(self, tmp_path) -> None:
        a = make_tree(tmp_path / "a", BASE)
        b = make_tree(tmp_path / "b", BASE)
        assert bp.payload_digest(a) == bp.payload_digest(b)

    def test_ignores_the_manifest(self, tmp_path) -> None:
        """The manifest holds a build timestamp, so it must not feed the digest."""
        a = make_tree(tmp_path / "a", BASE)
        b = make_tree(tmp_path / "b", BASE)
        (a / bp.MANIFEST_NAME).write_text(json.dumps({"built_utc": "2026-01-01T00:00:00"}))
        (b / bp.MANIFEST_NAME).write_text(json.dumps({"built_utc": "2099-12-31T23:59:59"}))

        assert bp.payload_digest(a) == bp.payload_digest(b)

    def test_detects_changed_content(self, tmp_path) -> None:
        a = make_tree(tmp_path / "a", BASE)
        b = make_tree(tmp_path / "b", {**BASE, "v4ag.bat": b"@echo on"})
        assert bp.payload_digest(a) != bp.payload_digest(b)

    def test_detects_a_single_appended_byte(self, tmp_path) -> None:
        a = make_tree(tmp_path / "a", BASE)
        before = bp.payload_digest(a)
        with open(a / "lib/volatility3/__init__.py", "ab") as handle:
            handle.write(b"\x90")
        assert bp.payload_digest(a) != before

    def test_detects_a_renamed_file(self, tmp_path) -> None:
        """Content-only hashing would miss this; paths are part of the digest."""
        a = make_tree(tmp_path / "a", BASE)
        before = bp.payload_digest(a)
        (a / "v4ag.bat").rename(a / "run.bat")
        assert bp.payload_digest(a) != before

    def test_detects_an_added_file(self, tmp_path) -> None:
        a = make_tree(tmp_path / "a", BASE)
        before = bp.payload_digest(a)
        (a / "extra.dll").write_bytes(b"MZ")
        assert bp.payload_digest(a) != before

    def test_detects_a_removed_file(self, tmp_path) -> None:
        a = make_tree(tmp_path / "a", BASE)
        before = bp.payload_digest(a)
        (a / "v4ag.bat").unlink()
        assert bp.payload_digest(a) != before


class TestCheckBundle:
    def _bundle(self, tmp_path) -> Path:
        root = make_tree(tmp_path / "bundle", BASE)
        (root / bp.MANIFEST_NAME).write_text(
            json.dumps({"payload_sha256": bp.payload_digest(root)}), encoding="utf-8"
        )
        return root

    def test_accepts_an_intact_bundle(self, tmp_path, capsys) -> None:
        assert bp.check_bundle(self._bundle(tmp_path)) == 0
        assert "intact" in capsys.readouterr().out

    def test_rejects_a_tampered_bundle(self, tmp_path, capsys) -> None:
        root = self._bundle(tmp_path)
        (root / "v4ag.bat").write_bytes(b"@echo MALICIOUS")

        assert bp.check_bundle(root) == 1
        assert "MISMATCH" in capsys.readouterr().err

    def test_reports_a_missing_manifest(self, tmp_path, capsys) -> None:
        root = make_tree(tmp_path / "bundle", BASE)
        assert bp.check_bundle(root) == 2


class TestDeterministicZip:
    def test_identical_input_yields_identical_bytes(self, tmp_path) -> None:
        a = make_tree(tmp_path / "Bundle", BASE)
        first = tmp_path / "one.zip"
        second = tmp_path / "two.zip"

        bp.write_deterministic_zip(a, first)
        # Touch mtimes; a naive zip would embed these and drift.
        for path in a.rglob("*"):
            if path.is_file():
                import os

                os.utime(path, (0, 0))
        bp.write_deterministic_zip(a, second)

        assert first.read_bytes() == second.read_bytes()

    def test_entries_are_sorted_and_prefixed(self, tmp_path) -> None:
        a = make_tree(tmp_path / "Bundle", BASE)
        archive = tmp_path / "out.zip"
        bp.write_deterministic_zip(a, archive)

        with zipfile.ZipFile(archive) as zf:
            names = zf.namelist()

        assert names == sorted(names)
        assert all(n.startswith("Bundle/") for n in names)

    def test_timestamps_are_fixed(self, tmp_path) -> None:
        a = make_tree(tmp_path / "Bundle", BASE)
        archive = tmp_path / "out.zip"
        bp.write_deterministic_zip(a, archive)

        with zipfile.ZipFile(archive) as zf:
            assert {i.date_time for i in zf.infolist()} == {(1980, 1, 1, 0, 0, 0)}


class TestStripHostArtifacts:
    def test_removes_host_bytecode_and_unix_scripts(self, tmp_path) -> None:
        root = tmp_path / "lib"
        make_tree(
            root,
            {
                "volatility3/__init__.py": b"# vol",
                "volatility3/__pycache__/__init__.cpython-314.pyc": b"\x00",
                "__pycache__/thing.cpython-314.pyc": b"\x00",
                "bin/vol": b"#!/bin/sh",
                "keep.py": b"# keep",
            },
        )

        removed_pyc, removed_dirs = bp.strip_host_artifacts(root)

        assert removed_pyc == 2
        assert removed_dirs == 1
        assert not list(root.rglob("__pycache__"))
        assert not (root / "bin").exists()
        assert (root / "keep.py").is_file()
        assert (root / "volatility3" / "__init__.py").is_file()

    def test_is_a_no_op_on_a_clean_tree(self, tmp_path) -> None:
        root = make_tree(tmp_path / "lib", {"a.py": b"x"})
        assert bp.strip_host_artifacts(root) == (0, 0)


class TestDownloadVerification:
    def test_a_hash_mismatch_is_fatal(self, tmp_path) -> None:
        """Building around an unexpected interpreter is what pinning must prevent."""
        target = tmp_path / "cached.bin"
        target.write_bytes(b"not the real interpreter")

        # Points at a URL that will not be reached: the cached file fails its hash,
        # is deleted, and the refetch attempt must not silently succeed.
        with pytest.raises(Exception):
            bp.download(
                "http://127.0.0.1:1/unreachable",
                target,
                expected_sha256="00" * 32,
            )

    def test_a_matching_cached_file_is_reused(self, tmp_path) -> None:
        target = tmp_path / "cached.bin"
        target.write_bytes(b"payload")
        expected = bp.sha256_file(target)

        # No network access: a correct cache hit must short-circuit the download.
        assert bp.download("http://127.0.0.1:1/unreachable", target, expected_sha256=expected) == (
            expected
        )


class TestPinnedConstants:
    def test_python_pin_is_a_full_sha256(self) -> None:
        assert len(bp.PYTHON_SHA256) == 64
        assert all(c in "0123456789abcdef" for c in bp.PYTHON_SHA256)

    def test_pth_exposes_lib_and_app(self) -> None:
        """The embeddable distribution ignores PYTHONPATH, so ._pth is the only route."""
        assert "..\\lib" in bp.PTH_CONTENTS
        assert "..\\app" in bp.PTH_CONTENTS
        assert bp.PTH_CONTENTS.startswith(f"python{bp.PYTHON_TAG}.zip")

    def test_target_is_windows_x64(self) -> None:
        assert bp.TARGET_PLATFORM == "win_amd64"

    def test_launcher_uses_the_bundled_interpreter(self) -> None:
        assert "%~dp0python\\python.exe" in bp.LAUNCHER_BAT
        assert "-m app" in bp.LAUNCHER_BAT
