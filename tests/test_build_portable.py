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
            assert {i.date_time for i in zf.infolist()} == {bp.ARCHIVE_TIMESTAMP}


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


class TestRecordedWheels:
    """The manifest must describe the bundle, not the build host's scratch space.

    The wheel cache is shared between builds and never pruned. When a dependency
    publishes a new release, the old wheel stays behind, pip installs only the
    new one, and a manifest built from the cache listing claims a version that is
    not in the bundle. A real build recorded leechcorepyc twice this way.
    """

    def _lib_with(self, root: Path, dists: dict[str, str]) -> Path:
        lib = root / "lib"
        for name, version in dists.items():
            (lib / f"{name}-{version}.dist-info").mkdir(parents=True)
        return lib

    def test_reads_what_pip_installed(self, tmp_path) -> None:
        lib = self._lib_with(tmp_path, {"volatility3": "2.28.0", "pefile": "2024.8.26"})

        assert bp.installed_distributions(lib) == {
            ("volatility3", "2.28.0"), ("pefile", "2024.8.26"),
        }

    def test_underscores_and_dashes_compare_equal(self, tmp_path) -> None:
        """dist-info says yara_python; the wheel filename may differ in
        separator. PEP 503 normalisation is what makes them match."""
        assert bp._project_key("yara_python") == bp._project_key("yara-python")
        assert bp._project_key("Pillow") == bp._project_key("pillow")

    def test_an_empty_lib_reports_nothing(self, tmp_path) -> None:
        (tmp_path / "lib").mkdir()
        assert bp.installed_distributions(tmp_path / "lib") == set()


class TestPinnedConstants:
    def test_python_pin_is_a_full_sha256(self) -> None:
        assert len(bp.PYTHON_SHA256) == 64
        assert all(c in "0123456789abcdef" for c in bp.PYTHON_SHA256)

    def test_pth_exposes_lib_and_the_bundle_root(self) -> None:
        """The embeddable distribution ignores PYTHONPATH, so ._pth is the only route."""
        lines = [ln.strip() for ln in bp.PTH_CONTENTS.splitlines()]

        assert bp.PTH_CONTENTS.startswith(f"python{bp.PYTHON_TAG}.zip")
        assert "..\\lib" in lines, "lib/ must be on the path so `import volatility3` works"
        assert ".." in lines, "the bundle root must be on the path so `-m app` works"

    def test_pth_does_not_list_the_app_package_directory(self) -> None:
        """Regression: listing ..\\app broke `-m app` with 'No module named app'.

        `-m` imports app as a package, so its parent must be on sys.path. Pointing at
        the package directory itself exposes the modules inside while leaving the
        package unimportable, and breaks app/'s relative imports too.
        """
        assert "..\\app" not in [ln.strip() for ln in bp.PTH_CONTENTS.splitlines()]

    def test_target_is_windows_x64(self) -> None:
        assert bp.TARGET_PLATFORM == "win_amd64"

    def test_launcher_uses_the_bundled_interpreter(self) -> None:
        assert "%~dp0python\\python.exe" in bp.LAUNCHER_BAT
        assert "-m app" in bp.LAUNCHER_BAT


class TestDashMSemantics:
    """Why the ._pth must name the bundle root rather than the package directory.

    Asserting on the ._pth string alone would only encode the conclusion. These run
    the interpreter to demonstrate the rule itself, and are platform-independent
    because `-m` behaves the same everywhere.
    """

    @staticmethod
    def _package(tmp_path):
        root = tmp_path / "bundle"
        pkg = root / "app"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("VALUE = 'from package'\n")
        (pkg / "__main__.py").write_text("from . import VALUE\nprint(VALUE)\n")
        return root, pkg

    @staticmethod
    def _run(path_entry, cwd):
        import os
        import subprocess
        import sys

        env = dict(os.environ)
        env["PYTHONPATH"] = str(path_entry)
        return subprocess.run(
            [sys.executable, "-m", "app"],
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
        )

    def test_parent_directory_on_path_works(self, tmp_path) -> None:
        root, _ = self._package(tmp_path)
        neutral = tmp_path / "elsewhere"
        neutral.mkdir()

        result = self._run(root, neutral)

        assert result.returncode == 0, result.stderr
        assert "from package" in result.stdout

    def test_package_directory_on_path_fails(self, tmp_path) -> None:
        """Exactly the failure seen on the first Windows smoke test."""
        _, pkg = self._package(tmp_path)
        neutral = tmp_path / "elsewhere"
        neutral.mkdir()

        result = self._run(pkg, neutral)

        assert result.returncode != 0
        assert "No module named app" in result.stderr


class TestHowtoShips:
    """The reference must travel with the bundle.

    An analyst on an air-gapped workstation cannot open the repository to read it,
    so a HOWTO that only exists in docs/ is a HOWTO they do not have.
    """

    def test_the_howto_exists_in_the_repo(self) -> None:
        assert (REPO_ROOT / "docs" / "HOWTO.md").is_file()

    def test_it_documents_every_command(self) -> None:
        import sys

        sys.path.insert(0, str(REPO_ROOT))
        from app.__main__ import _COMMANDS

        text = (REPO_ROOT / "docs" / "HOWTO.md").read_text(encoding="utf-8")
        missing = [c for c in _COMMANDS if c not in text]
        assert not missing, f"HOWTO does not mention: {missing}"

    def test_it_documents_every_triage_option(self) -> None:
        import sys

        sys.path.insert(0, str(REPO_ROOT))
        from app.__main__ import build_parser

        parser = build_parser()
        triage = [
            a for a in parser._actions if getattr(a, "dest", None) == "command"
        ][0].choices["triage"]

        flags = {
            option
            for action in triage._actions
            for option in action.option_strings
            if option.startswith("--") and option != "--help"
        }
        text = (REPO_ROOT / "docs" / "HOWTO.md").read_text(encoding="utf-8")
        missing = sorted(f for f in flags if f not in text)
        assert not missing, f"HOWTO does not document triage options: {missing}"

    def test_it_documents_every_plugin_category(self) -> None:
        import sys

        sys.path.insert(0, str(REPO_ROOT))
        from app.plugins import CATEGORIES

        text = (REPO_ROOT / "docs" / "HOWTO.md").read_text(encoding="utf-8")
        missing = [c for c in CATEGORIES if c not in text]
        assert not missing, f"HOWTO does not mention categories: {missing}"


class TestEmptyDirectoriesSurvive:
    """Regression: cache/ and output/ vanished on extraction.

    A zip stores no directories unless they are written explicitly, so empty ones
    disappeared and Volatility could not create its symbol cache on the target.
    """

    def test_empty_directories_are_archived(self, tmp_path) -> None:
        root = make_tree(tmp_path / "Bundle", BASE)
        (root / "cache").mkdir()
        (root / "output").mkdir()

        archive = tmp_path / "out.zip"
        bp.write_deterministic_zip(root, archive)

        with zipfile.ZipFile(archive) as zf:
            names = zf.namelist()

        assert "Bundle/cache/" in names
        assert "Bundle/output/" in names

    def test_they_survive_a_round_trip(self, tmp_path) -> None:
        root = make_tree(tmp_path / "Bundle", BASE)
        (root / "cache").mkdir()

        archive = tmp_path / "out.zip"
        bp.write_deterministic_zip(root, archive)

        extracted = tmp_path / "extracted"
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(extracted)

        assert (extracted / "Bundle" / "cache").is_dir()

    def test_archiving_stays_deterministic_with_directories(self, tmp_path) -> None:
        root = make_tree(tmp_path / "Bundle", BASE)
        (root / "cache").mkdir()
        (root / "output").mkdir()

        first, second = tmp_path / "a.zip", tmp_path / "b.zip"
        bp.write_deterministic_zip(root, first)
        bp.write_deterministic_zip(root, second)

        assert first.read_bytes() == second.read_bytes()

    def test_a_directory_precedes_its_contents(self, tmp_path) -> None:
        """Extractors expect the parent entry first."""
        root = make_tree(tmp_path / "Bundle", BASE)
        archive = tmp_path / "out.zip"
        bp.write_deterministic_zip(root, archive)

        with zipfile.ZipFile(archive) as zf:
            names = zf.namelist()

        assert names.index("Bundle/app/") < names.index("Bundle/app/__main__.py")


class TestLauncherLineEndings:
    """cmd.exe expects CRLF.

    The launcher is generated on macOS, so Unix endings are the default and must be
    forced. An LF-only .bat parses unreliably and fails in ways that point nowhere
    near the cause.
    """

    def test_every_line_ends_crlf(self) -> None:
        data = bp.LAUNCHER_BAT.encode("ascii")
        assert b"\r\n" in data
        # No bare LF: every \n must be preceded by \r.
        assert data.replace(b"\r\n", b"") .count(b"\n") == 0, "bare LF in launcher"

    def test_it_is_ascii_with_no_bom(self) -> None:
        """A BOM would be echoed by cmd as a stray character on the first line."""
        data = bp.LAUNCHER_BAT.encode("ascii")
        assert not data.startswith(b"\xef\xbb\xbf")
        assert data.startswith(b"@echo off\r\n")

    def test_it_still_invokes_the_bundled_interpreter(self) -> None:
        assert "%~dp0python\\python.exe" in bp.LAUNCHER_BAT
        assert "-m app %*" in bp.LAUNCHER_BAT

    def test_it_guards_a_missing_interpreter(self) -> None:
        """A truncated extract should say so, not fail obscurely."""
        assert "if not exist" in bp.LAUNCHER_BAT
        assert "Re-extract" in bp.LAUNCHER_BAT

    def test_the_written_file_keeps_crlf(self, tmp_path) -> None:
        """write_text would translate newlines per platform; write_bytes must not."""
        target = tmp_path / "v4ag.bat"
        target.write_bytes(bp.LAUNCHER_BAT.encode("ascii"))

        raw = target.read_bytes()
        assert b"\r\n" in raw
        assert raw.replace(b"\r\n", b"").count(b"\n") == 0


class TestAtomicArchive:
    """A partially written archive is worse than a failed one.

    Copying it mid-build yields entry offsets that no longer match the data, so
    extraction succeeds while placing one file's contents under another's name.
    """

    def test_no_part_file_is_left_behind(self, tmp_path) -> None:
        root = make_tree(tmp_path / "Bundle", BASE)
        archive = tmp_path / "out.zip"
        bp.write_deterministic_zip(root, archive)

        assert archive.is_file()
        assert not archive.with_name(archive.name + ".part").exists()

    def test_an_existing_archive_is_replaced_wholesale(self, tmp_path) -> None:
        root = make_tree(tmp_path / "Bundle", BASE)
        archive = tmp_path / "out.zip"
        archive.write_bytes(b"stale content that must not survive")

        bp.write_deterministic_zip(root, archive)

        assert zipfile.is_zipfile(archive)
        with zipfile.ZipFile(archive) as zf:
            assert zf.testzip() is None

    def test_the_archive_is_only_visible_once_complete(self, tmp_path, monkeypatch) -> None:
        """Mid-write, the final name must not yet exist."""
        root = make_tree(tmp_path / "Bundle", BASE)
        archive = tmp_path / "out.zip"
        seen = {}

        real_copyfileobj = bp.shutil.copyfileobj

        def spy(src, dst, length=None):
            seen.setdefault("existed_during_write", archive.exists())
            return real_copyfileobj(src, dst, length) if length else real_copyfileobj(src, dst)

        monkeypatch.setattr(bp.shutil, "copyfileobj", spy)
        bp.write_deterministic_zip(root, archive)

        assert seen["existed_during_write"] is False
        assert archive.is_file()


class TestWindowsExtractorCompatibility:
    """The bundle is extracted on Windows, often by Explorer.

    Explorer's zip handling is the least robust of the common extractors, so the
    archive should present the metadata its usual path expects rather than relying
    on everyone reaching for Expand-Archive.
    """

    def _archive(self, tmp_path):
        root = make_tree(tmp_path / "Bundle", BASE)
        (root / "cache").mkdir()
        archive = tmp_path / "out.zip"
        bp.write_deterministic_zip(root, archive)
        return archive

    def test_declares_a_windows_created_archive(self, tmp_path) -> None:
        """create_system 3 (Unix) makes extractors read Unix mode bits instead."""
        with zipfile.ZipFile(self._archive(tmp_path)) as zf:
            assert {i.create_system for i in zf.infolist()} == {0}

    def test_files_carry_the_dos_archive_attribute(self, tmp_path) -> None:
        with zipfile.ZipFile(self._archive(tmp_path)) as zf:
            info = zf.getinfo("Bundle/v4ag.bat")
        assert info.external_attr & 0xFF == bp.DOS_ARCHIVE

    def test_directories_carry_the_dos_directory_attribute(self, tmp_path) -> None:
        with zipfile.ZipFile(self._archive(tmp_path)) as zf:
            info = zf.getinfo("Bundle/cache/")
        assert info.external_attr & 0xFF == bp.DOS_DIRECTORY

    def test_avoids_the_dos_epoch_boundary(self, tmp_path) -> None:
        """1980-01-01 is the minimum DOS timestamp and a common edge case."""
        assert bp.ARCHIVE_TIMESTAMP[0] > 1980
        with zipfile.ZipFile(self._archive(tmp_path)) as zf:
            assert {i.date_time for i in zf.infolist()} == {bp.ARCHIVE_TIMESTAMP}

    def test_still_deterministic(self, tmp_path) -> None:
        root = make_tree(tmp_path / "Bundle", BASE)
        (root / "cache").mkdir()
        first, second = tmp_path / "a.zip", tmp_path / "b.zip"
        bp.write_deterministic_zip(root, first)
        bp.write_deterministic_zip(root, second)
        assert first.read_bytes() == second.read_bytes()
