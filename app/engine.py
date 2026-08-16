"""How a Volatility plugin gets invoked.

Two backends, selected by ``--engine``:

``library``  the bundled interpreter running volatility3 from ``lib/``
``exe``      the official volatility3.exe

The abstraction is thin on purpose — both amount to building an argv — but it is
what lets the accreditation question ("official binaries only?") be answered later
with a flag rather than a rewrite.

The design originally called for an ``engine/`` package of three files. A single
module is a truer fit for roughly a hundred lines, and keeps the two command
builders side by side where the differences are obvious.
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from pathlib import Path

RENDERERS = {"csv": "csv", "json": "json"}


class EngineUnavailable(RuntimeError):
    pass


class VolEngine(ABC):
    name: str

    @abstractmethod
    def base_command(self) -> list[str]:
        """The prefix that invokes Volatility."""

    @abstractmethod
    def available(self) -> bool:
        """Whether this backend can actually run here."""

    def command(
        self,
        image: Path,
        plugin: str,
        renderer: str,
        *,
        symbols_dir: Path | None = None,
        cache_dir: Path | None = None,
        offline: bool = True,
        parallelism: str | None = "off",
        swap_files: list[Path] | None = None,
        output_dir: Path | None = None,
        plugin_args: list[str] | None = None,
    ) -> list[str]:
        """Build the argv for one plugin invocation.

        Two of these arguments sit on opposite sides of the plugin name, and the
        split is not stylistic. ``-o`` is a *global* Volatility option, so it must
        precede the plugin. ``plugin_args`` belong to the plugin and must follow
        it. Swapping either produces an argparse error that names neither.
        """
        if renderer not in RENDERERS:
            raise ValueError(f"unknown renderer {renderer!r}")

        argv = list(self.base_command())

        # --single-swap-locations takes nargs='*', so anything following it is
        # consumed until the next option. It must never sit immediately before the
        # plugin name or the plugin is swallowed as a swap path. Emitting it first,
        # with -q straight after, bounds the list.
        if swap_files:
            argv += ["--single-swap-locations", *[str(p) for p in swap_files]]

        argv += ["-q", "-f", str(image), "-r", RENDERERS[renderer]]

        if symbols_dir is not None:
            argv += ["-s", str(symbols_dir)]
        if cache_dir is not None:
            # A dedicated flag, so the analyst's roaming profile stays untouched
            # and every worker shares one warmed cache.
            argv += ["--cache-path", str(cache_dir)]
        if offline:
            # Without this, a missing symbol sends Volatility to the internet and
            # an air-gapped host waits out the timeout on every plugin.
            argv.append("--offline")
        if parallelism:
            # Volatility can fan out internally. Combined with --jobs that would
            # oversubscribe by a factor of the core count.
            argv += ["--parallelism", parallelism]
        if output_dir is not None:
            # Where --dump writes. Without it, dumped executables land in the
            # working directory of whichever process the scheduler happened to
            # start, which is not a place evidence should go.
            argv += ["-o", str(output_dir)]

        argv.append(plugin)

        # Plugin arguments come last, and nothing may follow them. ``--pid`` is a
        # ListRequirement, so argparse gives it nargs='+' and it consumes every
        # following token — the same hazard --single-swap-locations has above,
        # avoided here by there being no later argument to swallow.
        if plugin_args:
            argv += [str(arg) for arg in plugin_args]

        return argv


class LibraryEngine(VolEngine):
    """Runs volatility3 as a library, via the bundled interpreter."""

    name = "library"

    def __init__(self, python: Path | None = None) -> None:
        self.python = Path(python) if python else Path(sys.executable)

    def base_command(self) -> list[str]:
        # volatility3.cli has no __main__, so we go through our own shim.
        return [str(self.python), "-m", "app.volrunner"]

    def available(self) -> bool:
        try:
            import volatility3  # noqa: F401
        except ImportError:
            return False
        return self.python.exists()


class BinaryEngine(VolEngine):
    """Runs the official volatility3.exe."""

    name = "exe"

    def __init__(self, executable: Path) -> None:
        self.executable = Path(executable)

    def base_command(self) -> list[str]:
        return [str(self.executable)]

    def available(self) -> bool:
        return self.executable.is_file()


def find_binary(bundle_root: Path) -> Path | None:
    for candidate in ("volatility3.exe", "vol.exe", "volatility3"):
        path = bundle_root / candidate
        if path.is_file():
            return path
    return None


def select(preference: str, bundle_root: Path, *, python: Path | None = None) -> VolEngine:
    """Choose a backend.

    ``auto`` prefers the library engine: it starts in milliseconds, whereas the
    one-file exe re-extracts tens of megabytes to %TEMP% on every invocation —
    paid once per plugin, per renderer.
    """
    library = LibraryEngine(python)
    binary_path = find_binary(bundle_root)
    binary = BinaryEngine(binary_path) if binary_path else None

    if preference == "library":
        if not library.available():
            raise EngineUnavailable(
                "the library engine needs volatility3 importable from lib/"
            )
        return library

    if preference == "exe":
        if binary is None or not binary.available():
            raise EngineUnavailable(f"no volatility3.exe found beside {bundle_root}")
        return binary

    if preference != "auto":
        raise ValueError(f"unknown engine {preference!r}")

    if library.available():
        return library
    if binary is not None and binary.available():
        return binary
    raise EngineUnavailable(
        "neither volatility3 in lib/ nor volatility3.exe is available"
    )
