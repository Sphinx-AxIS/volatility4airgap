"""Entry shim for running Volatility as a subprocess of the bundled interpreter.

``volatility3.cli`` is a package with no ``__main__``, so ``python -m
volatility3.cli`` fails. This module gives us a stable ``-m`` target that does not
depend on a console script being installed — which matters because the bundle
deliberately strips the Unix ``vol``/``volshell`` shims wheels try to install.
"""

from __future__ import annotations


def main() -> None:
    import sys

    # Volatility renders CSV straight to stdout, which the scheduler redirects to
    # a file. A redirected stream on Windows defaults to cp1252, and strings
    # carved out of memory routinely contain characters it cannot encode — one
    # Hangul syllable in a handle name kills the whole plugin. UTF-8 with
    # 'replace' keeps the row (with U+FFFD standing in) instead of the crash.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass

    from volatility3.cli import main as vol_main

    vol_main()


if __name__ == "__main__":
    main()
