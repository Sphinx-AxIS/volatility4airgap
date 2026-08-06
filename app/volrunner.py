"""Entry shim for running Volatility as a subprocess of the bundled interpreter.

``volatility3.cli`` is a package with no ``__main__``, so ``python -m
volatility3.cli`` fails. This module gives us a stable ``-m`` target that does not
depend on a console script being installed — which matters because the bundle
deliberately strips the Unix ``vol``/``volshell`` shims wheels try to install.
"""

from __future__ import annotations


def main() -> None:
    from volatility3.cli import main as vol_main

    vol_main()


if __name__ == "__main__":
    main()
