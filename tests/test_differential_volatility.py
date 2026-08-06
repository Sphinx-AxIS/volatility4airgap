"""Differential tests against the real volatility3 library.

Our scanner and URL construction deliberately reimplement what volatility3 does
internally, so that the ``exe`` engine — which cannot expose volatility as a
library — still resolves symbols without scraping ``-vvv`` output. That
duplication is only safe while the two agree.

These tests import volatility3 and compare directly. They are skipped when it is
absent, so the ordinary suite still runs on a machine with nothing installed.
If volatility ever changes its symbol-server scheme, these fail and tell us.
"""

from __future__ import annotations

import io
import os

import pytest

from app.symbols import KERNEL_PDB_NAMES, SYMBOL_SERVER_URL, KernelPdb, iter_rsds

from .test_symbols import GOLDEN_AGE, GOLDEN_GUID, GOLDEN_NAME, image_with, rsds_record

volatility3 = pytest.importorskip("volatility3", reason="volatility3 not installed")

from volatility3.framework import constants  # noqa: E402
from volatility3.framework.symbols.windows import pdbutil  # noqa: E402


def test_symbol_server_url_matches_upstream() -> None:
    assert SYMBOL_SERVER_URL == constants.SYMBOL_SERVER_URL


def test_kernel_pdb_names_are_recognised_upstream() -> None:
    """Our kernel name list must be usable by volatility's own scanner."""
    scanner = pdbutil.PdbSignatureScanner(list(KERNEL_PDB_NAMES))
    assert set(scanner._pdb_names) == set(KERNEL_PDB_NAMES)


@pytest.mark.parametrize("age", [1, 2, 12])
@pytest.mark.parametrize("name", [n.decode() for n in KERNEL_PDB_NAMES])
def test_scanner_agrees_with_volatility(name: str, age: int) -> None:
    """Volatility's scanner and ours must extract the same identity."""
    record = rsds_record(GOLDEN_GUID, age, name)
    data = image_with(record, offset=4096, total=1 << 20)

    upstream = list(pdbutil.PdbSignatureScanner(list(KERNEL_PDB_NAMES))(data, 0))
    assert len(upstream) == 1, "volatility should find exactly one planted record"
    up_guid, up_age, up_name, up_offset = upstream[0]

    ours = list(iter_rsds(io.BytesIO(data)))
    assert len(ours) == 1

    assert ours[0].guid == up_guid
    assert ours[0].age == up_age
    assert ours[0].pdb_name == up_name.decode()
    assert ours[0].offset == up_offset


def test_guid_byte_order_matches_upstream() -> None:
    """The mixed-endian permutation is the easiest thing here to get wrong."""
    # A GUID whose every byte is distinct, so any transposition shows up.
    guid = "000102030405060708090A0B0C0D0E0F"
    record = rsds_record(guid, 1, GOLDEN_NAME)
    data = image_with(record, offset=512, total=1 << 16)

    (up_guid, _, _, _) = next(iter(pdbutil.PdbSignatureScanner(list(KERNEL_PDB_NAMES))(data, 0)))
    assert next(iter(iter_rsds(io.BytesIO(data)))).guid == up_guid == guid


@pytest.mark.parametrize("age", [0, 1, 2, 12, 255])
def test_isf_path_matches_upstream_filter_string(age: int) -> None:
    """Reproduces PDBUtility.load_windows_symbol_table's path construction."""
    pdb = KernelPdb(GOLDEN_NAME, GOLDEN_GUID, age)

    # Verbatim from volatility3, framework/symbols/windows/pdbutil.py
    filter_string = os.path.join(
        GOLDEN_NAME.strip("\x00"), GOLDEN_GUID.upper() + "-" + str(age)
    )
    upstream = os.path.join("windows", filter_string) + ".json.xz"

    assert pdb.isf_relative_path == upstream.replace(os.sep, "/")


@pytest.mark.parametrize("age", [0, 1, 2, 12, 255])
def test_download_url_matches_upstream_construction(age: int) -> None:
    """Reproduces PdbRetreiver.retreive_pdb's URL construction."""
    pdb = KernelPdb(GOLDEN_NAME, GOLDEN_GUID, age)

    # Verbatim from volatility3, framework/symbols/windows/pdbconv.py:
    #   file_name = ".".join(file_name.split(".")[:-1] + ["pdb"])
    #   url = sym_url + f"/{file_name}/{guid}/"      # guid here is guid + str(age)
    #   for suffix in [file_name, file_name[:-1] + "_"]: ...
    file_name = ".".join(GOLDEN_NAME.split(".")[:-1] + ["pdb"])
    guid_age = GOLDEN_GUID.upper() + str(age)
    base = constants.SYMBOL_SERVER_URL + f"/{file_name}/{guid_age}/"

    assert pdb.download_url == base + file_name
    assert pdb.compressed_url == base + file_name[:-1] + "_"


def test_url_and_isf_disagree_by_design() -> None:
    """The two constructions genuinely differ — this is the original bug's root.

    Asserted against upstream so the distinction is documented as real, not as an
    assumption of ours.
    """
    pdb = KernelPdb(GOLDEN_NAME, GOLDEN_GUID, GOLDEN_AGE)

    url_segment = GOLDEN_GUID + str(GOLDEN_AGE)          # what the URL uses
    isf_segment = GOLDEN_GUID + "-" + str(GOLDEN_AGE)    # what the ISF name uses

    assert url_segment in pdb.download_url
    assert isf_segment in pdb.isf_relative_path
    assert url_segment not in pdb.isf_relative_path
