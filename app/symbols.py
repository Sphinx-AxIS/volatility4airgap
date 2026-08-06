"""Kernel symbol identification for air-gapped Volatility3 runs.

Scans a memory image for the kernel's CodeView RSDS record, then derives the two
strings the analyst needs:

    download URL   http://msdl.microsoft.com/download/symbols/{pdb}/{GUID}{age}/{pdb}
    required ISF   windows/{pdb}/{GUID}-{age}.json.xz

These differ in a way that is easy to get wrong. The URL path segment is the GUID
*concatenated* with the age and no separator; the ISF filename joins them with a
hyphen. Treating the 33-character URL segment as if it were the GUID yields an ISF
name that can never match, for any image, at any age.

Both strings are therefore derived here from a single ``KernelPdb``. Nothing else in
the codebase should build either one by hand.

Mirrors volatility3's own construction:
  - ``framework/symbols/windows/pdbconv.py``  PdbRetreiver.retreive_pdb
  - ``framework/symbols/windows/pdbutil.py``  PDBUtility.load_windows_symbol_table
"""

from __future__ import annotations

import hashlib
import re
import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

# volatility3.framework.constants.SYMBOL_SERVER_URL
SYMBOL_SERVER_URL = "http://msdl.microsoft.com/download/symbols"

RSDS_MAGIC = b"RSDS"

#: Kernel images vary by architecture and build; volatility scans for this set.
KERNEL_PDB_NAMES: tuple[bytes, ...] = (
    b"ntkrnlmp.pdb",
    b"ntkrnlpa.pdb",
    b"ntkrpamp.pdb",
    b"ntoskrnl.pdb",
)

# CV_INFO_PDB70: 'RSDS' (4) + GUID (16) + Age (4) + NUL-terminated name.
_GUID_AGE = struct.Struct("<16sI")
_HEADER_LEN = 4 + _GUID_AGE.size
_MAX_NAME = 256
_MAX_RECORD = _HEADER_LEN + _MAX_NAME

# A Windows GUID is stored mixed-endian: Data1 (4 bytes LE), Data2 (2 LE),
# Data3 (2 LE), then Data4 (8 bytes as-is). Rendering it as the flat 32-hex
# string Microsoft's symbol server expects means reading the raw bytes in this
# order. Defined once; `decode_guid` and `encode_guid` are inverses over it.
_GUID_BYTE_ORDER = (3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15)

_GUID_RE = re.compile(r"\A[0-9A-F]{32}\Z")
_NAME_RE = re.compile(r"\A[A-Za-z0-9_.\-+]{1,255}\Z")


def decode_guid(raw: bytes) -> str:
    """Render 16 raw mixed-endian GUID bytes as 32 uppercase hex characters."""
    if len(raw) != 16:
        raise ValueError(f"GUID must be 16 bytes, got {len(raw)}")
    return "".join(f"{raw[i]:02X}" for i in _GUID_BYTE_ORDER)


def encode_guid(guid: str) -> bytes:
    """Inverse of :func:`decode_guid`: 32 hex characters back to 16 raw bytes."""
    guid = guid.strip().upper()
    if not _GUID_RE.match(guid):
        raise ValueError(f"GUID must be 32 hex characters, got {guid!r}")
    raw = bytearray(16)
    for position, source in enumerate(_GUID_BYTE_ORDER):
        raw[source] = int(guid[position * 2 : position * 2 + 2], 16)
    return bytes(raw)


@dataclass(frozen=True)
class KernelPdb:
    """A kernel PDB identity, and the only source of the URL and ISF path."""

    pdb_name: str
    guid: str
    age: int
    offset: int | None = None

    def __post_init__(self) -> None:
        if not _GUID_RE.match(self.guid):
            raise ValueError(f"GUID must be 32 uppercase hex characters, got {self.guid!r}")
        if self.age < 0:
            raise ValueError(f"age must not be negative, got {self.age}")
        if not _NAME_RE.match(self.pdb_name):
            raise ValueError(f"implausible PDB name: {self.pdb_name!r}")

    @property
    def guid_age(self) -> str:
        """The symbol-server path segment: GUID and age concatenated.

        This is *not* the GUID. It is one character longer for a single-digit age,
        and longer still beyond that.
        """
        return f"{self.guid}{self.age}"

    @property
    def download_filename(self) -> str:
        """PDB filename, extension normalised to ``.pdb`` as volatility does."""
        return ".".join(self.pdb_name.split(".")[:-1] + ["pdb"])

    @property
    def compressed_filename(self) -> str:
        """The cabinet-compressed variant, e.g. ``ntkrnlmp.pd_``."""
        return self.download_filename[:-1] + "_"

    @property
    def download_url(self) -> str:
        name = self.download_filename
        return f"{SYMBOL_SERVER_URL}/{name}/{self.guid_age}/{name}"

    @property
    def compressed_url(self) -> str:
        name = self.download_filename
        return f"{SYMBOL_SERVER_URL}/{name}/{self.guid_age}/{self.compressed_filename}"

    @property
    def isf_relative_path(self) -> str:
        """Path below the symbols directory, POSIX-separated.

        Note the hyphen. ``guid_age`` must never appear here.
        """
        return f"windows/{self.pdb_name}/{self.guid}-{self.age}.json.xz"

    @property
    def cache_identifier(self) -> bytes:
        """The key Volatility's symbol cache looks this kernel up by.

        ``load_windows_symbol_table`` consults the SQLite cache *before* falling
        back to a path glob, and builds this key from the scanned pdb name. The
        cache indexes an ISF under whatever ``metadata.windows.pdb.database``
        says, so a converted ISF must carry the real pdb name there.

        ``PdbReader`` defaults that field to ``unknown.pdb``, which produces a key
        that never matches. Anything converting a PDB must therefore pass
        ``database_name=self.pdb_name``. Without it the fast path misses and
        Volatility waits on a doomed download attempt before finding the file by
        path — on an air-gapped host, a network timeout on every run.
        """
        return f"{self.pdb_name}|{self.guid.upper()}|{self.age}".encode("latin-1")

    def isf_path(self, symbols_dir: Path | str) -> Path:
        return Path(symbols_dir).joinpath(*self.isf_relative_path.split("/"))

    def as_dict(self) -> dict:
        return {
            "pdb_name": self.pdb_name,
            "guid": self.guid,
            "age": self.age,
            "guid_age": self.guid_age,
        }


def parse_symbol_server_url(url: str) -> KernelPdb:
    """Recover a :class:`KernelPdb` from a Microsoft symbol-server URL.

    Splits the ``{GUID}{age}`` segment correctly: the first 32 characters are the
    GUID and the remainder is the age. Naively treating the whole segment as the
    GUID is the defect this function exists to make impossible.
    """
    parts = [p for p in url.strip().split("/") if p]
    if len(parts) < 3:
        raise ValueError(f"not a symbol-server URL: {url!r}")

    pdb_name, guid_age = parts[-3], parts[-2]
    if len(guid_age) <= 32:
        raise ValueError(
            f"expected a GUID+age segment longer than 32 characters, got {guid_age!r}"
        )

    guid, age_text = guid_age[:32].upper(), guid_age[32:]
    if not age_text.isdigit():
        raise ValueError(f"could not read an age from {guid_age!r}")

    return KernelPdb(pdb_name=pdb_name, guid=guid, age=int(age_text))


def parse_rsds(buf: bytes, pos: int, *, allow_truncated: bool = False) -> KernelPdb | None:
    """Parse one RSDS record at ``pos``, or return ``None`` if it is not valid.

    Returns ``None`` rather than raising when the record is malformed or extends
    past the end of ``buf``, because callers scan raw memory where most ``RSDS``
    byte sequences are coincidental.
    """
    if buf[pos : pos + 4] != RSDS_MAGIC:
        return None

    header = buf[pos + 4 : pos + _HEADER_LEN]
    if len(header) < _GUID_AGE.size:
        return None

    raw_guid, age = _GUID_AGE.unpack(header)

    name_start = pos + _HEADER_LEN
    end = buf.find(b"\x00", name_start, name_start + _MAX_NAME)
    if end == -1:
        # No terminator in range. If more data may follow, the caller should retry
        # once the record is fully buffered.
        if not allow_truncated and name_start + _MAX_NAME > len(buf):
            return None
        return None

    try:
        name = buf[name_start:end].decode("ascii")
    except UnicodeDecodeError:
        return None

    try:
        return KernelPdb(pdb_name=name, guid=decode_guid(raw_guid), age=age, offset=pos)
    except ValueError:
        return None


def iter_rsds(
    stream: BinaryIO,
    *,
    pdb_names: Iterable[bytes] | None = KERNEL_PDB_NAMES,
    chunk_size: int = 8 << 20,
    digest: "hashlib._Hash | None" = None,
) -> Iterator[KernelPdb]:
    """Scan a stream for RSDS records, yielding each distinct match once.

    Reads in overlapping windows so a record straddling a chunk boundary is still
    found. ``pdb_names`` filters to the kernel by default; pass ``None`` to accept
    every PDB in the image.

    ``digest`` is updated with each byte read, so a chain-of-custody hash costs no
    extra I/O over an image that may be tens of gigabytes. Only freshly read bytes
    are fed to it — never the carried overlap, which would be counted twice.

    Because this is a generator, ``digest`` is complete only once the caller has
    exhausted it. Prefer :func:`scan_image`, which cannot be left half-consumed.
    """
    wanted = None if pdb_names is None else {n.lower() for n in pdb_names}
    overlap = 0x4000  # comfortably larger than _MAX_RECORD
    if chunk_size <= overlap:
        raise ValueError("chunk_size must exceed the overlap window")

    carry = b""
    carry_base = 0
    consumed = 0
    resume_at = 0
    seen: set[tuple[str, str, int]] = set()

    while True:
        chunk = stream.read(chunk_size)
        at_eof = not chunk
        # Hash the fresh bytes only. `buf` below repeats the carried overlap.
        if digest is not None and chunk:
            digest.update(chunk)
        buf = carry + chunk
        base = carry_base
        search = 0

        while True:
            hit = buf.find(RSDS_MAGIC, search)
            if hit == -1:
                break
            search = hit + 1
            absolute = base + hit

            if absolute < resume_at:
                continue
            # Defer a record that may continue into the next window.
            if not at_eof and hit + _MAX_RECORD > len(buf):
                break

            record = parse_rsds(buf, hit, allow_truncated=at_eof)
            if record is None:
                continue
            if wanted is not None and record.pdb_name.lower().encode() not in wanted:
                continue

            key = (record.pdb_name, record.guid, record.age)
            resume_at = absolute + 1
            if key in seen:
                continue
            seen.add(key)
            # Report the offset within the image, not within the window.
            yield KernelPdb(record.pdb_name, record.guid, record.age, absolute)

        if at_eof:
            break

        consumed += len(chunk)
        keep = min(overlap, len(buf))
        carry = buf[len(buf) - keep :]
        carry_base = consumed - keep


@dataclass(frozen=True)
class ScanResult:
    """What one pass over a memory image produced."""

    kernels: list[KernelPdb]
    bytes_read: int
    sha256: str | None = None

    @property
    def is_ambiguous(self) -> bool:
        """True when the image holds more than one kernel build."""
        return len(self.kernels) > 1


def scan_image(
    path: Path | str,
    *,
    pdb_names: Iterable[bytes] | None = KERNEL_PDB_NAMES,
    chunk_size: int = 8 << 20,
    hash_image: bool = True,
) -> ScanResult:
    """Scan a memory image once, returning every kernel found and its digest.

    Ordinarily finds exactly one kernel. More than one usually means the image
    holds several builds — a hibernation remnant, or a capture spanning a reboot.
    The caller should surface that rather than guessing; symbols are small enough
    that fetching all of them beats a second trip to the networked machine.

    The scan already reads every byte, so ``hash_image`` computes the
    chain-of-custody SHA-256 in the same pass. Hashing separately would mean a
    second full read of an image that may be tens of gigabytes.
    """
    digest = hashlib.sha256() if hash_image else None

    with open(path, "rb") as handle:
        kernels = list(
            iter_rsds(handle, pdb_names=pdb_names, chunk_size=chunk_size, digest=digest)
        )
        bytes_read = handle.tell()

    return ScanResult(
        kernels=kernels,
        bytes_read=bytes_read,
        sha256=digest.hexdigest() if digest is not None else None,
    )
