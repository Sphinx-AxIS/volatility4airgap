"""Strings from a memory image, and what ``windows.strings`` makes of them.

Two commands share this module.

``strings`` walks the image once and writes ``offset:string`` lines — the file
``windows.strings.Strings`` takes as ``--strings-file``. It exists because the
obvious tool for the job on a Windows host, Sysinternals ``strings.exe``, prints
its ``-o`` offset as a 32-bit number. On an image larger than 4 GiB the offsets
wrap, and a wrapped offset is not an error the plugin can see: it lands on a
real page in the low 4 GiB, owned by some real process, and the string is
attributed to the wrong one. Offsets here are the true file position whatever
the size, and the strings themselves are found the way ``strings`` has always
found them: runs of printable ASCII, and runs of printable UTF-16LE.

``strings-hits`` takes a strings file — this tool's or anyone else's — searches
it for the analyst's terms, checks every hit against the image (which is what
catches wrapped offsets, and puts them right), and runs the plugin on the
result. The plugin reads its whole input into memory and emits a row per line,
so it is fed the few hundred lines that matter rather than the whole file.

Both work in file offsets, which for a raw image are physical addresses — the
premise the plugin itself rests on.
"""

from __future__ import annotations

import codecs
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

PLUGIN = "windows.strings.Strings"

#: Where a 32-bit offset wraps.
WRAP = 1 << 32
DEFAULT_MIN_LENGTH = 4
CHUNK_SIZE = 64 << 20
#: A run longer than this that reaches a chunk's end is emitted there and then,
#: cut, rather than carried into the next chunk and rescanned. Nothing real is
#: a megabyte of contiguous printable text; a region that is gets split at the
#: boundary and both parts still come out.
MAX_CARRY = 1 << 20
#: How much of a string is compared with the image when locating it.
PROBE_LENGTH = 64
#: A backward jump this large between consecutive lines is a pass restarting.
DROP = 2 << 30

ENCODINGS = ("ascii", "unicode")

#: Every byte of a chunk is first classed as printable (1), NUL (0) or other (2).
#: The patterns then run over that mask rather than the data. It is not a
#: stylistic choice: ``re`` tries a character-class pattern afresh at every
#: byte, which caps it near 50 MB/s, whereas a pattern that *begins with a
#: literal* is searched with the engine's fast prefix scan — 3–9× quicker on
#: real memory and near memory bandwidth across the zero pages that make up
#: most of a large image. The mask makes the pattern literal.
PRINTABLE, NUL, OTHER = 1, 0, 2
_MASK_TABLE = bytes(
    PRINTABLE if (0x20 <= b <= 0x7E or b == 0x09) else NUL if b == 0 else OTHER
    for b in range(256)
)


def _mask(data: bytes) -> bytes:
    return data.translate(_MASK_TABLE)


class _Scanner:
    """One encoding's matcher, carrying a run that reaches a chunk's end into the next.

    A string that straddles two chunks must come out once, whole, at its true
    offset. So a run touching the end of a chunk is not emitted; its bytes are
    prepended to the next chunk and found again there, complete. For the wide
    encoding "touching" includes a lone character byte at the very end whose
    NUL is the next chunk's first byte.
    """

    def __init__(self, width: int, min_length: int) -> None:
        self.width = width
        self.min_length = min_length
        unit = b"\x01" if width == 1 else b"\x01\x00"
        # ``unit * (n-1)`` is a literal prefix the engine scans for quickly;
        # ``unit+`` then takes the rest of the run.
        self.pattern = re.compile(re.escape(unit * (min_length - 1)) + b"(?:" + re.escape(unit) + b")+")
        self.pending = b""
        self.pending_mask = b""
        self.pending_at = 0
        #: Set when a run past MAX_CARRY was emitted cut. What follows is the
        #: rest of that string and comes out even if shorter than min_length.
        self.continuing = False
        self.count = 0

    def _text(self, data: bytes, start: int, end: int) -> bytes:
        return data[start:end] if self.width == 1 else data[start:end:2]

    def _leading_run(self, mask: bytes) -> int:
        """Bytes of printable run at the start, counted no further than a match's worth."""
        n = len(mask)
        i = 0
        if self.width == 1:
            stop = min(self.min_length, n)
            while i < stop and mask[i] == PRINTABLE:
                i += 1
            return i
        pairs = 0
        while (
            pairs < self.min_length
            and i + 1 < n
            and mask[i] == PRINTABLE
            and mask[i + 1] == NUL
        ):
            i += 2
            pairs += 1
        return i

    def _reaches_end(self, mask: bytes, end: int) -> bool:
        n = len(mask)
        if end == n:
            return True
        return self.width == 2 and end == n - 1 and mask[n - 1] == PRINTABLE

    def _tail_start(self, mask: bytes) -> int:
        """Where the trailing partial run starts, when no match reached the end.

        Fewer than ``min_length`` characters can trail — more would have been a
        match — so the walk back is bounded and cheap.
        """
        n = len(mask)
        i = n
        if self.width == 1:
            stop = max(n - (self.min_length - 1), 0)
            while i > stop and mask[i - 1] == PRINTABLE:
                i -= 1
            return i
        if i and mask[i - 1] == PRINTABLE:
            i -= 1
        pairs = 0
        while (
            i >= 2
            and pairs < self.min_length - 1
            and mask[i - 1] == NUL
            and mask[i - 2] == PRINTABLE
        ):
            i -= 2
            pairs += 1
        return i

    def scan(self, chunk: bytes, chunk_mask: bytes, chunk_at: int, lines: list[bytes]) -> None:
        if self.pending:
            data = self.pending + chunk
            mask = self.pending_mask + chunk_mask
        else:
            data, mask = chunk, chunk_mask
        base = chunk_at - len(self.pending)
        held = None
        append = lines.append
        text = self._text
        if self.continuing:
            # The rest of a string cut at MAX_CARRY. Long enough and the loop
            # below emits it; too short for a match and it comes out here —
            # unless it reaches this chunk's end too, in which case it is
            # carried on as the tail and still continuing.
            short = self._leading_run(mask)
            if short // self.width >= self.min_length:
                self.continuing = False  # a match in its own right; the loop has it
            elif not self._reaches_end(mask, short):
                self.continuing = False
                if short:
                    append(b"%d:%s\n" % (base, text(data, 0, short)))
                    self.count += 1
        for match in self.pattern.finditer(mask):
            start, end = match.span()
            if self._reaches_end(mask, end):
                held = start
                break
            append(b"%d:%s\n" % (base + start, text(data, start, end)))
            self.count += 1
        tail = held if held is not None else self._tail_start(mask)
        self.pending = data[tail:]
        self.pending_mask = mask[tail:]
        self.pending_at = base + tail
        if held is not None and len(self.pending) > MAX_CARRY:
            self.flush(lines, cut=True)

    def flush(self, lines: list[bytes], *, cut: bool = False) -> None:
        """Emit what is pending: at the end of the image if it is long enough to
        be a string, or cut at MAX_CARRY, in which case the wide encoding's
        dangling character byte stays pending and the rest is marked as
        continuing so the remainder comes out too."""
        pending = self.pending
        keep = len(pending) % 2 if (self.width == 2 and cut) else 0
        if keep:
            pending = pending[:-1]
        elif self.width == 2:
            pending = pending[: len(pending) // 2 * 2]  # a dangling character byte is nothing
        threshold = 1 if (cut or self.continuing) else self.min_length
        if len(pending) // self.width >= threshold:
            lines.append(b"%d:%s\n" % (self.pending_at, self._text(pending, 0, len(pending))))
            self.count += 1
        self.pending_at += len(pending) if keep else 0
        self.pending = self.pending[-1:] if keep else b""
        self.pending_mask = self.pending_mask[-1:] if keep else b""
        self.continuing = cut


def _scanners(min_length: int, encodings) -> list[_Scanner]:
    unknown = set(encodings) - set(ENCODINGS)
    if unknown:
        raise ValueError(f"unknown encoding(s): {', '.join(sorted(unknown))}")
    if min_length < 1:
        raise ValueError("min_length must be at least 1")
    scanners = []
    if "ascii" in encodings:
        scanners.append(_Scanner(1, min_length))
    if "unicode" in encodings:
        scanners.append(_Scanner(2, min_length))
    if not scanners:
        raise ValueError("no encodings selected")
    return scanners


@dataclass
class ExtractResult:
    output: Path
    image_size: int
    min_length: int
    encodings: tuple
    strings: int
    ascii: int
    unicode: int
    seconds: float

    def as_dict(self) -> dict:
        return {
            "format": "decimal offset, colon, string; one per line",
            "offsets": "exact",
            "image_size": self.image_size,
            "min_length": self.min_length,
            "encodings": list(self.encodings),
            "strings": self.strings,
            "ascii": self.ascii,
            "unicode": self.unicode,
            "seconds": round(self.seconds, 1),
        }


def extract(
    image: Path,
    output: Path,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    encodings=ENCODINGS,
    chunk_size: int = CHUNK_SIZE,
    progress: Callable[[int, int, int], None] | None = None,
) -> ExtractResult:
    """Write every string in ``image`` to ``output`` as ``offset:string`` lines.

    Lines are in ascending offset order within each encoding per chunk read;
    ASCII and UTF-16 strings are not interleaved. Nothing downstream needs them
    to be, and merging would cost more than the scan.
    """
    scanners = _scanners(min_length, tuple(encodings))
    size = image.stat().st_size
    started = time.monotonic()
    at = 0
    with open(image, "rb") as source, open(output, "wb") as sink:
        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break
            lines: list[bytes] = []
            mask = _mask(chunk)
            for scanner in scanners:
                scanner.scan(chunk, mask, at, lines)
            sink.write(b"".join(lines))
            at += len(chunk)
            if progress is not None:
                progress(at, size, sum(s.count for s in scanners))
        lines = []
        for scanner in scanners:
            scanner.flush(lines)
        sink.write(b"".join(lines))

    by_width = {s.width: s.count for s in scanners}
    return ExtractResult(
        output=output,
        image_size=size,
        min_length=min_length,
        encodings=tuple(encodings),
        strings=sum(by_width.values()),
        ascii=by_width.get(1, 0),
        unicode=by_width.get(2, 0),
        seconds=time.monotonic() - started,
    )


# --------------------------------------------------------------------------- hits

_LINE = re.compile(rb"\s*(\d+)(.*)", re.S)


def parse_line(line: bytes) -> tuple[int, bytes] | None:
    """The offset and string of one strings-file line, or None.

    Accepts the three shapes in circulation: this tool's and Sysinternals'
    ``offset:string``, and GNU ``strings -td``'s right-aligned ``offset string``.
    The string is kept byte-for-byte after the separator — leading spaces are
    part of what was in memory.
    """
    line = line.rstrip(b"\r\n")
    match = _LINE.match(line)
    if not match:
        return None
    rest = match.group(2)
    if rest[:1] in (b":", b" "):
        rest = rest[1:]
    return int(match.group(1)), rest


@dataclass
class Hit:
    stated: int
    string: bytes
    line: bytes
    located: list[int] = field(default_factory=list)


@dataclass
class HitScan:
    path: Path
    size: int
    lines: int
    hits: list[Hit]
    max_offset: int
    drops: int
    unparsed: int
    truncated: bool = False


def _text_encoding(head: bytes) -> tuple[str | None, int]:
    """A BOM says the file needs transcoding before its bytes mean anything.

    PowerShell 5's ``>`` writes UTF-16; a strings file made that way is the
    common case, not an exotic one.
    """
    if head.startswith(codecs.BOM_UTF16_LE) or head.startswith(codecs.BOM_UTF16_BE):
        return "utf-16", 0
    if head.startswith(codecs.BOM_UTF8):
        return None, len(codecs.BOM_UTF8)
    return None, 0


def _blocks(handle, block_size: int) -> Iterator[bytes]:
    head = handle.read(4)
    encoding, skip = _text_encoding(head)
    handle.seek(skip)
    if encoding is None:
        yield from iter(lambda: handle.read(block_size), b"")
        return
    decoder = codecs.getincrementaldecoder(encoding)()
    for raw in iter(lambda: handle.read(block_size), b""):
        yield decoder.decode(raw).encode("utf-8")
    tail = decoder.decode(b"", final=True)
    if tail:
        yield tail.encode("utf-8")


def encode_terms(terms, *, ignore_case: bool = True) -> list[bytes]:
    encoded = [t.encode("utf-8") if isinstance(t, str) else bytes(t) for t in terms]
    if ignore_case:
        encoded = [t.lower() for t in encoded]
    encoded = [t for t in encoded if t]
    if not encoded:
        raise ValueError("no search terms")
    return encoded


def _positions(haystack: bytes, needles: list[bytes]) -> list[int]:
    """Where any needle occurs, ascending.

    ``bytes.find`` per needle rather than one alternation regex: the former is
    a tuned substring search, the latter re-tries at every byte, and on a
    multi-gigabyte file that is the difference between seconds and a minute.
    """
    found: list[int] = []
    for needle in needles:
        position = haystack.find(needle)
        while position != -1:
            found.append(position)
            position = haystack.find(needle, position + 1)
    found.sort()
    return found


def scan_hits(
    path: Path,
    terms,
    *,
    ignore_case: bool = True,
    block_size: int = 16 << 20,
    max_hits: int | None = None,
) -> HitScan:
    """Every line of a strings file containing any of ``terms``.

    Reads in blocks and searches each as a whole, because a strings file for a
    large image is gigabytes and a line-at-a-time loop in Python is minutes.
    Alongside the hits it samples the offsets — the first line of every block
    and each hit — for the largest seen and how often the sequence jumps
    backwards, which is what a wrapped file looks like.
    """
    needles = encode_terms(terms, ignore_case=ignore_case)
    hits: list[Hit] = []
    lines = 0
    max_offset = -1
    drops = 0
    unparsed = 0
    previous: int | None = None
    truncated = False

    def sample(offset: int) -> None:
        nonlocal max_offset, drops, previous
        max_offset = max(max_offset, offset)
        if previous is not None and previous - offset > DROP:
            drops += 1
        previous = offset

    with open(path, "rb") as handle:
        carry = b""
        for block in _blocks(handle, block_size):
            data = carry + block
            cut = data.rfind(b"\n")
            if cut < 0:
                carry = data
                continue
            body, carry = data[: cut + 1], data[cut + 1 :]
            lines += body.count(b"\n")

            first = parse_line(body[: body.find(b"\n")])
            if first is not None:
                sample(first[0])

            haystack = body.lower() if ignore_case else body
            last_start = -1
            for position in _positions(haystack, needles):
                start = body.rfind(b"\n", 0, position) + 1
                if start == last_start:
                    continue
                last_start = start
                end = body.find(b"\n", position)
                line = body[start:end]
                parsed = parse_line(line)
                if parsed is None:
                    unparsed += 1
                    continue
                sample(parsed[0])
                hits.append(Hit(parsed[0], parsed[1], line.rstrip(b"\r")))
                if max_hits is not None and len(hits) >= max_hits:
                    truncated = True
                    break
            if truncated:
                break
        if carry and not truncated:
            lines += 1
            if _positions(carry.lower() if ignore_case else carry, needles):
                parsed = parse_line(carry)
                if parsed is None:
                    unparsed += 1
                else:
                    sample(parsed[0])
                    hits.append(Hit(parsed[0], parsed[1], carry.rstrip(b"\r")))

    return HitScan(
        path=path,
        size=path.stat().st_size,
        lines=lines,
        hits=hits,
        max_offset=max_offset,
        drops=drops,
        unparsed=unparsed,
        truncated=truncated,
    )


def _widen(probe: bytes) -> bytes:
    try:
        return probe.decode("utf-8").encode("utf-16-le")
    except UnicodeDecodeError:
        return b"".join(bytes((b, 0)) for b in probe)


@dataclass
class Location:
    """What checking the hits against the image established."""

    image_size: int
    at_stated: int
    relocated: int
    unresolved: int

    @property
    def wrapped(self) -> bool:
        """Any hit found only above where its offset says is a 32-bit file.

        Not one that merely repeats — a string present both at ``p`` and at
        ``p + 4 GiB`` counts as at its stated offset. Relocation is the
        signature: the bytes are not where the line says and are exactly a
        multiple of 4 GiB further on.
        """
        return self.relocated > 0


def locate(image: Path, hits: list[Hit], *, wrap: int | None = None) -> Location:
    """Check each hit against the image at its offset and at every offset a
    32-bit wrap could have folded onto it, recording where the bytes really are.

    Every candidate is read, in ascending order, in one sweep — a few thousand
    small reads that a spinning evidence disk can serve without thrashing. A
    string is recognised as ASCII or as UTF-16LE, whichever the memory held.
    """
    wrap = WRAP if wrap is None else wrap
    size = image.stat().st_size
    probes: list[tuple[bytes, bytes]] = []
    reads: list[tuple[int, int]] = []
    for index, hit in enumerate(hits):
        hit.located = []
        probe = hit.string[:PROBE_LENGTH]
        probes.append((probe, _widen(probe)))
        if not probe:
            continue
        offset = hit.stated
        while offset < size:
            reads.append((offset, index))
            offset += wrap
    reads.sort()

    with open(image, "rb") as handle:
        for offset, index in reads:
            narrow, wide = probes[index]
            handle.seek(offset)
            buffer = handle.read(len(wide))
            if buffer.startswith(narrow) or buffer.startswith(wide):
                hits[index].located.append(offset)

    at_stated = sum(1 for h in hits if h.stated in h.located)
    relocated = sum(1 for h in hits if h.located and h.stated not in h.located)
    unresolved = sum(1 for h in hits if not h.located)
    return Location(size, at_stated, relocated, unresolved)


def plugin_lines(hits: list[Hit], *, wrapped: bool, trust: bool = False) -> list[bytes]:
    """The lines the plugin should be given, sorted by offset, each once.

    With wrapped offsets every verified location is a real occurrence and all
    are kept. With exact offsets a hit is kept at its stated offset only: a
    repeat 4 GiB on has its own line already. ``trust`` skips the check
    altogether and passes the file's claims through.
    """
    chosen: set[tuple[int, bytes]] = set()
    for hit in hits:
        if trust:
            chosen.add((hit.stated, hit.string))
        elif wrapped:
            chosen.update((offset, hit.string) for offset in hit.located)
        elif hit.stated in hit.located:
            chosen.add((hit.stated, hit.string))
    return [b"%d:%s\n" % pair for pair in sorted(chosen)]


def unresolved_lines(hits: list[Hit]) -> list[bytes]:
    return [hit.line + b"\n" for hit in hits if not hit.located]


# ------------------------------------------------------------------ plugin output


def _int(value) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        text = str(value).strip()
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except (TypeError, ValueError):
        return None


@dataclass
class Group:
    label: str
    rows: list[dict] = field(default_factory=list)


def _owner(result: str, names: dict[int, str]) -> str:
    """``Process 4180:0x1b2c3d4e, kernel:0xf800...`` -> ``Process 4180 powershell.exe, kernel``."""
    parts = []
    for item in str(result).split(","):
        name = item.strip().rsplit(":", 1)[0].strip()
        if name.startswith("Process "):
            pid = _int(name[8:])
            if pid is not None and pid in names:
                name = f"{name} {names[pid]}"
        parts.append(name)
    return ", ".join(parts)


def group_rows(rows: list[dict], names: dict[int, str] | None = None) -> list[Group]:
    """The plugin's rows by owner, most hits first."""
    names = names or {}
    groups: dict[str, Group] = {}
    for row in rows:
        label = _owner(row.get("Result", ""), names)
        groups.setdefault(label, Group(label)).rows.append(row)
    return sorted(groups.values(), key=lambda g: (-len(g.rows), g.label))


def process_names(pslist_rows: list[dict]) -> dict[int, str]:
    names: dict[int, str] = {}
    for row in pslist_rows:
        pid = _int(row.get("PID"))
        name = row.get("ImageFileName")
        if pid is not None and name:
            names.setdefault(pid, str(name))
    return names


def report_lines(groups: list[Group], *, width: int | None = None, per_group: int | None = None) -> list[str]:
    """A readable account of who holds what: one block per owner."""
    lines: list[str] = []
    for group in groups:
        lines.append(f"{group.label}  ({len(group.rows)} hit{'s' if len(group.rows) != 1 else ''})")
        shown = group.rows if per_group is None else group.rows[:per_group]
        for row in shown:
            physical = _int(row.get("Physical Address"))
            where = f"0x{physical:x}" if physical is not None else "?"
            text = str(row.get("String", ""))
            if width is not None and len(text) > width:
                text = text[: width - 3] + "..."
            lines.append(f"    {where:>14}  {text}")
        if per_group is not None and len(group.rows) > per_group:
            lines.append(f"    ... {len(group.rows) - per_group} more")
    return lines


def console_safe(text: str) -> str:
    """Only what any Windows console can show; the report file has the rest."""
    return text.encode("ascii", "replace").decode("ascii")
