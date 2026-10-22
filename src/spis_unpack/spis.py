from __future__ import annotations

import io
from bisect import bisect_left
from pathlib import Path
from typing import BinaryIO, Iterator

from .binary import read_i32le, read_u32le
from .errors import ParseError
from .model import BlockSpan, SpisBlock, SpisHeader

SPIS_MAGIC = b"SPIS\x1a"
SPIS_HEADER_SIZE = 21
SPIS_BIG_FILE_FLAG = 0x80
SPIS_METHODS = ("LH5", "RLE", "LZH", "NON", "LH0")
SPIS_SIGNATURES = tuple(SPIS_MAGIC + method.encode("ascii") for method in SPIS_METHODS)
SPIS_SCAN_CHUNK_SIZE = 1024 * 1024


def parse_header(data: bytes, offset: int = 0) -> SpisHeader | None:
    if len(data) < SPIS_HEADER_SIZE:
        return None
    if data[:5] != SPIS_MAGIC:
        return None

    method = data[5:8].decode("ascii", errors="replace")
    if method not in SPIS_METHODS:
        return None
    full_size = read_u32le(data, 8)
    archive_type = data[12]
    checksum = read_i32le(data, 13)
    locked_raw = read_i32le(data, 17)
    header_size = SPIS_HEADER_SIZE

    if (locked_raw & SPIS_BIG_FILE_FLAG) != 0:
        if len(data) < SPIS_HEADER_SIZE + 4:
            return None
        upper_size = read_u32le(data, 21)
        full_size = (upper_size << 31) + full_size
        header_size = SPIS_HEADER_SIZE + 4

    locked = locked_raw & ~SPIS_BIG_FILE_FLAG
    return SpisHeader(
        method=method,
        full_size=full_size,
        archive_type=archive_type,
        checksum=checksum,
        locked=locked,
        offset=offset,
        header_size=header_size,
    )


def find_blocks(data: bytes) -> list[int]:
    offsets = {
        found for signature in SPIS_SIGNATURES for found in _find_signature_offsets(data, signature)
    }
    return sorted(offsets)


def find_blocks_in_file(path: Path) -> list[int]:
    longest_signature = max(len(signature) for signature in SPIS_SIGNATURES)
    tail = b""
    offset = 0
    offsets: set[int] = set()

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(SPIS_SCAN_CHUNK_SIZE)
            if not chunk:
                break
            haystack = tail + chunk
            base_offset = offset - len(tail)
            for signature in SPIS_SIGNATURES:
                for found in _find_signature_offsets(haystack, signature):
                    offsets.add(base_offset + found)
            tail = haystack[-(longest_signature - 1) :] if longest_signature > 1 else b""
            offset += len(chunk)

    return sorted(offsets)


def _find_signature_offsets(data: bytes, signature: bytes) -> list[int]:
    offsets: list[int] = []
    start = 0
    while True:
        found = data.find(signature, start)
        if found < 0:
            return offsets
        offsets.append(found)
        start = found + 1


def iter_blocks_from_bytes(data: bytes) -> Iterator[SpisBlock]:
    for span in _index(io.BytesIO(data), find_blocks(data), len(data)):
        yield SpisBlock(
            index=span.index,
            offset=span.offset,
            header=span.header,
            payload=data[span.payload_offset : span.payload_offset + span.payload_size],
        )


def _index(handle: BinaryIO, offsets: list[int], file_size: int) -> list[BlockSpan]:
    headers = []
    for offset in offsets:
        handle.seek(offset)
        header = parse_header(handle.read(25), offset=offset)
        if header is not None:
            headers.append(header)
    spans = []
    positions = [header.offset for header in headers]
    consumed = 0
    for pos, header in enumerate(headers):
        if header.offset < consumed:
            continue
        start = header.offset + header.header_size
        if header.is_stored:
            end = start + header.full_size
            if end > file_size:
                raise ParseError(f"Truncated stored block at offset {header.offset}")
        else:
            next_index = bisect_left(positions, start, lo=pos + 1)
            end = positions[next_index] if next_index < len(positions) else file_size
        spans.append(BlockSpan(len(spans), header.offset, header, start, end - start))
        consumed = end
    return spans


def index_file(path: Path) -> list[BlockSpan]:
    offsets = find_blocks_in_file(path)
    file_size = path.stat().st_size
    with path.open("rb") as handle:
        return _index(handle, offsets, file_size)


def iter_blocks(path: Path) -> Iterator[SpisBlock]:
    spans = index_file(path)
    with path.open("rb") as handle:
        for span in spans:
            handle.seek(span.payload_offset)
            yield SpisBlock(
                index=span.index,
                offset=span.offset,
                header=span.header,
                payload=handle.read(span.payload_size),
            )
