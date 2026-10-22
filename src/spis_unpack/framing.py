"""Explicit external uint32-length framing, separate from SPIS header discovery."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

from .errors import ParseError
from .model import BlockSpan, SpisHeader
from .spis import parse_header


@dataclass(frozen=True)
class FramedBlock:
    index: int
    prefix_offset: int
    source_offset: int
    end: int
    raw: bytes
    decoded_length: int
    checksum: int
    header: SpisHeader


def spans(
    handle: BinaryIO, size: int, *, start: int = 0, length: int | None = None, first_index: int = 0
) -> Iterator[BlockSpan]:
    end = size if length is None else start + length
    if start < 0 or end < start or end > size or first_index < 0:
        raise ParseError("Framed stream range is outside input")
    cursor = start
    index = first_index
    while cursor < end:
        handle.seek(cursor)
        prefix = handle.read(4)
        if len(prefix) != 4 or cursor + 4 > end:
            raise ParseError(f"Truncated block length at {cursor}")
        block_size = struct.unpack("<I", prefix)[0]
        block_end = cursor + 4 + block_size
        if block_size < 21 or block_end > end:
            raise ParseError(f"Invalid block extent at {cursor}: {block_size}")
        offset = cursor + 4
        header = parse_header(handle.read(min(25, block_size)), offset)
        if header is None or header.header_size > block_size:
            raise ParseError(f"Invalid SPIS header at {offset}")
        payload = offset + header.header_size
        if header.is_stored and block_end - payload != header.full_size:
            raise ParseError(f"Stored size differs from framed extent at {offset}")
        yield BlockSpan(
            index,
            offset,
            header,
            payload,
            block_end - payload,
            prefix_offset=cursor,
            framing="length-prefixed",
        )
        cursor = block_end
        index += 1


def index_file(path: Path, *, start: int = 0, length: int | None = None) -> list[BlockSpan]:
    with path.open("rb") as handle:
        return list(spans(handle, path.stat().st_size, start=start, length=length))


def blocks(
    handle: BinaryIO,
    size: int,
    *,
    start: int = 0,
    length: int | None = None,
    first_index: int = 0,
    max_decoded: int = 8 * 1024 * 1024,
    max_compressed: int = 16 * 1024 * 1024,
) -> Iterator[FramedBlock]:
    for span in spans(handle, size, start=start, length=length, first_index=first_index):
        extent = span.payload_offset + span.payload_size - span.offset
        if extent > max_compressed or span.header.full_size > max_decoded:
            raise ParseError(f"Framed block exceeds resource bound at {span.offset}")
        handle.seek(span.offset)
        raw = handle.read(extent)
        if len(raw) != extent:
            raise ParseError(f"Truncated block at {span.offset}")
        yield FramedBlock(
            span.index,
            span.prefix_offset,
            span.offset,
            span.payload_offset + span.payload_size,
            raw,
            span.header.full_size,
            span.header.checksum & 0xFFFFFFFF,
            span.header,
        )
