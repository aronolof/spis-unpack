from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import BinaryIO, Iterator

from .errors import DecodeError, EncryptedBlockError, ParseError, UnsupportedMethodError
from .lh5 import LH5Decoder
from .model import BlockReport, BlockSpan, SpisBlock
from .spis import index_file

DEFAULT_MAX_OUTPUT = 1024 * 1024 * 1024
CHUNK_SIZE = 65536


def _report(span: BlockSpan, output: Path | None = None, verify: bool | None = None) -> BlockReport:
    h = span.header
    return BlockReport(
        span.index,
        span.offset,
        h.method,
        span.payload_size,
        h.full_size,
        h.archive_type,
        h.checksum,
        h.locked,
        str(output) if output else None,
        span.prefix_offset,
        span.payload_offset,
        span.payload_offset + span.payload_size,
        span.framing,
        False if verify and h.is_stored and h.checksum == 0 else verify,
        ("absent" if h.is_stored and h.checksum == 0 else "passed") if verify else "not-requested",
    )


def _spans(
    path: Path,
    max_output: int | None = None,
    *,
    framing: str = "scan",
    start: int = 0,
    length: int | None = None,
) -> list[BlockSpan]:
    if framing == "length-prefixed":
        from .framing import index_file as framed_index

        spans = framed_index(path, start=start, length=length)
    elif framing == "scan" and start == 0 and length is None:
        spans = index_file(path)
    else:
        raise ParseError("Use length-prefixed framing for an explicit start/length")
    if not spans:
        raise ParseError("No complete SPIS headers found")
    if max_output is not None and (
        max_output < 0 or sum(s.header.full_size for s in spans) > max_output
    ):
        raise DecodeError(f"Declared output exceeds limit of {max_output} bytes")
    return spans


def inspect_file(
    path: Path, *, framing: str = "scan", start: int = 0, length: int | None = None
) -> list[BlockReport]:
    return [_report(s) for s in _spans(path, framing=framing, start=start, length=length)]


def decompress_block(block: SpisBlock) -> bytes:
    header = block.header
    if header.archive_type != 0:
        raise ParseError(f"Block {block.index} uses unsupported archive type {header.archive_type}")
    if header.is_encrypted:
        raise EncryptedBlockError(f"Block {block.index} is encrypted")
    if header.is_stored:
        if len(block.payload) < header.full_size:
            raise DecodeError(f"Block {block.index} is truncated")
        return block.payload[: header.full_size]
    if header.is_compressed:
        return LH5Decoder(block.payload).expand(header.full_size)
    raise UnsupportedMethodError(f"Block {block.index} uses unsupported method {header.method!r}")


class _PayloadReader:
    """Keep buffered decoding inside the indexed compressed span."""

    def __init__(self, handle: BinaryIO, span: BlockSpan):
        handle.seek(span.payload_offset)
        self.handle = handle
        self.remaining = span.payload_size

    def read(self, size: int) -> bytes:
        data = self.handle.read(min(size, self.remaining))
        self.remaining -= len(data)
        return data


def _chunks(handle: BinaryIO, span: BlockSpan) -> Iterator[bytes]:
    h = span.header
    if h.archive_type != 0:
        raise ParseError(f"Block {span.index} uses unsupported archive type {h.archive_type}")
    if h.is_encrypted:
        raise EncryptedBlockError(f"Block {span.index} is encrypted")
    source = _PayloadReader(handle, span)
    if h.is_compressed:
        yield from LH5Decoder(source).iter_expand(h.full_size)
    elif h.is_stored:
        remaining = h.full_size
        while remaining:
            chunk = source.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                raise DecodeError(f"Block {span.index} is truncated")
            remaining -= len(chunk)
            yield chunk
    else:
        raise UnsupportedMethodError(f"Block {span.index} uses unsupported method {h.method!r}")


def _decode(handle: BinaryIO, span: BlockSpan, target: BinaryIO | None, verify: bool) -> None:
    checksum = 0
    for chunk in _chunks(handle, span):
        if verify:
            checksum = (checksum + sum(chunk)) & 0xFFFFFFFF
        if target is not None:
            target.write(chunk)
    # TCompress permits an absent (zero) checksum for stored data only.
    if verify and not (span.header.is_stored and span.header.checksum == 0):
        if checksum != span.header.checksum & 0xFFFFFFFF:
            raise DecodeError(f"Block {span.index} checksum mismatch")


def test_file(
    path: Path,
    *,
    verify: bool = False,
    max_output: int | None = DEFAULT_MAX_OUTPUT,
    framing: str = "scan",
    start: int = 0,
    length: int | None = None,
) -> list[BlockReport]:
    spans = _spans(path, max_output, framing=framing, start=start, length=length)
    with path.open("rb") as source:
        for span in spans:
            _decode(source, span, None, verify)
    return [_report(s, verify=verify) for s in spans]


def _protect_input(path: Path, output: Path) -> None:
    if path.resolve() == output.resolve() or (output.exists() and path.samefile(output)):
        raise ParseError("Input and output must be different files")


def unpack_to_file(
    path: Path,
    output_path: Path,
    *,
    verify: bool = False,
    max_output: int | None = DEFAULT_MAX_OUTPUT,
    framing: str = "scan",
    start: int = 0,
    length: int | None = None,
) -> list[BlockReport]:
    _protect_input(path, output_path)
    spans = _spans(path, max_output, framing=framing, start=start, length=length)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=output_path.parent, prefix=".spis-", delete=False
        ) as target:
            temporary = Path(target.name)
            with path.open("rb") as source:
                for span in spans:
                    _decode(source, span, target, verify)
        os.replace(temporary, output_path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return [_report(s, output_path, verify) for s in spans]


def unpack_to_dir(
    path: Path,
    output_dir: Path,
    *,
    verify: bool = False,
    max_output: int | None = DEFAULT_MAX_OUTPUT,
    framing: str = "scan",
    start: int = 0,
    length: int | None = None,
) -> list[BlockReport]:
    spans = _spans(path, max_output, framing=framing, start=start, length=length)
    destinations = [output_dir / f"block_{s.index:04d}.bin" for s in spans]
    for destination in destinations:
        _protect_input(path, destination)
        if destination.exists() and not destination.is_file():
            raise ParseError(f"Output is not a file: {destination}")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output_dir.parent, prefix=".spis-") as temporary:
        staged = Path(temporary)
        with path.open("rb") as source:
            for span, destination in zip(spans, destinations):
                with (staged / destination.name).open("wb") as target:
                    _decode(source, span, target, verify)
        output_dir.mkdir(parents=True, exist_ok=True)
        for destination in destinations:
            os.replace(staged / destination.name, destination)
    return [_report(s, p, verify) for s, p in zip(spans, destinations)]


def reports_to_json(input_path: Path, reports: list[BlockReport]) -> str:
    return json.dumps(
        {
            "schema_version": "2.0.0",
            "input_bytes": input_path.stat().st_size,
            "unclassified_ranges": _unclassified(input_path, reports),
            "input": str(input_path),
            "blocks": [report.to_dict() for report in reports],
        },
        indent=2,
        sort_keys=True,
    )


def _unclassified(path: Path, reports: list[BlockReport]) -> list[dict]:
    ranges = []
    cursor = 0
    for report in reports:
        start = report.prefix_offset if report.prefix_offset is not None else report.offset
        if start > cursor:
            ranges.append({"offset": cursor, "bytes": start - cursor})
        cursor = report.end_offset
    if cursor < path.stat().st_size:
        ranges.append({"offset": cursor, "bytes": path.stat().st_size - cursor})
    return ranges
