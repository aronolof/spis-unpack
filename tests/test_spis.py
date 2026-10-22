from __future__ import annotations

from pathlib import Path

from spis_unpack.spis import (
    SPIS_MAGIC,
    find_blocks,
    find_blocks_in_file,
    iter_blocks_from_bytes,
    parse_header,
)


def build_header(
    *,
    method: bytes,
    full_size: int,
    archive_type: int = 0,
    checksum: int = 0,
    locked: int = 0,
) -> bytes:
    return (
        SPIS_MAGIC
        + method
        + full_size.to_bytes(4, "little", signed=False)
        + bytes([archive_type])
        + checksum.to_bytes(4, "little", signed=True)
        + locked.to_bytes(4, "little", signed=True)
    )


def test_parse_header_reads_standard_fields() -> None:
    header = parse_header(build_header(method=b"LH5", full_size=1234, archive_type=1, checksum=99))
    assert header is not None
    assert header.method == "LH5"
    assert header.full_size == 1234
    assert header.archive_type == 1
    assert header.checksum == 99
    assert header.locked == 0
    assert header.header_size == 21


def test_find_blocks_finds_all_spis_headers() -> None:
    data = (
        b"noise"
        + build_header(method=b"NON", full_size=2)
        + b"ab"
        + build_header(method=b"NON", full_size=3)
        + b"xyz"
    )
    assert find_blocks(data) == [5, 28]


def test_iter_blocks_slices_payloads_between_headers() -> None:
    data = (
        build_header(method=b"NON", full_size=2)
        + b"ab"
        + build_header(method=b"NON", full_size=3)
        + b"xyz"
    )
    blocks = list(iter_blocks_from_bytes(data))
    assert len(blocks) == 2
    assert blocks[0].payload == b"ab"
    assert blocks[1].payload == b"xyz"


def test_parse_header_rejects_unknown_method() -> None:
    assert parse_header(build_header(method=b"XYZ", full_size=1)) is None


def test_find_blocks_ignores_false_magic_hits() -> None:
    data = b"junkSPIS\x1aXYZtrash" + build_header(method=b"LH5", full_size=1) + b"x"
    assert find_blocks(data) == [17]


def test_find_blocks_in_file_handles_split_signature(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(
        b"a" * (1024 * 1024 - 3) + b"SPI" + b"S\x1aLH5" + b"\x01\x00\x00\x00\x00" + b"\x00" * 8
    )
    assert find_blocks_in_file(path) == [1024 * 1024 - 3]


def test_parse_header_reads_big_file_size() -> None:
    lower = 5
    upper = 3
    header_bytes = (
        SPIS_MAGIC
        + b"LH5"
        + lower.to_bytes(4, "little", signed=False)
        + b"\x00"
        + (0).to_bytes(4, "little", signed=True)
        + (0x80).to_bytes(4, "little", signed=True)
        + upper.to_bytes(4, "little", signed=False)
    )
    header = parse_header(header_bytes)
    assert header is not None
    assert header.header_size == 25
    assert header.full_size == (upper << 31) + lower


def test_header_signatures_inside_header_fields_do_not_make_negative_spans():
    data = bytearray(build_header(method=b"LH5", full_size=4))
    data[13:21] = SPIS_MAGIC + b"NON"
    data.extend(bytes(20))
    blocks = list(iter_blocks_from_bytes(bytes(data)))
    assert len(blocks) == 1
    assert len(blocks[0].payload) == 20
