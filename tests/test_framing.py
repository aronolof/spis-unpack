import io
import json
import struct

import pytest

from spis_unpack.errors import ParseError
from spis_unpack.framing import blocks, index_file
from spis_unpack.unpack import inspect_file, reports_to_json, unpack_to_file
from spis_unpack.unpack import test_file as validate


def stored(payload):
    raw = b"SPIS\x1aNON" + struct.pack("<IBII", len(payload), 0, sum(payload), 0) + payload
    return struct.pack("<I", len(raw)) + raw


def test_embedded_signatures_are_data_and_ranges_are_explicit(tmp_path):
    data = b"before" + stored(b"SPIS\x1aLH5 is data") + stored(b"end") + b"after"
    path = tmp_path / "source.b"
    path.write_bytes(data)
    length = len(data) - 11
    reports = validate(path, framing="length-prefixed", start=6, length=length, verify=True)
    assert len(reports) == 2
    assert reports[0].offset == 10
    assert reports[0].prefix_offset == 6
    out = tmp_path / "out.bin"
    unpack_to_file(path, out, framing="length-prefixed", start=6, length=length, verify=True)
    assert out.read_bytes() == b"SPIS\x1aLH5 is dataend"
    report = json.loads(reports_to_json(path, reports))
    assert report["unclassified_ranges"] == [
        {"offset": 0, "bytes": 6},
        {"offset": len(data) - 5, "bytes": 5},
    ]
    assert all(r["checksum_verified"] for r in report["blocks"])
    assert inspect_file(path, framing="length-prefixed", start=6, length=length)


@pytest.mark.parametrize(
    "raw",
    [
        b"\1",
        struct.pack("<I", 20) + b"0" * 20,
        struct.pack("<I", 1000) + b"0" * 21,
        struct.pack("<I", 21) + b"0" * 21,
    ],
)
def test_invalid_framing_is_not_recovered(tmp_path, raw):
    path = tmp_path / "source.b"
    path.write_bytes(raw)
    with pytest.raises(ParseError):
        index_file(path)


def test_stream_blocks_preserve_raw_and_enforce_bounds():
    data = stored(b"AB") + stored(b"C")
    rows = list(blocks(io.BytesIO(data), len(data), first_index=4))
    assert [r.index for r in rows] == [4, 5]
    assert rows[0].raw[21:] == b"AB"
    assert rows[-1].end == len(data)
    with pytest.raises(ParseError, match="resource bound"):
        list(blocks(io.BytesIO(data), len(data), max_decoded=1))
    with pytest.raises(ParseError, match="outside"):
        list(blocks(io.BytesIO(data), len(data), start=-1))


def test_framed_stored_extent_must_match_declared_size(tmp_path):
    data = bytearray(stored(b"AB"))
    struct.pack_into("<I", data, 12, 1)
    path = tmp_path / "bad.b"
    path.write_bytes(data)
    with pytest.raises(ParseError, match="Stored size"):
        index_file(path)


def test_cli_framing_and_missing_stored_checksum_are_explicit(tmp_path, capsys):
    from spis_unpack.cli import main

    path = tmp_path / "source.b"
    data = bytearray(stored(b"AB"))
    struct.pack_into("<I", data, 17, 0)
    path.write_bytes(b"header" + data)
    assert (
        main(
            [
                str(path),
                "--framing",
                "length-prefixed",
                "--start",
                "6",
                "--test",
                "--verify",
                "--json",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["blocks"][0]["checksum_status"] == "absent"
    assert report["blocks"][0]["checksum_verified"] is False
    assert not path.with_suffix(".bin").exists()
    with pytest.raises(SystemExit):
        main([str(path), "--start", "6"])
