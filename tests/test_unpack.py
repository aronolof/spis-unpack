from __future__ import annotations

from pathlib import Path

from spis_unpack.spis import SPIS_MAGIC
from spis_unpack.unpack import inspect_file, unpack_to_dir, unpack_to_file


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


def write_sample(path: Path) -> None:
    path.write_bytes(
        build_header(method=b"NON", full_size=5)
        + b"hello"
        + build_header(method=b"NON", full_size=5)
        + b"world"
    )


def test_unpack_to_file_concatenates_blocks(tmp_path: Path) -> None:
    source = tmp_path / "sample.b1"
    output = tmp_path / "sample.bin"
    write_sample(source)

    reports = unpack_to_file(source, output)

    assert output.read_bytes() == b"helloworld"
    assert len(reports) == 2
    assert reports[0].decompressed_size == 5


def test_unpack_to_dir_writes_one_file_per_block(tmp_path: Path) -> None:
    source = tmp_path / "sample.b1"
    output_dir = tmp_path / "out"
    write_sample(source)

    reports = unpack_to_dir(source, output_dir)

    assert len(reports) == 2
    assert (output_dir / "block_0000.bin").read_bytes() == b"hello"
    assert (output_dir / "block_0001.bin").read_bytes() == b"world"


def test_inspect_file_reports_block_sizes(tmp_path: Path) -> None:
    source = tmp_path / "sample.b1"
    write_sample(source)

    reports = inspect_file(source)

    assert [report.compressed_size for report in reports] == [5, 5]
    assert [report.decompressed_size for report in reports] == [5, 5]


def test_failed_decode_preserves_output(tmp_path):
    import pytest

    from spis_unpack.errors import DecodeError

    source, output = tmp_path / "in.b1", tmp_path / "out.bin"
    source.write_bytes(
        build_header(method=b"NON", full_size=2)
        + b"ok"
        + build_header(method=b"LH5", full_size=5)
        + b"bad"
    )
    output.write_bytes(b"previous")
    with pytest.raises(DecodeError):
        unpack_to_file(source, output)
    assert output.read_bytes() == b"previous"
    directory = tmp_path / "split"
    with pytest.raises(DecodeError):
        unpack_to_dir(source, directory)
    assert not directory.exists()


def test_rejects_invalid_inputs_and_same_file(tmp_path):
    import pytest

    from spis_unpack.errors import ParseError

    source = tmp_path / "in.b1"
    for data in [b"ordinary file", build_header(method=b"NON", full_size=5) + b"ab"]:
        source.write_bytes(data)
        with pytest.raises(ParseError):
            unpack_to_file(source, tmp_path / "out")
    write_sample(source)
    before = source.read_bytes()
    with pytest.raises(ParseError):
        unpack_to_file(source, source)
    assert source.read_bytes() == before


def test_stored_data_can_contain_complete_spis_headers(tmp_path):
    payload = b"before" + build_header(method=b"NON", full_size=2) + b"abafter"
    source, output = tmp_path / "in.b1", tmp_path / "out"
    source.write_bytes(build_header(method=b"NON", full_size=len(payload)) + payload)
    reports = unpack_to_file(source, output)
    assert len(reports) == 1
    assert output.read_bytes() == payload


def test_checksum_and_output_limit(tmp_path):
    import pytest

    from spis_unpack.errors import DecodeError
    from spis_unpack.unpack import test_file as validate

    source = tmp_path / "in.b1"
    source.write_bytes(build_header(method=b"NON", full_size=2, checksum=195) + b"ab")
    assert len(validate(source, verify=True)) == 1
    with pytest.raises(DecodeError, match="limit"):
        validate(source, max_output=1)
    source.write_bytes(build_header(method=b"NON", full_size=2, checksum=1) + b"ab")
    with pytest.raises(DecodeError, match="checksum"):
        validate(source, verify=True)


def test_multifile_archive_is_not_decoded_as_single_stream(tmp_path):
    import pytest

    from spis_unpack.errors import ParseError

    source = tmp_path / "multi.b1"
    source.write_bytes(build_header(method=b"NON", full_size=2, archive_type=1) + b"ab")
    with pytest.raises(ParseError, match="archive type"):
        unpack_to_file(source, tmp_path / "out.bin")
