from __future__ import annotations

from pathlib import Path

from spis_unpack.cli import main
from spis_unpack.spis import SPIS_MAGIC


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
    path.write_bytes(build_header(method=b"NON", full_size=4) + b"test")


def test_cli_lists_blocks(capsys, tmp_path: Path) -> None:
    source = tmp_path / "sample.b1"
    write_sample(source)

    exit_code = main([str(source), "--list"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "index\toffset\tmethod" in captured.out
    assert "\tNON\t" in captured.out


def test_cli_unpacks_to_default_output(tmp_path: Path) -> None:
    source = tmp_path / "sample.b1"
    write_sample(source)

    exit_code = main([str(source)])

    assert exit_code == 0
    assert (tmp_path / "sample.bin").read_bytes() == b"test"


def test_cli_splits_blocks(tmp_path: Path) -> None:
    source = tmp_path / "sample.b1"
    output_dir = tmp_path / "split"
    write_sample(source)

    exit_code = main([str(source), "--split-blocks", "-d", str(output_dir)])

    assert exit_code == 0
    assert (output_dir / "block_0000.bin").read_bytes() == b"test"


def test_cli_validates_without_output(capsys, tmp_path):
    import json

    source = tmp_path / "sample.b1"
    write_sample(source)
    assert main([str(source), "--test", "--verify", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["blocks"]) == 1
    assert not source.with_suffix(".bin").exists()


def test_cli_cannot_overwrite_input_with_force(capsys, tmp_path):
    source = tmp_path / "sample.bin"
    write_sample(source)
    before = source.read_bytes()
    assert main([str(source), "--force"]) == 1
    assert source.read_bytes() == before
    assert "different files" in capsys.readouterr().err
