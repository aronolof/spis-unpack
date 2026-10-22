# spis-unpack

Unpack SPIS containers and decompress SPIS payloads. Requires Python 3.11 or newer.

## Background

SPIS is a legacy container/compression format found in older Windows software and data archives.

- TCompress component page: https://webcentre.co.nz/compress.htm

## Install

```bash
uv tool install .
```

## Use

```bash
spis-unpack input.b1
spis-unpack input.b1 -o output.bin
spis-unpack input.b1 --list
spis-unpack input.b1 --split-blocks -d out/
spis-unpack input.b1 --json
```

## Notes

- Supports SPIS `LH5`, `NON`, and `LH0`.
- Writes raw decompressed bytes.
- Does not parse application-specific record formats.

## Validate before extracting

```bash
spis-unpack input.b1 --test
spis-unpack input.b1 --test --verify --json
spis-unpack input.b1 -o output.bin --verify --max-output 4294967296
```

`--test` decodes every block without writing files. `--verify` also checks the
32-bit additive checksum defined by TCompress; it is an integrity check, not a
cryptographic signature. A zero checksum is permitted for stored blocks. Checksum
verification is opt-in because legacy embedded payloads may lack usable checksums.

The default total decoded-output limit is 1 GiB. `--max-output` accepts bytes;
`--max-output 0` removes that limit. The command-line extraction and validation
paths stream compressed input and decoded output in bounded chunks. The block
index uses memory proportional to the number of discovered signatures. The
convenience `decompress_block` and `LH5Decoder.expand` APIs return complete bytes;
use `LH5Decoder.iter_expand` when consuming large output in Python.

`--list` is inspection only and never decompresses or writes files. Use
`--list --json` for one machine-readable metadata document. `--out-dir` requires
`--split-blocks`; inspection and extraction flags cannot be mixed.

Single-file extraction is staged beside the destination and published using an
atomic replacement after successful decoding. Split extraction stages every
block before publishing; replacements are atomic per file, not across the whole
directory. `--force` replaces existing destinations but never permits replacing
the input itself. Invalid inputs and truncated stored blocks raise errors.

## Format boundaries

- Only single-stream headers (`archive_type=0`) are decoded. Multi-file archive
  directories, encrypted blocks, RLE, and LZH require additional format work.
- Stored blocks use their declared size, so embedded SPIS signatures are preserved.
- Compressed spans are discovered by scanning for complete recognized headers.
  SPIS headers do not include a compressed length; an accidental valid header in
  compressed bytes is still ambiguous. Use an explicit framing adapter when the
  surrounding format supplies block lengths. Checksums do not resolve framing.
- LH5 regression cases cover literal tables, nonconstant Huffman tables,
  overlapping back-references, dictionary wrapping, truncation, and malformed
  tables. A representative real-world SPIS corpus remains necessary before
  claiming broad compatibility.

## Development

```bash
uv sync --extra dev --locked
uv run --extra dev pytest
uv run --extra dev ruff check src tests
```

## Continuing development or moving machines

Read [AGENTS.md](AGENTS.md) and the [format and maintenance notes](docs/HANDOFF.md)
for implementation boundaries and verification requirements. Recreate development
environments from the lockfile rather than copying virtual environments.

## Exact external framing (0.3)

The supported `length-prefixed` adapter reads an external little-endian uint32
length before each complete SPIS block. This is container framing, not a field
inside the SPIS header. It is explicitly selected; arbitrary SPIS files are not
assumed to have this layout.

```sh
spis-unpack framed.bin --framing length-prefixed --start 8 --list --json
spis-unpack framed.bin --framing length-prefixed --start 8 --test --verify
spis-unpack framed.bin --framing length-prefixed --start 8 -o decoded.bin --verify
```

`--length` restricts the framed region in bytes; the default extends to EOF.
Truncated or invalid lengths fail instead of scanning forward. `--start` and
`--length` require this adapter. The default `--framing scan` remains signature
recovery and does not prove compressed boundaries. Stored payload extents remain
exact in either mode.

Python callers can pass `framing="length-prefixed", start=8, length=...` to
`inspect_file`, `test_file`, `unpack_to_file` and `unpack_to_dir`. For bounded
stream access use `spis_unpack.framing.blocks(handle, file_size, start=...)`;
it yields raw blocks with prefix/header/end offsets. `framing.spans` indexes
without retaining whole compressed blocks. Application-specific schemas remain downstream.

JSON schema 2.0.0 adds framing, prefix/payload/end offsets, checksum verification
state and unclassified input ranges. A checksum checked during validation is
separate from a cryptographic hash; listing never claims verification.

The public suite uses synthetic compressed streams and malformed-input fixtures.
It does not require external files. Additional compatibility checks should use
lawfully shareable fixtures with independently established expected bytes and
checksums, or externally supplied inputs. Passing synthetic tests alone does not
establish compatibility with arbitrary SPIS variants.

Current focus: exact external framing, bounded streaming, useful errors and
independent decoded-byte checks. Application schemas belong in consuming tools.
