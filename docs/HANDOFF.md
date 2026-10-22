# Format and maintenance notes

This package decodes SPIS/TCompress payload bytes. Keep header parsing, external
framing, decompression, integrity verification and output publication separate.
Application-specific records, schemas, databases and analytics belong elsewhere.

## Architecture

| Module | Responsibility |
| --- | --- |
| `cli.py` | Command-line validation and operation selection |
| `spis.py` | Header parsing and signature-recovery indexing |
| `framing.py` | Explicit external uint32-length framing and physical spans |
| `model.py` | Headers, spans and report records |
| `bitstream.py` | Buffered MSB-first bit reads |
| `lh5.py` | Canonical Huffman decoding and 8 KiB sliding window |
| `unpack.py` | Bounded reads, checksums and staged output publication |
| `errors.py` | Format, decoding, encryption and unsupported-method errors |

## Header fields

Multi-byte fields are little-endian.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 5 | `SPIS` followed by byte `0x1A` |
| 5 | 3 | ASCII method |
| 8 | 4 | Low decoded-size field |
| 12 | 1 | Archive type; supported extraction uses zero |
| 13 | 4 | Signed checksum, compared modulo 2^32 |
| 17 | 4 | Lock/flags field |
| 21 | 4, optional | Upper size field when flag `0x80` is set |

Headers contain 21 or 25 bytes. The implemented large-size formula is
`(upper << 31) + lower`; preserve this behavior unless independent format evidence
supports a change. Strip the big-file flag before interpreting encryption flags.
Other nonzero lock flags and multi-file directories are unsupported for decoding.
Recognition of RLE/LZH enables inspection, not decompression.

## Framing

SPIS single-stream headers do not contain a compressed length. Signature scanning
is recovery: an accidental recognized header inside compressed bytes can split a
stream incorrectly. Stored extents use their declared size and preserve embedded
signatures. Checksums do not resolve boundary ambiguity.

The explicitly selected `length-prefixed` adapter reads an external little-endian
uint32 before each complete SPIS block. Validate all extents and exact region
coverage; do not scan past malformed lengths. A caller supplies the region start
and optional byte length. Preserve prefix, header, payload and end offsets.
The raw-block convenience iterator enforces compressed and decoded bounds;
span iteration avoids materializing complete compressed payloads.

## LH5 behavior

The dictionary contains 8192 bytes, initially spaces. Maximum match length is
256; minimum match length is three. There are 510 character symbols, 14 position
symbols and 19 temporary symbols. Table widths are 9, 4 and 5 bits respectively.
Reject incomplete, oversubscribed or malformed Huffman tables.

The decoded position value becomes a match distance with exactly one `+1`.
Two literals A and B followed by a length-three match at distance two must produce
`ABABA`. Preserve overlap and dictionary-wrap behavior. Reject matches extending
beyond the declared output size. Tests include independent synthetic streams,
nonconstant tables and distinct leaves in a thirteen-bit canonical tree.

## Integrity and output

Checksum verification is opt-in and sums decoded bytes modulo 2^32. A zero
checksum is absent for stored methods; compressed zero checksums are still
checked. Reports distinguish an absent checksum from successful verification.
JSON schema 2.0.0 includes framing, physical ranges, verification state and
unclassified ranges. A checksum is not a cryptographic signature.

The default CLI decoded-output limit is 1 GiB. CLI zero disables it; Python APIs
use `None` for unlimited output. Streaming paths use bounded chunks; convenience
APIs returning complete bytes allocate the complete result. Index memory scales
with the number of discovered headers.

Stage a single output beside its destination and publish after successful decode.
Split extraction stages all blocks before publication, but replacements are atomic
per file rather than across the directory. Protect input aliases and hard links.
CLI overwrites require `--force`; Python writers may replace existing outputs.
Preserve existing destinations on decoding or checksum failure.

## Development

Run from the repository root:

```sh
uv sync --extra dev --locked
uv run --extra dev pytest
uv run --extra dev ruff check src tests
uv build
```

Run lint without automatic fixes first. Preserve modified and untracked source
before bulk edits. Scope fixes to reviewed paths. Keep fixtures synthetic or
redistributable, with independent expected bytes and checksum evidence. External
compatibility checks should not introduce private inputs or corpus-specific
claims into public documentation. Tests establish only the cases they exercise.

The public TCompress component reference is https://webcentre.co.nz/compress.htm.
Do not redistribute third-party source or fixtures without appropriate rights;
retain required notices. Unsupported methods or format extensions need separate,
fixture-driven work. Measure a real workload before optimizing the decoder.
