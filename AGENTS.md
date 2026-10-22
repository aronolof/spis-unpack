# Working on spis-unpack

Read `README.md` for usage and `docs/HANDOFF.md` for format decisions,
verification requirements and maintenance notes.
The repository and these documents should allow continuation without chat history.

## Scope and preservation

- Set every shell command's working directory to this repository explicitly.
  Before changing files, check `git rev-parse --show-toplevel` and confirm the
  intended repository. Never run automatic fixes from the shared parent directory.
- Sibling projects are read-only references unless the user authorizes edits.
- Before bulk automated edits, preserve the current files, including local changes
  and untracked source files. A new branch alone does not snapshot them. Do not
  reset to HEAD to undo an incident when there was pre-existing local work.
- Run lint without fixes first: `uv run --extra dev ruff check src tests`.
  Scope any subsequent fixes to reviewed files or explicit directories.
- These instructions are procedural; OS write restrictions need a separately
  configured execution environment.

## Implementation contract

- Success means exact decoded bytes, explicit format boundaries, and useful errors.
  Reject truncated stored blocks and unsupported/encrypted formats explicitly.
- Stored extents come from their declared length. Compressed-header scanning is
  ambiguous recovery; do not present it as validated application container framing.
- Preserve streaming, decoded-output limits, checksum semantics, input protection,
  and staged publication. Split output is atomic per file, not per directory.
- LH5's decoded position must receive a single +1 to become the match distance.
  Retain the ABABA regression and bounded malformed-table handling.
- Keep application-specific schemas and analytics in consuming tools.
- Prioritize independent real-data fixtures and explicit container adapters before
  Huffman optimization or parallel decompression. Label historical evidence clearly.

## Verification

Run from this repository:

```sh
uv sync --extra dev --locked
uv run --extra dev pytest
uv run --extra dev ruff check src tests
```

For packaging changes also run `uv build`. Decoder changes need independent
expected bytes and checksum evidence, not only agreement with another local port.
See the handoff for reference-source locations and unsupported formats.

## Public repository boundary

Keep source, examples, tests, documentation and release artifacts generic.
Do not include personal filesystem paths, hostnames, private project names,
customer/dataset details, private fixtures, corpus receipts or recovery notes.
Use synthetic examples and retain required copyright/license attribution.
Keep local reviews, private evidence and backups outside this repository.
