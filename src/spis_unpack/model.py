from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class SpisHeader:
    method: str
    full_size: int
    archive_type: int
    checksum: int
    locked: int
    offset: int
    header_size: int

    @property
    def is_encrypted(self) -> bool:
        return self.locked != 0

    @property
    def is_compressed(self) -> bool:
        return self.method == "LH5"

    @property
    def is_stored(self) -> bool:
        return self.method in {"NON", "LH0"}


@dataclass(frozen=True)
class SpisBlock:
    index: int
    offset: int
    header: SpisHeader
    payload: bytes


@dataclass(frozen=True)
class BlockSpan:
    index: int
    offset: int
    header: SpisHeader
    payload_offset: int
    payload_size: int
    prefix_offset: int | None = None
    framing: str = "scan-recovery"


@dataclass(frozen=True)
class BlockReport:
    index: int
    offset: int
    method: str
    compressed_size: int
    decompressed_size: int
    archive_type: int
    checksum: int
    locked: int
    output: str | None = None
    prefix_offset: int | None = None
    payload_offset: int | None = None
    end_offset: int | None = None
    framing: str = "scan-recovery"
    checksum_verified: bool | None = None
    checksum_status: str = "not-requested"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
