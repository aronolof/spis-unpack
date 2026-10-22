from __future__ import annotations

import io
from typing import BinaryIO

from .errors import DecodeError


class BitStream:
    def __init__(self, data: bytes | BinaryIO):
        self._source = io.BytesIO(data) if isinstance(data, bytes) else data
        self._data = b""
        self._byte_index = 0
        self._buffer = 0
        self._bits = 0

    def _fill(self, minimum: int) -> None:
        while self._bits < minimum:
            if self._byte_index >= len(self._data):
                self._data = self._source.read(65536)
                self._byte_index = 0
                if not self._data:
                    raise DecodeError("Unexpected end of compressed stream")
            self._buffer = (self._buffer << 8) | self._data[self._byte_index]
            self._byte_index += 1
            self._bits += 8

    def peek(self, count: int) -> int:
        if count < 0:
            raise ValueError("Bit count must be non-negative")
        if count == 0:
            return 0
        self._fill(count)
        return (self._buffer >> (self._bits - count)) & ((1 << count) - 1)

    def drop(self, count: int) -> None:
        if count < 0:
            raise ValueError("Bit count must be non-negative")
        if count == 0:
            return
        self._fill(count)
        self._bits -= count
        if self._bits == 0:
            self._buffer = 0
        else:
            self._buffer &= (1 << self._bits) - 1

    def read(self, count: int) -> int:
        value = self.peek(count)
        self.drop(count)
        return value
