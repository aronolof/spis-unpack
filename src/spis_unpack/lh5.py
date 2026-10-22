from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO, Iterator

from .bitstream import BitStream
from .errors import DecodeError

DICTIONARY_BITS = 13
DICTIONARY_SIZE = 1 << DICTIONARY_BITS
MAX_MATCH = 256
MIN_MATCH = 3
CHAR_MAX = 255
NC = CHAR_MAX + MAX_MATCH + 2 - MIN_MATCH
NP = DICTIONARY_BITS + 1
NT = 19
CBIT = 9
PBIT = 4
TBIT = 5


@dataclass(frozen=True)
class PrefixDecoder:
    constant: int | None
    nodes: tuple[tuple[int | None, int | None], ...]

    @classmethod
    def from_lengths(cls, lengths: list[int], symbol_count: int) -> "PrefixDecoder":
        active = [
            (symbol, length) for symbol, length in enumerate(lengths[:symbol_count]) if length > 0
        ]
        if not active:
            raise DecodeError("Empty Huffman table")
        counts = [0] * 17
        for _, length in active:
            if length > 16:
                raise DecodeError("Unsupported Huffman code length")
            counts[length] += 1

        code = 0
        next_code = [0] * 17
        for bit_length in range(1, 17):
            code = (code + counts[bit_length - 1]) << 1
            next_code[bit_length] = code
        if code + counts[16] != 1 << 16:
            raise DecodeError("Incomplete or oversubscribed Huffman table")

        mutable_nodes: list[list[int | None]] = [[None, None]]
        for symbol, length in active:
            codeword = next_code[length]
            next_code[length] += 1
            node_index = 0
            for shift in range(length - 1, -1, -1):
                bit = (codeword >> shift) & 1
                branch = mutable_nodes[node_index][bit]
                if shift == 0:
                    if branch is not None:
                        raise DecodeError("Conflicting Huffman table")
                    mutable_nodes[node_index][bit] = -(symbol + 1)
                    continue
                if branch is None:
                    mutable_nodes.append([None, None])
                    branch = len(mutable_nodes) - 1
                    mutable_nodes[node_index][bit] = branch
                elif branch < 0:
                    raise DecodeError("Conflicting Huffman table")
                node_index = branch

        nodes = tuple((left, right) for left, right in mutable_nodes)
        return cls(constant=None, nodes=nodes)

    def decode(self, stream: BitStream) -> int:
        if self.constant is not None:
            return self.constant

        node_index = 0
        while True:
            bit = stream.read(1)
            branch = self.nodes[node_index][bit]
            if branch is None:
                raise DecodeError("Invalid Huffman stream")
            if branch < 0:
                return -branch - 1
            node_index = branch


class LH5Decoder:
    def __init__(self, data: bytes | BinaryIO):
        self._stream = BitStream(data)
        self._block_symbols_remaining = 0
        self._char_decoder: PrefixDecoder | None = None
        self._position_decoder: PrefixDecoder | None = None

    def expand(self, expected_size: int) -> bytes:
        return b"".join(self.iter_expand(expected_size))

    def iter_expand(self, expected_size: int, chunk_size: int = 65536) -> Iterator[bytes]:
        if expected_size < 0 or chunk_size < 1:
            raise ValueError("Expected size must be non-negative and chunk size positive")
        output = bytearray()
        window = bytearray(b" " * DICTIONARY_SIZE)
        write_index = 0
        produced = 0

        while produced < expected_size:
            symbol = self._decode_symbol()
            if symbol < 256:
                byte = symbol
                output.append(byte)
                window[write_index] = byte
                write_index = (write_index + 1) % DICTIONARY_SIZE
                produced += 1
                if len(output) >= chunk_size:
                    yield bytes(output)
                    output.clear()
                continue

            length = symbol - 256 + MIN_MATCH
            if produced + length > expected_size:
                raise DecodeError("Match exceeds declared output size")
            distance = self._decode_position() + 1
            for _ in range(length):
                byte = window[(write_index - distance) % DICTIONARY_SIZE]
                output.append(byte)
                window[write_index] = byte
                write_index = (write_index + 1) % DICTIONARY_SIZE
                produced += 1
                if len(output) >= chunk_size:
                    yield bytes(output)
                    output.clear()
        if output:
            yield bytes(output)

    def _decode_symbol(self) -> int:
        if self._block_symbols_remaining == 0:
            self._start_block()
        self._block_symbols_remaining -= 1
        assert self._char_decoder is not None
        return self._char_decoder.decode(self._stream)

    def _decode_position(self) -> int:
        assert self._position_decoder is not None
        slot = self._position_decoder.decode(self._stream)
        if slot == 0:
            return 0
        return (1 << (slot - 1)) + self._stream.read(slot - 1)

    def _start_block(self) -> None:
        self._block_symbols_remaining = self._stream.read(16)
        if self._block_symbols_remaining == 0:
            raise DecodeError("Empty LH5 symbol block")
        temp_decoder = self._read_position_decoder(symbol_count=NT, width=TBIT, special_index=3)
        self._char_decoder = self._read_char_decoder(temp_decoder)
        self._position_decoder = self._read_position_decoder(symbol_count=NP, width=PBIT)

    def _read_position_decoder(
        self,
        symbol_count: int,
        width: int,
        special_index: int | None = None,
    ) -> PrefixDecoder:
        used = self._stream.read(width)
        if used == 0:
            symbol = self._stream.read(width)
            if symbol >= symbol_count:
                raise DecodeError("Invalid constant Huffman symbol")
            return PrefixDecoder(constant=symbol, nodes=())
        if used > symbol_count:
            raise DecodeError("Huffman table exceeds symbol count")

        lengths = [0] * symbol_count
        index = 0
        while index < used:
            code_length = self._read_length_code()
            lengths[index] = code_length
            index += 1
            if special_index is not None and index == special_index:
                zero_count = self._stream.read(2)
                if index + zero_count > used:
                    raise DecodeError("Huffman zero run exceeds table")
                for _ in range(zero_count):
                    if index >= symbol_count:
                        break
                    lengths[index] = 0
                    index += 1

        return PrefixDecoder.from_lengths(lengths, symbol_count)

    def _read_char_decoder(self, temp_decoder: PrefixDecoder) -> PrefixDecoder:
        used = self._stream.read(CBIT)
        if used == 0:
            symbol = self._stream.read(CBIT)
            if symbol >= NC:
                raise DecodeError("Invalid constant character symbol")
            return PrefixDecoder(constant=symbol, nodes=())
        if used > NC:
            raise DecodeError("Character table exceeds symbol count")

        lengths = [0] * NC
        index = 0
        while index < used:
            symbol = temp_decoder.decode(self._stream)
            if symbol <= 2:
                if symbol == 0:
                    zero_count = 1
                elif symbol == 1:
                    zero_count = self._stream.read(4) + 3
                else:
                    zero_count = self._stream.read(CBIT) + 20
                if index + zero_count > used:
                    raise DecodeError("Character zero run exceeds table")
                for _ in range(zero_count):
                    if index >= NC:
                        break
                    lengths[index] = 0
                    index += 1
                continue
            lengths[index] = symbol - 2
            index += 1

        return PrefixDecoder.from_lengths(lengths, NC)

    def _read_length_code(self) -> int:
        prefix = self._stream.read(3)
        if prefix < 7:
            return prefix
        extra = 0
        while self._stream.read(1) == 1:
            extra += 1
            if prefix + extra > 16:
                raise DecodeError("Unsupported Huffman code length")
        return prefix + extra
