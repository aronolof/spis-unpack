import io

import pytest

from spis_unpack.errors import DecodeError
from spis_unpack.lh5 import LH5Decoder, PrefixDecoder


def bits(*fields):
    text = "".join(f"{value:0{width}b}" for value, width in fields)
    return text


def constant_block(symbol, count=1, position=0):
    return bits((count, 16), (0, 5), (0, 5), (0, 9), (symbol, 9), (0, 4), (position, 4))


def pack(text):
    text += "0" * (-len(text) % 8)
    return int(text, 2).to_bytes(len(text) // 8, "big")


def test_back_reference_distance_and_overlap():
    # Two literals followed by a length-three match at distance two: ABABA.
    data = pack(constant_block(65) + constant_block(66) + constant_block(256, position=1))
    assert LH5Decoder(data).expand(5) == b"ABABA"
    assert list(LH5Decoder(io.BytesIO(data)).iter_expand(5, 2)) == [b"AB", b"AB", b"A"]


def test_dictionary_wrap_and_streaming():
    data = pack(constant_block(65, 20000))
    chunks = list(LH5Decoder(data).iter_expand(20000, 1024))
    assert b"".join(chunks) == b"A" * 20000
    assert max(map(len, chunks)) == 1024


def test_initial_dictionary_and_position_extra_bits():
    data = pack(constant_block(256, position=3) + bits((3, 2)))
    assert LH5Decoder(data).expand(3) == b"   "


@pytest.mark.parametrize(
    "text,size",
    [
        (constant_block(65, 0), 1),
        (constant_block(511), 1),
        (constant_block(256, position=15), 3),
        (constant_block(256), 2),
        (bits((1, 16), (31, 5)), 1),
    ],
)
def test_malformed_streams_raise_decode_error(text, size):
    with pytest.raises(DecodeError):
        LH5Decoder(pack(text)).expand(size)


def test_truncation():
    with pytest.raises(DecodeError):
        LH5Decoder(b"\x00").expand(1)


@pytest.mark.parametrize("lengths", [[1], [1, 1, 1], [2, 2], [17, 17]])
def test_invalid_prefix_tables(lengths):
    with pytest.raises(DecodeError):
        PrefixDecoder.from_lengths(lengths, len(lengths))


def test_nonconstant_huffman_tree():
    text = bits((6, 16), (0, 5), (3, 5), (2, 9), (0, 4), (0, 4)) + "011001"
    assert LH5Decoder(pack(text)).expand(6) == b"\x00\x01\x01\x00\x00\x01"


def test_nonconstant_position_table():
    text = constant_block(65) + constant_block(66)
    text += bits((1, 16), (0, 5), (0, 5), (0, 9), (256, 9), (2, 4), (1, 3), (1, 3), (1, 1))
    assert LH5Decoder(pack(text)).expand(5) == b"ABABA"


def test_thirteen_bit_canonical_codes_keep_distinct_leaves():
    from spis_unpack.bitstream import BitStream

    # A complete canonical tree: lengths 1..12 and two leaves at depth 13.
    decoder = PrefixDecoder.from_lengths(list(range(1, 13)) + [13, 13], 14)
    assert decoder.decode(BitStream(pack("1111111111110"))) == 12
    assert decoder.decode(BitStream(pack("1111111111111"))) == 13
