from __future__ import annotations


class SpisError(Exception):
    pass


class ParseError(SpisError):
    pass


class DecodeError(SpisError):
    pass


class UnsupportedMethodError(DecodeError):
    pass


class EncryptedBlockError(DecodeError):
    pass
