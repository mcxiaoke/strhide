"""Exceptions module for strhide."""


class StrHideError(Exception):
    """Base exception for all strhide errors."""
    pass


class RejectionError(StrHideError):
    """Raised when a host file cannot or should not be modified due to integrity/signature."""
    pass


class CorruptedDataError(StrHideError):
    """Raised when envelope, chunk, or trailer structure is corrupted or modified."""
    pass


class PasswordError(StrHideError):
    """Raised when decryption fails due to invalid password or corrupted ciphertext."""
    pass


class UnsupportedFormatError(StrHideError):
    """Raised when a file format or requested strategy is not supported."""
    pass


class RestoreMismatchError(StrHideError):
    """Raised when restored file SHA-256 does not match original host SHA-256."""
    pass
