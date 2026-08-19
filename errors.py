"""Errors raised by the unified vault."""


class VaultError(Exception):
    """Base vault error."""


class VaultAlreadyExists(VaultError):
    pass


class VaultNotInitialized(VaultError):
    pass


class WrongPassword(VaultError):
    pass


class EntryAlreadyExists(VaultError):
    pass


class EntryNotFound(VaultError):
    pass


class CorruptEntry(VaultError):
    pass
