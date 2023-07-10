class MissingHashException(Exception):
    """Exception raised when a hash is missing."""


class MissingHashTypeException(Exception):
    """Exception raised when a hash type is missing."""


class InvalidIDException(Exception):
    """Exception raised when an invalid ID is encountered."""


class ServerNotFoundException(Exception):
    """Exception raised when the server is not found."""


class ItemNotFoundException(Exception):
    """Exception raised when an item is not found."""


class DuplicateFileException(Exception):
    """Exception raised when a duplicate file is encountered."""
