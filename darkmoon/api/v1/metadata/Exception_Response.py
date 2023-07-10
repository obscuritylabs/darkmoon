class Missing_Hash_Exception(Exception):
    """Exception raised when a hash is missing."""


class Missing_Hash_Type_Exception(Exception):
    """Exception raised when a hash type is missing."""


class Invalid_ID_Exception(Exception):
    """Exception raised when an invalid ID is encountered."""


class Server_Not_Found_Exception(Exception):
    """Exception raised when the server is not found."""


class Item_Not_Found_Exception(Exception):
    """Exception raised when an item is not found."""


class Duplicate_File_Exception(Exception):
    """Exception raised when a duplicate file is encountered."""
