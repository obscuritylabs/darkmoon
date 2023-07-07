class Missing_Hash_Exception(Exception):
    """Exception raised when a hash is missing.

    Attributes:
        code (int): The error code associated with the exception (400).
        detail (str): The details of the exception.
    """

    def __init__(self) -> None:
        self.code = 400
        self.detail = "Enter Hash"


class Missing_Hash_Type_Exception(Exception):
    """Exception raised when a hash type is missing.

    Attributes:
        code (int): The error code associated with the exception (400).
        detail (str): The details of the exception.
    """

    def __init__(self) -> None:
        self.code = 400
        self.detail = "Enter hash type"


class Invalid_ID_Exception(Exception):
    """Exception raised when an invalid ID is encountered.

    Attributes:
        code (int): The error code associated with the exception (400).
        detail (tuple): The details of the exception, containing two strings:
            - The first string indicates that the ID is not valid.
            - The second string specifies the valid ID format requirements.
    """

    def __init__(self) -> None:
        self.code = 400
        self.detail = (
            "This is not a valid ID",
            "It must be a 12-byte input or a 24-character hex string.",
        )


class Server_Not_Found_Exception(Exception):
    """Exception raised when the server is not found.

    Attributes:
        code (int): The error code associated with the exception (408).
        detail (str): The details of the exception.
    """

    def __init__(self) -> None:
        self.code = 408
        self.detail = (
            "The computer can't find the server.",
            "Check the IP Address and the server name.",
        )


class Item_Not_Found_Exception(Exception):
    """Exception raised when an item is not found.

    Attributes:
        code (int): The error code associated with the exception (404).
        detail (str): The details of the exception.
    """

    def __init__(self) -> None:
        self.code = 404
        self.detail = "Item not found"


class Duplicate_File_Exception(Exception):
    """Exception raised when a duplicate file is encountered.

    Attributes:
        code (int): The error code associated with the exception (409).
        detail (str): The details of the exception.
    """

    def __init__(self) -> None:
        self.code = 409
        self.detail = "There is a duplicate file."
