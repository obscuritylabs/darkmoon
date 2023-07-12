from fastapi import HTTPException
from pydantic import BaseModel, Field


class Response(BaseModel):
    """Sets model for other reponse types to inherit from."""

    message: str = Field(
        description="Base response model",
    )


class ServerNotFoundException(HTTPException):
    """Exception raised when the server is not found."""


class ItemNotFoundException(HTTPException):
    """Exception raised when an item is not found."""


class DuplicateFileException(HTTPException):
    """Exception raised when a duplicate file is encountered."""


class IncorrectInputException(HTTPException):
    """Exception raised when a input does not contain proper identifiers."""


class InvalidIDException(HTTPException):
    """Exception raised when an invalid ID is encountered."""
