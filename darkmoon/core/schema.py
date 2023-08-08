from fastapi import HTTPException
from pydantic import BaseModel, Field


class Response(BaseModel):
    """Sets model for other reponse types to inherit from."""

    message: str = Field(
        description="Base response model",
    )


class ValidationError(Exception):
    """Error thrown when a given packer template is invalid."""


class ServerNotFoundException(HTTPException):
    """Exception raised when the server is not found."""


class ItemNotFoundException(HTTPException):
    """Exception raised when an item is not found."""


class DuplicateFileException(HTTPException):
    """Exception raised when a duplicate file is encountered."""


class IncorrectInputException(HTTPException):
    """Exception raised when a input does not contain proper identifiers."""


class ExtractionError(Exception):
    """An error raised when 7zip is unable to extract a file."""


class InternalServerException(HTTPException):
    """Exception raised when a problem occurs internally."""
