"""Imports the modules."""
from pydantic import BaseModel, Field


class Incoming_Files(BaseModel):
    """Creates the incoming files class."""

    name: str = Field(
        description="name of file",
        example="End_Of_The_World",
    )
    file_extention: str = Field(
        description="the extension of a file",
        example=".jpeg",
    )
    hashes: str = Field(
        description="a hash",
        example="",
    )
    source_ISO_name: str = Field(
        description="",
        example="",
    )
    source_ISO_hash: str = Field(
        description="",
        example="",
    )
    header_info = {"architecture": str, "timestap": str, "compile_time": str, "signature": str}


class Outgoing_Files(BaseModel):
    """Creates the outoging files class."""

    id: str = Field(
        description="ID",
        example="1",
    )
    name: str = Field(
        description="name of file",
        example="End_Of_The_World",
    )
    file_extention: str = Field(
        description="the extension of a file",
        example=".jpeg",
    )
    hashes: str = Field(
        description="a hash",
        example="",
    )
    source_ISO_name: str = Field(
        description="",
        example="",
    )
    source_ISO_hash: str = Field(
        description="",
        example="",
    )
    header_info = {"architecture": str, "timestap": str, "compile_time": str, "signature": str}
