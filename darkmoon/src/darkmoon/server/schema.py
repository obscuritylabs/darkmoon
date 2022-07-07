"""Imports the modules."""
from datetime import datetime

from pydantic import BaseModel, Field


class HeaderInfo(BaseModel):
    """Creates the HeaderInfo class, used in both Incoming Files and Outgoing Files."""

    architecture: str = Field(
        description="",
        example="",
    )
    timestap: datetime = Field(
        description="",
        example="",
    )
    compile_time: float = Field(
        description="",
        example="",
    )
    signature: str = Field(
        description="",
        example="",
    )


class IncomingFiles(BaseModel):
    """Creates the incoming files class."""

    name: str = Field(
        description="name of file",
        example="End_Of_The_World",
    )
    file_extention: str = Field(
        description="the extension of a file",
        example=".jpeg",
    )
    hashes: list[str] = Field(
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
    header_info: HeaderInfo = Field(
        description="contains all the header information",
        example="",
    )


class OutgoingFiles(BaseModel):
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
    hashes: list[str] = Field(
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
    header_info: HeaderInfo = Field(
        description="contains all the header information",
        example="",
    )
