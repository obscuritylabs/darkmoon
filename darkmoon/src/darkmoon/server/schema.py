"""Imports the modules/classes Field, BaseModel, and datetime."""

from pydantic import BaseModel, Field


class HeaderInfo(BaseModel):
    """Creates the HeaderInfo class, used in both Incoming Files and Outgoing Files."""

    architecture: str = Field(
        description="architecture of the file",
        example="",
    )
    timestamp: str = Field(
        description="timestap of file",
        example="12/2/23 17:57:43",
    )
    compile_time: str = Field(
        description="compile time of the file",
        example="",
    )
    signature: str = Field(
        description="digital file signature",
        example="",
    )


class IncomingFiles(BaseModel):
    """Sets incoming file requirements."""

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
        example=["8743b52063cd84097a65d1633f5c74f5", "8743b52063cd84097a65d1633f5c74f5"],
    )
    source_ISO_name: str = Field(
        description="source ISO name",
        example="",
    )
    source_ISO_hash: list[str] = Field(
        description="source ISO hash",
        example=["8743b52063cd84097a65d1633f5c74f5", "8743b52063cd84097a65d1633f5c74f5"],
    )
    header_info: HeaderInfo = Field(
        description="contains all the header information",
    )


class OutgoingFiles(BaseModel):
    """Sets outgoing file requirements."""

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
        example=["8743b52063cd84097a65d1633f5c74f5", "8743b52063cd84097a65d1633f5c74f5"],
    )
    source_ISO_name: str = Field(
        description="source ISO name",
        example="",
    )
    source_ISO_hash: list[str] = Field(
        description="source ISO hash",
        example=["8743b52063cd84097a65d1633f5c74f5", "8743b52063cd84097a65d1633f5c74f5"],
    )
    header_info: HeaderInfo = Field(
        description="contains all the header information",
        example="",
    )
