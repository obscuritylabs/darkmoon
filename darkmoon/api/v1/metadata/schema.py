"""Imports the modules/classes Field, BaseModel, Core Response model, and Optional."""
from beanie import PydanticObjectId
from pydantic import BaseModel, Field

from darkmoon.core.schema import Response


class Hashes(BaseModel):
    """Holds the hash info and is called in MetaData and MetaDataEntity."""

    md5: str | None = Field(
        description="The md5 hash",
        example="5d41402abc4b2a76b9719d911017c592",
    )

    sha1: str | None = Field(
        description="The sha1 hash",
        example="aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    )

    sha256: str | None = Field(
        description="The sha256 hash",
        example="2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    )

    sha512: str | None = Field(
        description="The sha512 hash",
        example="75d527c368f2efe848ecd5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976",
    )


class HeaderInfo(BaseModel):
    """Holds HeaderInfo class properties for .exe files."""

    machine_type: str | None = Field(
        description="The machine type of the .exe file.",
        example="0x14c",
    )

    timestamp: str | None = Field(
        description="timestap of file",
        example="12/2/23 17:57:43",
    )

    compile_time: str | None = Field(
        description="compile time of the file",
        example="",
    )

    signature: str | None = Field(
        description="digital file signature",
        example="",
    )

    rich_header_hashes: Hashes | None = Field(
        description="a dictionary of hashes from the hashes class",
    )


class Metadata(BaseModel):
    """Sets incoming file requirements."""

    name: list[str] = Field(
        description="name of file",
        example=["End_Of_The_World"],
    )
    file_extension: list[str] = Field(
        description="the extension of a file",
        example=[".jpeg"],
    )
    file_type: list[str] = Field(
        description="the type of file",
        example=["exe"],
    )
    hashes: Hashes = Field(
        description="a hash",
    )

    source_iso_name: list[str] = Field(
        description="source ISO name",
        example=[""],
    )

    operating_system: list[str] = Field(
        description="The operating system of the computer"
        " where the file is coming from.",
        example=["WindowsXP"],
    )

    header_info: HeaderInfo | None = Field(
        description="contains all the header information",
    )


class MetadataEntity(BaseModel):
    """Sets outgoing file requirements."""

    id: PydanticObjectId = Field(
        description="ID",
        example="1",
        alias="_id",
    )
    name: list[str] = Field(
        description="name of file",
        example=["End_Of_The_World"],
    )
    file_extension: list[str] = Field(
        description="the extension of a file",
        example=[".jpeg"],
    )

    file_type: list[str] = Field(
        description="the type of file",
        example=["exe"],
    )

    hashes: Hashes = Field(
        description="a hash",
    )
    source_iso_name: list[str] = Field(
        description="source ISO name",
        example=[""],
    )

    operating_system: list[str] = Field(
        description="The operating system of the computer"
        " where the file is coming from.",
        example=["WindowsXP"],
    )

    header_info: HeaderInfo | None = Field(
        description="contains all the header information",
        example="",
    )


class UploadResponse(Response):
    """Sets upload response requirements."""

    data: Metadata = Field(
        description="The object inserted or updated on the database",
    )
