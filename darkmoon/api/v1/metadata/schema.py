"""Imports the modules/classes Field, BaseModel, Core Response model, and Optional."""

from typing import Literal

from beanie import PydanticObjectId
from pydantic import BaseModel, Field, validator

from darkmoon.core.schema import Response


class Hashes(BaseModel):
    """Holds the hash info and is called in MetaData and MetaDataEntity."""

    md5: str = Field(
        description="The md5 hash",
        example="5d41402abc4b2a76b9719d911017c592",
    )

    sha1: str = Field(
        description="The sha1 hash",
        example="aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    )

    sha256: str = Field(
        description="The sha256 hash",
        example="2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    )

    sha512: str = Field(
        description="The sha512 hash",
        example="75d527c368f2efe848ecd5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976",
    )


class HeaderInfo(BaseModel):
    """Holds HeaderInfo class properties for .exe files."""

    machine_type: str = Field(
        description="The machine type of the .exe file.",
        example="0x14c",
    )

    timestamp: str = Field(
        description="timestap of file",
        example="12/2/23 17:57:43",
    )

    compile_time: str = Field(
        description="compile time of the file",
        example="comp time",
    )

    signature: str = Field(
        description="digital file signature",
        example="signature",
    )

    rich_header_hashes: Hashes = Field(
        description="a dictionary of hashes from the hashes class",
    )


class BaseMetadata(BaseModel):
    """Sets incoming file requirements."""

    name: list[str] = Field(
        description="name of file",
        example=["End_Of_The_World"],
        min_items=1,
    )

    file_extension: list[str] = Field(
        description="the extension of a file",
        example=[".jpeg"],
        min_items=1,
    )

    file_type: list[str] = Field(
        description="the type of file",
        example=["exe"],
        min_items=1,
    )

    hashes: Hashes = Field(
        description="a hash",
    )

    source_iso_name: list[str] = Field(
        description="source ISO name",
        example=["Win_XP"],
        min_items=1,
    )

    operating_system: list[str] = Field(
        description="The operating system of the computer"
        " where the file is coming from.",
        example=["WindowsXP"],
        min_items=1,
    )

    @validator(
        "name",
        "file_extension",
        "file_type",
        "source_iso_name",
        "operating_system",
    )
    def validate_input(cls, input: list[str]) -> list[str]:
        """Ensure all data in an uploaded file uses proper UTF-8 characters."""
        for value in input:
            try:
                value.encode("UTF-8")

            except UnicodeEncodeError:
                raise ValueError

        return input


class EXEMetadata(BaseMetadata):
    """Sets incoming EXE file requirements."""

    base_file_type: Literal["exe"] = Field(example="exe")

    header_info: HeaderInfo = Field(
        description="contains all the header information",
    )


class DocMetadata(BaseMetadata):
    """Sets incoming Doc file requirements."""

    base_file_type: Literal["doc"] = Field(example="doc")


class Metadata(BaseModel):
    """Sets incoming file requirements."""

    __root__: EXEMetadata | DocMetadata = Field(
        ...,
        discriminator="base_file_type",
    )


class EXEMetadataEntity(EXEMetadata):
    """Sets outgoing EXE file requirements."""

    base_file_type: Literal["exe"] = Field(example="exe")
    id: PydanticObjectId = Field(
        description="ID",
        example="1",
        alias="_id",
    )


class DocMetadataEntity(DocMetadata):
    """Sets outgoing Doc file requirements."""

    base_file_type: Literal["doc"] = Field(example="doc")
    id: PydanticObjectId = Field(
        description="ID",
        example="1",
        alias="_id",
    )


class MetadataEntity(BaseModel):
    """Sets outgoing file requirements."""

    __root__: DocMetadataEntity | EXEMetadataEntity = Field(
        ...,
        disciminator="base_file_type",
    )


class UploadMetadataResponse(Response):
    """Sets upload response requirements."""

    data: Metadata = Field(
        description="The object inserted or updated on the database",
    )


class UploadListMetadataEntityResponse(Response):
    """Sets upload response requirements."""

    data: list[MetadataEntity] = Field(
        description="The object inserted or updated on the database",
    )


class DatabaseUpload(BaseModel):
    """Return type forr when file metadata is posted to the database."""

    operation: Literal["created"] | Literal["updated"] | Literal["conflict"] = Field(
        description="The database operation performed",
    )
    data: Metadata = Field(
        description="The object inserted or updated on the database",
    )
