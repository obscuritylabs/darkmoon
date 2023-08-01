import hashlib
import tarfile
import tempfile
from pathlib import Path
from typing import Annotated

import typer
from beanie import PydanticObjectId
from fastapi import Depends, Query
from motor.motor_asyncio import AsyncIOMotorCollection

from darkmoon.cli.main import iterate_files
from darkmoon.common.schema import (
    Hashes,
    MetadataEntity,
    UploadListMetadataEntityResponse,
)
from darkmoon.core.database import get_file_metadata_collection


def extract(
    file: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    source_iso: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    darkmoon_server_url: Path,
) -> None:
    """Extract vmdk and put in new folder."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        with tarfile.open(file) as f:
            f.extractall(tmpdirname)
        iterate_files(Path(tmpdirname), source_iso, darkmoon_server_url)


async def hash_comparison(
    fileInput: Path,
    collection: AsyncIOMotorCollection = Depends(get_file_metadata_collection),
    page: int = Query(
        0,
        ge=0,
        le=18446744073709552,
        description="The page to iterate to.",
    ),
    length: int = Query(10, ge=1, le=500),
) -> UploadListMetadataEntityResponse:
    """Fast API POST function to search database with an input file.

    Parameters:
        file (UploadFile): The file that the use inputs.
        collection (AsyncIOMotorCollection) : The database collection to query.

    Returns:
        response (UploadListMetadataEntityResponse): return a list[MetadataEntity] or
        raise an exception.

    Raises:
        ServerNotFoundException:
            Endpoint is unable to connect to mongoDB instance
    """
    inputFileName = str(fileInput.name)

    data = fileInput.read_bytes()
    h_md5 = hashlib.md5()  # noqa S324
    h_sha1 = hashlib.sha1()  # noqa: S324: dS324
    h_sha256 = hashlib.sha256()
    h_sha512 = hashlib.sha512()
    h_md5.update(data)
    h_sha1.update(data)
    h_sha256.update(data)
    h_sha512.update(data)
    md5Hash = h_md5.hexdigest()
    sha1Hash = h_sha1.hexdigest()
    sha256Hash = h_sha256.hexdigest()
    sha512Hash = h_sha512.hexdigest()

    search_query = {
        "name": inputFileName,
    }

    results = await collection.find(search_query).to_list(length=length)
    li = [MetadataEntity.parse_obj(item) for item in results]
    if len(li) == 0:
        obj = MetadataEntity(
            _id=PydanticObjectId(),
            name=[inputFileName],
            file_type=[],
            operating_system=[],
            source_iso_name=[],
            file_extension=[""],
            hashes=Hashes(
                md5=md5Hash,
                sha1=sha1Hash,
                sha256=sha256Hash,
                sha512=sha512Hash,
            ),
            header_info=None,
        )
        li.append(obj)
        return UploadListMetadataEntityResponse(
            message="No results found in database.",
            data=li,
        )
    return UploadListMetadataEntityResponse(
        message="Database results available",
        data=li,
    )
