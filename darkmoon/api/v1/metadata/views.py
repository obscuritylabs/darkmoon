"""Defines an API router for handling metadata related requests."""

import bson
from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, Query, status
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import errors

from darkmoon.api.v1.metadata.schema import Metadata, MetadataEntity, UploadResponse
from darkmoon.core.database import get_file_metadata_collection
from darkmoon.core.schema import (
    DuplicateFileException,
    IncorrectInputException,
    ItemNotFoundException,
    ServerNotFoundException,
)

router = APIRouter(prefix="/metadata", tags=["metadata"])


@router.get(
    "/",
    responses={
        422: {"Client Error Response": "Unprocessable Content"},
        504: {"Server Error Response": "Gateway Timeout"},
    },
)
async def list_metadata(
    fullHash: str = Query(example="sha256:sdlkfjksldklsdjsdfklj"),
    collection: AsyncIOMotorCollection = Depends(get_file_metadata_collection),
    file_name: str | None = None,
    page: int = Query(
        0,
        ge=0,
        le=18446744073709552,
        description="The page to iterate to.",
    ),
    length: int = Query(10, ge=1, le=500),
) -> list[MetadataEntity]:
    """Get list of metadata that matches the parameters in the database.

    Parameters:
        collection (AsyncIOMotorCollection): The database collection to query.
        file_name (str): The name of the file being searched.
        fullHash (str): The hash of the file.
        page (int): The page number to iterate to.
        length (int): The number of items per page.

    Returns:
        List[MetadataEntity]: List of all documents that match parameters in the
            database.

    Raises:
        ServerNotFoundException: Endpoint is unable to connect to mongoDB instance
        IncorrectInputException: Provided document is missing information or
            uses invalid characters
    """
    split = fullHash.split(":")
    if len(split) != 2 or ":" not in fullHash:
        raise IncorrectInputException(
            status_code=422,
            detail=(
                "Format hash information like this: ",
                "sha256:94dfb9048439d49490de0a00383e2b0183676cbd56d8c1f4432b5d2f17390621",
            ),
        )
    hash_type = str(split[0])
    hash = str(split[1])
    try:
        hash.encode("UTF-8")
        hash_type.encode("UTF-8")
    except UnicodeEncodeError:
        raise IncorrectInputException(
            status_code=422,
            detail=("Input contains invalid characters"),
        )

    if "\x00" in hash or "\x00" in hash_type or hash.isspace() or hash_type.isspace():
        raise IncorrectInputException(
            status_code=422,
            detail=("Input contains invalid characters"),
        )

    search = {}

    try:
        if file_name:
            search["name"] = file_name
        if hash and hash_type:
            hash_parameter = "hashes." + str(hash_type)
            search[hash_parameter] = hash
        elif hash_type:
            raise IncorrectInputException(status_code=422, detail="Enter hash.")
        elif hash:
            raise IncorrectInputException(status_code=422, detail="Enter hash type.")

        data = await collection.find(search).skip(page * length).to_list(length=length)  # type: ignore # noqa
        return [MetadataEntity.parse_obj(item) for item in data]

    except errors.ServerSelectionTimeoutError:
        raise ServerNotFoundException(status_code=504, detail="Server timed out.")


@router.get(
    "/{id}",
    responses={
        400: {"Client Error Response": "Bad Request"},
        404: {"Client Error Response": "Not Found"},
        500: {"Server Error Response": "Internal Server Error"},
    },
)
async def get_metadata_by_id(
    id: PydanticObjectId,
    collection: AsyncIOMotorCollection = Depends(get_file_metadata_collection),
) -> MetadataEntity:
    """Find file by ObjectID in MongoDB.

    Parameters:
        id (str): Unique id of specific entry in MongoDB
        collection (AsyncIOMotorCollection) : The database collection to query.

    Returns:
        document (MetadataEntity): Return the database entry with
            matching id or raise 400, 404, or 500 error.

    Raises:
        ItemNotFoundException:
            no item with the provided ID is in the database
        ServerNotFoundException:
            Endpoint is unable to connect to mongoDB instance

    """
    try:
        doc = await collection.find_one({"_id": id})
        if doc:
            document = MetadataEntity(**doc)
        else:
            raise ItemNotFoundException(status_code=404, detail="Item not found.")

        return document

    except errors.ServerSelectionTimeoutError:
        raise ServerNotFoundException(status_code=504, detail="Server timed out.")

    except bson.errors.InvalidId:  # type: ignore
        raise ItemNotFoundException(status_code=404, detail="Item not found, check ID.")


@router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {"Client Error Response": "Conflict"},
        422: {"Client Error Response": "Unprocessable Content"},
        500: {"Server Error Response": "Internal Server Error"},
    },
)
async def upload_metadata(
    file: Metadata,
    collection: AsyncIOMotorCollection = Depends(get_file_metadata_collection),
) -> UploadResponse:
    """Fast API POST function for incoming files.

    Parameters:
        file (Metadata): The file that is uploaded to the database.
        collection (AsyncIOMotorCollection) : The database collection to query.

    Returns:
        response (UploadResponse): return a copy of the uploaded file
            or raise 409, 422, or 500 error.

    Raises:
        DuplicateFileException:
            A file already exists in the database with this information
        IncorrectInputException:
            Provided document is missing information or
            uses invalid characters
        ServerNotFoundException:
            Endpoint is unable to connect to mongoDB instance
    """
    file_metadata = file.dict()
    try:
        duplicate_hashes = {
            "hashes.md5": file_metadata["hashes"]["md5"],
            "hashes.sha1": file_metadata["hashes"]["sha1"],
            "hashes.sha256": file_metadata["hashes"]["sha256"],
            "hashes.sha512": file_metadata["hashes"]["sha512"],
        }
        check_dup = {
            "name": file_metadata["name"][0],
            "file_extension": file_metadata["file_extension"][0],
            "file_type": file_metadata["file_type"][0],
            "hashes": file_metadata["hashes"],
            "source_iso_name": file_metadata["source_iso_name"][0],
            "operating_system": file_metadata["operating_system"][0],
            "header_info": file_metadata["header_info"],
        }
    except IndexError:
        raise IncorrectInputException(status_code=422, detail=["Input missing"])

    try:
        dup = await collection.find_one(check_dup)
        if dup:
            raise DuplicateFileException(status_code=409, detail="File is a duplicate.")

        doc = await collection.find_one(duplicate_hashes)
        if doc:
            document = MetadataEntity(**doc)

            data_type = [
                document.name,
                document.file_extension,
                document.file_type,
                document.source_iso_name,
                document.operating_system,
            ]
            data_type_string = [
                "name",
                "file_extension",
                "file_type",
                "source_iso_name",
                "operating_system",
            ]
            for index in range(len(data_type)):
                if file_metadata[data_type_string[index]][0] not in data_type[index]:
                    data_type[index].append(file_metadata[data_type_string[index]][0])

            change = {
                "$set": {
                    "name": data_type[0],
                    "file_extension": data_type[1],
                    "file_type": data_type[2],
                    "source_iso_name": data_type[3],
                    "operating_system": data_type[4],
                },
            }
            await collection.update_one(duplicate_hashes, change)
            return UploadResponse(message="Successfully Updated Object.", data=file)

        else:
            await collection.insert_one(file_metadata)
            return UploadResponse(message="Successfully Inserted Object.", data=file)

    except errors.ServerSelectionTimeoutError:
        raise ServerNotFoundException(status_code=500, detail="Server not found.")
    except UnicodeEncodeError:
        raise IncorrectInputException(
            status_code=422,
            detail=("Input contains invalid characters"),
        )
