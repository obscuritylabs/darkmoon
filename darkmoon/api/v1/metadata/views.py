"""Defines an API router for handling metadata related requests."""
import tempfile
from pathlib import Path, Path as PyPath
from typing import Annotated

import bson
from beanie import PydanticObjectId
from fastapi import (
    APIRouter,
    Body,
    Depends,
    File,
    Form,
    Query,
    Response,
    UploadFile,
    status,
)
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import errors

from darkmoon.api.v1.metadata.schema import (
    CounterResponse,
    Metadata,
    MetadataEntity,
    UploadListMetadataEntityResponse,
    UploadMetadataResponse,
)
from darkmoon.common import utils
from darkmoon.common.utils import upload_metadata_to_database
from darkmoon.core.database import (
    get_file_metadata_collection,
    get_suspicious_file_metadata_collection,
)
from darkmoon.core.schema import (
    DuplicateFileException,
    ExtractionError,
    IncorrectInputException,
    InternalServerException,
    ItemNotFoundException,
    ServerNotFoundException,
)

router = APIRouter(prefix="/metadata", tags=["metadata"])


@router.get(
    "/hash-search",
    responses={
        422: {"Client Error Response": "Unprocessable Content"},
        504: {"Server Error Response": "Gateway Timeout"},
        400: {"Client Error Response": "Bad Request"},
        404: {"Client Error Response": "Result Not Found"},
    },
)
async def get_hash_search(
    fullHash: str = Query(
        example="sha256:94dfb9048439d49490de0a00383e2b0183676cbd56d8c1f4432b5d2f17390621",
    ),
    collection: AsyncIOMotorCollection = Depends(get_file_metadata_collection),
    file_name: str | None = None,
    page: int = Query(
        0,
        ge=0,
        le=100000,
        description="The page to iterate to.",
    ),
    length: int = Query(10, ge=1, le=500),
) -> UploadListMetadataEntityResponse:
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
                "Format hash information like this: "
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

        data = await collection.find(search).skip(page * length).to_list(length=length)

        out: list[MetadataEntity] = [MetadataEntity.parse_obj(item) for item in data]
        if len(out) == 0:
            raise IncorrectInputException(
                status_code=404,
                detail=("No database results available "),
            )
        else:
            return UploadListMetadataEntityResponse(
                data=out,
                message="Results available.",
            )
    except errors.ServerSelectionTimeoutError:
        raise ServerNotFoundException(status_code=504, detail="Server timed out.")


@router.get(
    "/suspicious-metadata",
    responses={
        422: {"Client Error Response": "Unprocessable Content"},
        504: {"Server Error Response": "Gateway Timeout"},
    },
)
async def get_suspicious_metadata(
    collection: AsyncIOMotorCollection = Depends(
        get_suspicious_file_metadata_collection,
    ),
    page: int = Query(
        0,
        ge=0,
        le=100000,
        description="The page to iterate to.",
    ),
    length: int = Query(10, ge=1, le=500),
) -> UploadListMetadataEntityResponse:
    """Get list of suspicious metadata that matches the parameters in the database.

    Parameters:
        collection (AsyncIOMotorCollection): The database collection to query.
        page (int): The page number to iterate to.
        length (int): The number of items per page.

    Returns:
        List[MetadataEntity]: List of all documents that match parameters in the
            database.

    Raises:
        ServerNotFoundException: Endpoint is unable to connect to mongoDB instance
    """
    try:
        data = await collection.find({}).skip(page * length).to_list(length=length)
        out: list[MetadataEntity] = [MetadataEntity.parse_obj(item) for item in data]
        if len(out) == 0:
            return UploadListMetadataEntityResponse(
                data=[],
                message="No Results Found.",
            )
        return UploadListMetadataEntityResponse(data=out, message="Results Available")

    except errors.ServerSelectionTimeoutError:
        raise ServerNotFoundException(status_code=504, detail="Server timed out.")


@router.get(
    "/",
    responses={
        422: {"Client Error Response": "Unprocessable Content"},
        504: {"Server Error Response": "Gateway Timeout"},
        400: {"Client Error Response": "Bad Request"},
    },
)
async def list_metadata(
    collection: AsyncIOMotorCollection = Depends(get_file_metadata_collection),
    page: int = Query(
        0,
        ge=0,
        le=100000,
        description="The page to iterate to.",
    ),
    length: int = Query(10, ge=1, le=500),
) -> UploadListMetadataEntityResponse:
    """Get list of metadata that matches the parameters in the database.

    Parameters:

        collection (AsyncIOMotorCollection): The database collection to query.

        page (int): The page number to iterate to.

        length (int): The number of items per page.



    Returns:
        List[MetadataEntity]: List of all documents that match parameters in the

            database.



    Raises:
        ServerNotFoundException: Endpoint is unable to connect to mongoDB instance

    """
    try:
        data = await collection.find({}).skip(page * length).to_list(length=length)
        out = [MetadataEntity.parse_obj(item) for item in data]
        if len(out) == 0:
            return UploadListMetadataEntityResponse(
                data=[],
                message="No results found.",
            )
        return UploadListMetadataEntityResponse(data=out, message="Results available.")

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
            document = MetadataEntity.parse_obj(doc)
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
        201: {"Successful Response": "Created"},
        409: {"Client Error Response": "Conflict"},
        422: {"Client Error Response": "Unprocessable Content"},
        500: {"Server Error Response": "Internal Server Error"},
    },
)
async def upload_metadata(
    file: Metadata = Body(
        example={
            "name": ["End_Of_The_World"],
            "file_extension": [".jpeg"],
            "file_type": ["exe"],
            "hashes": {
                "md5": "5d41402abc4b2a76b9719d",
                "sha1": "aaf4c61ddcc5e8a2dabede0f3b",
                "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c",
                "sha512": "75d527c368f2efe848ecd5f984f036eb6df891d75f72d9b154518c1",
            },
            "source_iso_name": ["Win_XP"],
            "operating_system": ["WindowsXP"],
            "base_file_type": "exe",
            "header_info": {
                "machine_type": "0x14c",
                "timestamp": "12/2/23 17:57:43",
                "compile_time": "comp time",
                "signature": "signature",
                "rich_header_hashes": {
                    "md5": "5d41402abc4b2a76b9719d",
                    "sha1": "aaf4c61ddcc5e8a2dabede0f3b",
                    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c",
                    "sha512": "75d527c368f2efe848ecd5f984f036eb6df891d75f72d9b154518c1",
                },
            },
        },
    ),
    collection: AsyncIOMotorCollection = Depends(get_file_metadata_collection),
) -> UploadMetadataResponse:
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
    try:
        result = await upload_metadata_to_database(collection=collection, file=file)
        match result.operation:
            case "created":
                return UploadMetadataResponse(
                    message="Created metadata entity",
                    data=result.data,
                )
            case "updated":
                return UploadMetadataResponse(
                    message="Updated metadata entity",
                    data=result.data,
                )
            case "conflict":
                raise DuplicateFileException(
                    status_code=409,
                    detail="Provided file is already in the database",
                )
            case _:
                raise InternalServerException(
                    status_code=500,
                    detail="Error occured during database upload",
                )

    except errors.ServerSelectionTimeoutError:
        raise ServerNotFoundException(status_code=500, detail="Server not found.")

    except UnicodeEncodeError:
        raise IncorrectInputException(
            status_code=422,
            detail=("Input contains invalid characters"),
        )


@router.post(
    "/hash-comparison",
    status_code=status.HTTP_201_CREATED,
    responses={
        200: {"Successful Request": "Results Available"},
        400: {"Client Error Response": "Bad Request"},
        404: {"Client Error Response": "No Results Found"},
        406: {"Client Error Response": "Not Acceptable"},
        504: {"Server Error Response": "Internal Server Error"},
    },
)
async def hash_comparison(
    response: Response,
    fileInput: UploadFile,
    sourceIsoName: Annotated[str, Form()],
    collection: AsyncIOMotorCollection = Depends(get_file_metadata_collection),
    susCollection: AsyncIOMotorCollection = Depends(
        get_suspicious_file_metadata_collection,
    ),
    page: int = Query(
        0,
        ge=0,
        le=100000,
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
    try:
        obj: Metadata
        inputFileName = fileInput.filename
        inputHashes = []
        with tempfile.NamedTemporaryFile(delete=True) as temp_file:
            temp_file.write(fileInput.file.read())
            absolute_file = temp_file.name
            tmp_path = Path(absolute_file)
            upload_hashes = utils.get_hashes(tmp_path)
            inputHashes = [
                upload_hashes["md5"],
                upload_hashes["sha1"],
                upload_hashes["sha256"],
                upload_hashes["sha512"],
            ]
            obj = Metadata.parse_obj(utils.get_metadata(tmp_path, sourceIsoName))
            obj.__root__.name = [str(inputFileName)]

        # Check if hash is suspicious
        search_query = {
            "name": [inputFileName],
        }
        susResults = await collection.find(search_query).to_list(length=length)
        sus_files: list[MetadataEntity] = [
            MetadataEntity.parse_obj(item) for item in susResults
        ]
        for metadata in sus_files:
            dbHashes = [
                metadata.__root__.hashes.md5,
                metadata.__root__.hashes.sha1,
                metadata.__root__.hashes.sha256,
                metadata.__root__.hashes.sha512,
            ]
            if dbHashes != inputHashes:
                insert_result = await susCollection.insert_one(obj.dict()["__root__"])
                temp = obj.dict()["__root__"]
                temp["_id"] = str(insert_result.inserted_id)
                response.status_code = status.HTTP_406_NOT_ACCEPTABLE
                data = [MetadataEntity.parse_obj(temp)]
                return UploadListMetadataEntityResponse(
                    message="Bad hashes. Put in suspicious collection.",
                    data=data,
                )

        results = await collection.find(search_query).to_list(length=length)
        li = [MetadataEntity.parse_obj(item) for item in results]

        if len(li) == 0:
            temp = obj.dict()["__root__"]
            temp["_id"] = PydanticObjectId()
            li.append(MetadataEntity.parse_obj(temp))
            response.status_code = status.HTTP_404_NOT_FOUND

            return UploadListMetadataEntityResponse(
                message="No results found in database.",
                data=li,
            )

        response.status_code = status.HTTP_200_OK

        return UploadListMetadataEntityResponse(
            message="Database results available",
            data=li,
        )

    except errors.ServerSelectionTimeoutError:
        raise ServerNotFoundException(status_code=504, detail="Server timed out.")


@router.post(
    "/extract-files",
    responses={
        400: {"Client Error Response": "Bad Request"},
        422: {"Client Error Response": "Unprocessable Content"},
        500: {"Server Error Response": "Internal Server Error"},
        504: {"Server Error Response": "Gateway Timeout"},
    },
)
async def extract_files(
    file: UploadFile = File(...),
    source_iso: UploadFile = File(...),
    collection: AsyncIOMotorCollection = Depends(get_file_metadata_collection),
) -> CounterResponse:
    """Extract file."""
    allowed_extensions = ["application/octet-stream"]
    file_extension = file.content_type
    if file_extension not in allowed_extensions:
        IncorrectInputException(status_code=400, detail="Only VMDK files are allowed")

    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(file.file.read())
        tmp_path = PyPath(tmpfile.name)
        tmpfile.write(await source_iso.read())
        iso_path = str(PyPath(tmpfile.name))
        try:
            result = await utils.extract_files(tmp_path, str(iso_path), collection)
            return CounterResponse(
                message="Successfully Extracted VMDK",
                operations=result,
            )
        except ExtractionError:
            raise IncorrectInputException(
                status_code=422,
                detail="Error during extraction",
            )


@router.post(
    "/iterate-files",
    responses={
        400: {"Client Error Response": "Bad Request"},
    },
)
async def iterate_files(
    path: UploadFile = File(...),
    source_iso: UploadFile = File(...),
    collection: AsyncIOMotorCollection = Depends(get_file_metadata_collection),
) -> CounterResponse:
    """Iterate through file."""
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(await path.read())
        tmp_path = PyPath(tmpfile.name)
        tmpfile.write(await source_iso.read())
        iso_path = str(PyPath(tmpfile.name))
        result = await utils.iterate_files(tmp_path, iso_path, collection)
        return CounterResponse(
            message="Successfully Iterated Files",
            operations=result,
        )
