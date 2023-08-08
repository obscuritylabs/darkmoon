"""Defines an API router for handling metadata related requests."""
import tempfile
from pathlib import Path, Path as PyPath

import bson
from beanie import PydanticObjectId
from fastapi import APIRouter, Body, Depends, File, Query, Response, UploadFile, status
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import errors
from requests.models import MissingSchema

from darkmoon.api.v1.metadata.schema import (
    DocMetadata,
    EXEMetadata,
    Metadata,
    MetadataEntity,
    UploadListMetadataEntityResponse,
    UploadMetadataResponse,
)
from darkmoon.common import utils
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
    "/hashSearch",
    responses={
        422: {"Client Error Response": "Unprocessable Content"},
        504: {"Server Error Response": "Gateway Timeout"},
        400: {"Client Error Response": "Bad Request"},
    },
)
async def list_metadata_by_hash(
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

        data = await collection.find(search).skip(page * length).to_list(length=length)
        out: list[MetadataEntity] = [MetadataEntity.parse_obj(item) for item in data]
        if len(out) == 0:
            temp: list[MetadataEntity] = []
            return UploadListMetadataEntityResponse(
                data=temp,
                message="No results found.",
            )
        else:
            return UploadListMetadataEntityResponse(
                data=out,
                message="Results available.",
            )
    except errors.ServerSelectionTimeoutError:
        raise ServerNotFoundException(status_code=504, detail="Server timed out.")


@router.get(
    "/suspicious",
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
    file_metadata = file.dict()["__root__"]
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
        }
        match file.__root__:
            case EXEMetadata():
                check_dup["header_info"] = file_metadata["header_info"]
            case DocMetadata():
                ...
            case _:
                raise IncorrectInputException(
                    status_code=422,
                    detail="Error validating file",
                )
    except IndexError:
        raise IncorrectInputException(status_code=422, detail=["Input missing"])

    try:
        dup = await collection.find_one(check_dup)
        if dup:
            raise DuplicateFileException(status_code=409, detail="File is a duplicate.")

        doc = await collection.find_one(duplicate_hashes)
        if doc:
            document = MetadataEntity.parse_obj(doc)

            data_type = [
                document.__root__.name,
                document.__root__.file_extension,
                document.__root__.file_type,
                document.__root__.source_iso_name,
                document.__root__.operating_system,
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
                    data_type[index].append(
                        file_metadata[data_type_string[index]][0],
                    )

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
            return UploadMetadataResponse(
                message="Successfully Updated Object.",
                data=Metadata.parse_obj(file_metadata),
            )

        else:
            await collection.insert_one(file_metadata)
            return UploadMetadataResponse(
                message="Successfully Inserted Object.",
                data=Metadata.parse_obj(file_metadata),
            )

    except errors.ServerSelectionTimeoutError:
        raise ServerNotFoundException(status_code=500, detail="Server not found.")
    except UnicodeEncodeError:
        raise IncorrectInputException(
            status_code=422,
            detail=("Input contains invalid characters"),
        )


@router.post(
    "/hashComparison",
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
    sourceIsoName: str,
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
async def extract_files_endpoint(
    file: UploadFile = File(...),  # only vmdks
    source_iso: UploadFile = File(...),
    url: PyPath = PyPath("..."),  # refactor it, so it not being used
) -> dict[str, str]:
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
            utils.extract_files(tmp_path, str(iso_path), str(url))
            return {"message": "Extraction successful"}
        except ExtractionError:
            raise IncorrectInputException(
                status_code=422,
                detail="Error during extraction",
            )
        except MissingSchema:
            raise IncorrectInputException(
                status_code=422,
                detail="Invalid URL",
            )
        except Exception:
            raise InternalServerException(
                status_code=500,
                detail="Internal Server Error",
            )


@router.post(
    "/iterate-files",
    responses={
        400: {"Client Error Response": "Bad Request"},
    },
)
async def iterate_files_endpoint(
    path: UploadFile = File(...),
    source_iso: UploadFile = File(...),
    url: PyPath = PyPath("..."),
) -> None:
    """Iterate through file."""
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(await path.read())
        tmp_path = PyPath(tmpfile.name)
        tmpfile.write(await source_iso.read())
        iso_path = str(PyPath(tmpfile.name))
        utils.iterate_files(tmp_path, iso_path, str(url))


@router.post("/process-iso")
async def process_iso(
    iso_upload: UploadFile = File(...),
    template_upload: UploadFile = File(...),
    answer_upload: UploadFile = File(...),
    darkmoon_url: str = "https://127.0.0.1:8000",
) -> None:
    """Takes in an ISO, Packer template, and answer file to extract files.

    The Packer template is used to upload and install an ISO,
    afterwards the NFS containing the VM image is mounted
    and the VM image is extracted and processed.
    """
    tmp_iso = PyPath("tmpfile.iso")
    tmp_iso.write_bytes(iso_upload.file.read())

    tmp_packer = PyPath("tmp.pkr.hcl")
    tmp_packer.write_bytes(template_upload.file.read())

    tmp_answer = PyPath("autounattend.xml")
    tmp_answer.write_bytes(answer_upload.file.read())

    vmid: int = 0
    build_process = utils.packer_build(tmp_packer)
    output = []
    while build_process.poll() is None:
        if build_process.stdout is not None:
            curr = build_process.stdout.readline().decode("utf-8")
            if "A template was created:" in output:
                vmid = int(curr.split(":")[-1].strip())
            output.append(curr)
    if build_process.poll() != 0:
        tmp_iso.unlink()
        tmp_packer.unlink()
        tmp_answer.unlink()
        raise InternalServerException(
            status_code=500,
            detail=f"Build Process Error Code {build_process.poll()}: "
            + "".join(output),
        )
    if vmid == 0:
        tmp_iso.unlink()
        tmp_packer.unlink()
        tmp_answer.unlink()
        raise InternalServerException(
            status_code=500,
            detail="Could not get VMID: " + "".join(output),
        )
    tmp_iso.unlink()
    tmp_packer.unlink()
    tmp_answer.unlink()
    # mount_point: PyPath = utils.mount_nfs("mount arguments")
    # disk_img = mount_point.joinpath(f"template file for {vmid}")
    # utils.extract_files(
    #     file=disk_img,
    #     source_iso=tmp_iso.name,
    #     url=darkmoon_url,
    # )
