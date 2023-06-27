"""This is the router file."""

###########
# IMPORTS #
###########

from typing import Optional

import bson
from bson.objectid import ObjectId
from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import errors

from darkmoon.api.v1.metadata.schema import Metadata, MetadataEntity
from darkmoon.core.database import get_file_metadata_collection

####################
# GLOBAL VARIABLES #
####################

router = APIRouter(prefix="/metadata", tags=["metadata"])

###########
# CLASSES #


#############
# FUNCTIONS #
#############


@router.get("/")
async def list_metadata(
    collection: AsyncIOMotorCollection = Depends(get_file_metadata_collection),
    file_name: Optional[str] = None,
    hash_type: Optional[str] = None,
    hash: Optional[str] = None,
) -> list[MetadataEntity]:
    """Return list of metadata that matches the parameters in the database.

    Parameters:
        file_name (Optional[str]): The name of the file being
            searched. Is None by default.
        hash_type (Optional[str]): The type of hash. Is None by default.
        hash (Optional[str]): Hash of the file. Is None by default.

    Returns:
        documents (list[MetadataEntity]): List of all documents that match
            parameters in the database

    """
    documents = []
    search = {}

    try:
        if file_name:
            search["name"] = file_name
        if hash and hash_type:
            hash_parameter = "hashes." + str(hash_type)
            search[hash_parameter] = hash
        elif hash_type:
            raise HTTPException(status_code=400, detail="Enter hash")
        elif hash:
            raise HTTPException(status_code=400, detail="Enter hash type")
        async for doc in collection.find(search):
            doc["id"] = str(doc["_id"])
            documents.append(MetadataEntity(**doc))
        return documents

    except errors.ServerSelectionTimeoutError:
        raise HTTPException(
            status_code=408,
            detail=(
                "The computer can't find the server.",
                "Check the IP Address and the server name.",
            ),
        )


@router.get("/{id}")
async def get_metadata_by_id(
    id: str,
    collection: AsyncIOMotorCollection = Depends(get_file_metadata_collection),
) -> MetadataEntity:
    """Return file by ObjectID in MongoDB.

    Parameters:
        id (str): Unique id of specific entry in MongoDB
    Returns:
        document (MetadataEntity): Return the database entry with
            matching id or raise 404 error

    """
    try:
        doc = await collection.find_one({"_id": ObjectId(id)})
        if doc:
            doc["id"] = str(doc["_id"])
            document = MetadataEntity(**doc)
        else:
            raise HTTPException(status_code=404, detail="Item not found")

        return document

    except errors.ServerSelectionTimeoutError:
        raise HTTPException(
            status_code=408,
            detail=(
                "The computer can't find the server.",
                "Check the IP Address and the server name.",
            ),
        )
    except bson.errors.InvalidId:
        raise HTTPException(
            status_code=400,
            detail=(
                "This is not a valid ID.",
                "It must be a 12-byte input or a 24-character hex string.",
            ),
        )


@router.post("/")
async def upload_metadata(
    file: Metadata,
    collection: AsyncIOMotorCollection = Depends(get_file_metadata_collection),
) -> None:
    """Fast API POST function for incoming files.

    Parameters:
        file (Metadata): The file that is uploaded to the database.

    Returns:
        None

    """
    file_metadata = file.dict()

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

    try:

        dup = await collection.find_one(check_dup)
        if dup:
            raise HTTPException(status_code=409, detail=("There is a duplicate file."))

        doc = await collection.find_one(duplicate_hashes)
        if doc:
            doc["id"] = str(doc["_id"])
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

        else:
            await collection.insert_one(file_metadata)

    except errors.ServerSelectionTimeoutError:
        raise HTTPException(
            status_code=408,
            detail=(
                "The computer can't find the server.",
                "Check the IP Address and the server name.",
            ),
        )
