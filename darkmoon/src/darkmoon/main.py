"""This is the main.py file."""

###########
# IMPORTS #
###########

from typing import Optional

from bson.objectid import ObjectId
from fastapi import FastAPI, HTTPException
from motor.motor_asyncio import AsyncIOMotorClient

from darkmoon.server.database import collection
from darkmoon.server.schema import Metadata, MetadataEntity
from darkmoon.settings import settings

####################
# GLOBAL VARIABLES #
####################

conn = settings.DATABASE_URL
client = AsyncIOMotorClient(conn, serverSelectionTimeoutMS=5000)
app = FastAPI()

#############
# FUNCTIONS #
#############


@app.get("/metadata")
async def list_metadata(
    file_name: Optional[str] = None,
    hash_type: Optional[str] = None,
    hash: Optional[str] = None,
) -> list[MetadataEntity]:
    """Return list of metadata that matches the parameters in the database.

    Parameters:
        file_name (Optional[str]): The name of the file being searched. Is None by default.
        hash_type (Optional[str]): The type of hash. Is None by default.
        hash (Optional[str]): Hash of the file. Is None by default.
    Returns:
        documents (list[MetadataEntity]): List of all documents that match parameters in the database

    """
    documents = []
    search = {}
    if file_name:
        search["name"] = file_name
    if hash and hash_type:
        hash_parameter = "hashes." + str(hash_type)
        search[hash_parameter] = hash
    elif hash_type:
        raise HTTPException(status_code=404, detail="Enter hash")
    elif hash:
        raise HTTPException(status_code=404, detail="Enter hash type")
    async for doc in collection.find(search):
        doc["id"] = str(doc["_id"])
        documents.append(MetadataEntity(**doc))
    return documents


@app.get("/metadata/{id}")
async def get_metadata_by_id(id: str) -> MetadataEntity:
    """Return file by ObjectID in MongoDB.

    Parameters:
        id (str): Unique id of specific entry in MongoDB
    Returns:
        document (MetadataEntity): Return the database entry with matching id or raise 404 error

    """
    doc = await collection.find_one({"_id": ObjectId(id)})
    if doc:
        doc["id"] = str(doc["_id"])
        document = MetadataEntity(**doc)
    else:
        raise HTTPException(status_code=404, detail="Item not found")

    return document


@app.post("/metadata")
async def upload_metadata(file: Metadata) -> None:
    """Fast API POST function for incoming files.

    Parameters:
        file (Metadata): The file that is uploaded to the database.
    Returns:
        None

    """
    file_metadata = file.dict()

    dup_list = []
    duplicate_hashes = {
        "hashes.md5": file_metadata["md5"],
        "hashes.sha1": file_metadata["sha1"],
        "hashes.sha256": file_metadata["sha256"],
        "hashes.sha512": file_metadata["sha512"],
    }
    async for hash_dup in await collection.find(duplicate_hashes):
        dup_list.append(hash_dup)

    collection.insert_one(file_metadata)

    print(duplicate_hashes)
