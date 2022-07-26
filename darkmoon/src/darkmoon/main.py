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

    dup = await collection.find_one(check_dup)
    if dup:
        print("it is")
        return

    doc = await collection.find_one(duplicate_hashes)
    if doc:
        doc["id"] = str(doc["_id"])

        document = MetadataEntity(**doc)
        name = document.name
        name.append(file_metadata["name"][0])
        file_extension = document.file_extension
        file_extension.append(file_metadata["file_extension"][0])
        file_type = document.file_type
        file_type.append(file_metadata["file_type"][0])
        source_iso_name = document.source_iso_name
        source_iso_name.append(file_metadata["source_iso_name"][0])
        operating_system = document.operating_system
        operating_system.append(file_metadata["operating_system"][0])

        change = {
            "$set": {
                "name": name,
                "file_extension": file_extension,
                "file_type": file_type,
                "source_iso_name": source_iso_name,
                "operating_system": operating_system,
            },
        }
        await collection.update_one(duplicate_hashes, change)

    else:
        collection.insert_one(file_metadata)
