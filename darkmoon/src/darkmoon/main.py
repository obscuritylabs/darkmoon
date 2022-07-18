"""This is the main.py file."""

###########
# IMPORTS #
###########

from typing import Optional

from fastapi import FastAPI
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
async def list_metadata(file_name: Optional[str] = None, hash: Optional[str] = None) -> list[MetadataEntity]:
    """Return list of metadata that matches the parameters.

    Parameters:
        file_name: The name of the file being searched. Is None by default
        hash: Hash of the file. Is None by default.
    Returns:
        documents: List of all documents that match parameters

    """
    documents = []
    search = {}
    if file_name:
        search["name"] = file_name
    if hash:
        search["hashes"] = hash
    async for doc in collection.find(search):
        doc["id"] = str(doc["_id"])
        documents.append(MetadataEntity(**doc))
    return documents


@app.get("/metadata/{id}")
async def get_metadata_by_id(id: str) -> list[MetadataEntity]:
    """Return file by ObjectID in MongoDB.

    Parameters:
        id: Unique id of specific entry in MongoDB
    Returns:
        documents: Returns the entry with matching id

    """
    document = []
    print("outside hello")
    async for doc in collection.find({"_id": id}):
        doc["id"] = str(doc["_id"])
        document.append(MetadataEntity(**doc))

    return document


@app.post("/metadata")
async def upload_metadata(file: Metadata) -> None:
    """Fast API POST function for incoming files.

    Parameters:
        file :The file that is uploaded to the database.
    Returns:
       None

    """
    print("Hello this is working")
    file_metadata = file.dict()
    collection.insert_one(file_metadata)
