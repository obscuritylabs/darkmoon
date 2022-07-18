"""This is the main.py file."""

###########
# IMPORTS #
###########

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
async def all_metadata() -> list[MetadataEntity]:
    """Return all metadata stored in the mongodb server.

    Parameters:
        None
    Returns:
        'list[MetadataEntity]': Lists of all documents in server.

    """
    documents = []
    async for doc in collection.find():
        doc["id"] = str(doc["_id"])
        documents.append(MetadataEntity(**doc))

    return documents


@app.get("/metadata/{file_name}")
async def get_metadata_by_filename(file_name: str) -> list[MetadataEntity]:
    """Return file by name on mongodb server.

    Parameters:
        file_name: The name of the file being searched.
    Returns:
        documents: Lists of all documents in server.

    """
    documents = []
    async for doc in collection.find({"name": file_name}):
        doc["id"] = str(doc["_id"])
        documents.append(MetadataEntity(**doc))
    return documents


@app.post("/metadata")
async def upload_metadata(file: Metadata) -> None:
    """Fast API POST function for incoming files.

    Parameters:
        file - The file that is uploaded to the database.
    Returns:
       None

    """
    print("Hello this is working")
    file_metadata = file.dict()
    collection.insert_one(file_metadata)
