"""This is the main.py file."""

from fastapi import FastAPI
from motor.motor_asyncio import AsyncIOMotorClient

from darkmoon.server.database import collection
from darkmoon.server.schema import Metadata, MetadataEntity
from darkmoon.settings import settings

conn = settings.DATABASE_URL

client = AsyncIOMotorClient(conn, serverSelectionTimeoutMS=5000)

app = FastAPI()


@app.get("/metadata")
async def all_metadata() -> list[MetadataEntity]:
    """Return all metadata stored in the mongodb server.

    Parameters:
        None
    Returns:
        list[MetadataEntity]: list of all documents in server

    """
    documents = []
    async for doc in collection.find():
        doc["id"] = str(doc["_id"])
        documents.append(MetadataEntity(**doc))

    return documents


@app.post("/metadata")
async def upload_metadata(file: Metadata) -> None:
    """Fast API POST function for incoming files."""
    print("Hello this is working")
    file_metadata = file.dict()
    collection.insert_one(file_metadata)
