"""This is the main.py file."""
from typing import Any

from fastapi import FastAPI
from motor.motor_asyncio import AsyncIOMotorClient

from darkmoon.server.database import collection
from darkmoon.server.schema import Metadata
from darkmoon.settings import settings

conn = settings.DATABASE_URL

client = AsyncIOMotorClient(conn, serverSelectionTimeoutMS=5000)

app = FastAPI()


@app.get("/")
def read_root() -> Any:
    """Fast API example."""
    return {"Hello": "World"}


@app.post("/upload-metadata")
async def upload_metadata(file: Metadata) -> None:
    """Fast API POST function for incoming files."""
    file_metadata = file.dict()
    collection.insert_one(file_metadata)
