"""This is the main.py file."""
from typing import Any

from fastapi import FastAPI
from motor.motor_asyncio import AsyncIOMotorClient
from server.schema import IncomingFiles

conn = "mongodb://darkmoon:password@10.0.8.4:27017/"

client = AsyncIOMotorClient(conn, serverSelectionTimeoutMS=5000)

db = client.darkmoon
collection = db.test

app = FastAPI()


@app.get("/")
def read_root() -> Any:
    """Fast API example."""
    return {"Hello": "World"}


@app.post("/incoming-files")
async def upload_metadata(file: IncomingFiles) -> None:
    """Fast API POST function for incoming files."""
    this_dict = file.dict()
    db.collection.insert_one(this_dict)
