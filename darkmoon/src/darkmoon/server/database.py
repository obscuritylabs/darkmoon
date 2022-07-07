"""Imports the libraries."""

import asyncio

from motor.motor_asyncio import AsyncIOMotorClient

conn = "mongodb://10.0.8.11:27017/"

client = AsyncIOMotorClient(conn, serverSelectionTimeoutMS=5000)
db = client.darkmoon
collection = db.test


async def find() -> None:
    """Runs the find function."""
    res = await collection.find_one({"test": "test"})
    print(res)


asyncio.run(find())
