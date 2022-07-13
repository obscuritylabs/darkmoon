"""Statement imports libraries."""

import asyncio

from motor.motor_asyncio import AsyncIOMotorClient

conn = "mongodb://darkmoon:password@10.0.8.4:27017/"

client = AsyncIOMotorClient(conn, serverSelectionTimeoutMS=5000)
db = client.darkmoon
collection = db.test


async def find() -> None:
    """Print data."""
    res = await collection.insert_one({"bye": "bye"})
    print(res)


asyncio.run(find())
