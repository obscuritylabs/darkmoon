"""Statement imports libraries."""
import asyncio

from motor.motor_asyncio import AsyncIOMotorClient

conn = "mongodb://darkmoon:password@10.0.8.2:27017/"

client = AsyncIOMotorClient(conn, serverSelectionTimeoutMS=5000)
db = client.darkmoon
collection = db.test


async def find() -> None:
    """Print data."""
    res = await collection.find_one({"test": "hello"})
    print(res)


asyncio.run(find())
