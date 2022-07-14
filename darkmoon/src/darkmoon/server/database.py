"""Statement imports libraries."""

from motor.motor_asyncio import AsyncIOMotorClient

from darkmoon.settings import settings

conn = settings.DATABASE_URL

client = AsyncIOMotorClient(conn, serverSelectionTimeoutMS=5000)
db = client.darkmoon
collection = db.test
