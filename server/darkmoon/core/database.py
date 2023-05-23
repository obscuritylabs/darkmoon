"""Statement imports libraries."""

###########
# IMPORTS #
###########

from motor.motor_asyncio import AsyncIOMotorClient

from darkmoon.settings import settings

####################
# GLOBAL VARIABLES #
####################

conn = settings.mongo_DSN()
client = AsyncIOMotorClient(conn, serverSelectionTimeoutMS=5000)

db = client.darkmoon
collection = db.get_collection(name="FileMetadata")
