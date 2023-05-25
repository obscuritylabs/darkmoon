"""Statement imports libraries."""

###########
# IMPORTS #
###########

from motor.motor_asyncio import AsyncIOMotorClient

from darkmoon.settings import settings

####################
# GLOBAL VARIABLES #
####################

client = AsyncIOMotorClient(settings.MONGODB_CONNECTION_STRING, serverSelectionTimeoutMS=5000)

db = client.darkmoon
collection = db.get_collection(name="FileMetadata")
