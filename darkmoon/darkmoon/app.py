"""This is the main.py file."""

###########
# IMPORTS #
###########

from fastapi import FastAPI
from motor.motor_asyncio import AsyncIOMotorClient

import darkmoon.api.v1.metadata.views as views
from darkmoon.settings import settings

####################
# GLOBAL VARIABLES #
####################

conn = settings.DATABASE_URL
client = AsyncIOMotorClient(conn, serverSelectionTimeoutMS=5000)
app = FastAPI()

app.include_router(views.router)
