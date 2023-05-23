"""This is the main.py file."""

###########
# IMPORTS #
###########

from fastapi import FastAPI

import darkmoon.api.v1.metadata.views as views

####################
# GLOBAL VARIABLES #
####################

app = FastAPI()
app.include_router(views.router)
