"""Statement imports libraries."""

###########
# IMPORTS #
###########

from darkmoon.app import client

####################
# GLOBAL VARIABLES #
####################

db = client.darkmoon
collection = db.get_collection(name="FileMetadata")
