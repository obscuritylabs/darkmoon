"""Statement imports libraries."""

###########
# IMPORTS #
###########

from pydantic import BaseSettings, MongoDsn

###########
# CLASSES #
###########


class Settings(BaseSettings):
    """The Settings class."""

    MONGODB_CONNECTION_STRING: MongoDsn


#############
# VARIABLES #
#############

settings = Settings()
