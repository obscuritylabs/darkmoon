"""Statement imports libraries."""

###########
# IMPORTS #
###########

import os

from dotenv import load_dotenv
from pydantic import BaseSettings

#############
# FUNCTIONS #
#############

load_dotenv()

###########
# CLASSES #
###########


class Settings(BaseSettings):
    """Settings class."""

    scheme = str(os.getenv("SCHEME"))
    ipv4 = str(os.getenv("IP_ADDRESS"))
    port = str(os.getenv("PORT"))
    user = str(os.getenv("DATABASE_USERNAME"))
    password = str(os.getenv("DATABASE_PASSWORD"))

    class Config:
        """Config class."""

        env_file = ".env"
        env_file_encoding = "utf-8"

    def mongo_DSN(self) -> str:
        """DSN_Model class."""
        return f"{self.scheme}://{self.user}:{self.password}@{self.ipv4}:{self.port}/?authMechanism=DEFAULT"


#############
# VARIABLES #
#############

settings = Settings()
