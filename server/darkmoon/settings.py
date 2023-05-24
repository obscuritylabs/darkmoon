"""Statement imports libraries."""

###########
# IMPORTS #
###########


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

    SCHEME: str
    IP_ADDRESS: str
    PORT: str
    USERNAME: str
    PASSWORD: str

    class Config:
        """Config class."""

        env_file = ".env"
        env_file_encoding = "utf-8"

    def mongo_DSN(self) -> str:
        """DSN_Model class."""
        return f"{self.SCHEME}://{self.USERNAME}:{self.PASSWORD}@{self.IP_ADDRESS}:{self.PORT}/?authMechanism=DEFAULT"


#############
# VARIABLES #
#############

settings = Settings()
