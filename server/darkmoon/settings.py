"""Statement imports libraries."""

###########
# IMPORTS #
###########


from dotenv import load_dotenv
from pydantic import BaseSettings, Field

#############
# FUNCTIONS #
#############

load_dotenv()

###########
# CLASSES #
###########


class Settings(BaseSettings):
    """Settings class."""

    scheme: str = Field(..., env="SCHEME")
    ipv4: str = Field(..., env="IP_ADDRESS")
    port: str = Field(..., env="PORT")
    user: str = Field(..., env="DATABASE_USERNAME")
    password: str = Field(..., env="DATABASE_PASSWORD")

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
