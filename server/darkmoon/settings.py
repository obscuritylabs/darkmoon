"""Statement imports libraries."""

###########
# IMPORTS #
###########


from ipaddress import IPv4Address

from dotenv import load_dotenv
from pydantic import BaseSettings, SecretStr

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
    IPv4: IPv4Address
    PORT: int
    USERNAME: str
    PASSWORD: SecretStr

    class Config:
        """Config class."""

        env_file = ".env"
        env_file_encoding = "utf-8"

        json_encoders = {
            SecretStr: lambda v: v.get_secret_value() if v else None,
        }

    def mongo_DSN(self) -> str:
        """DSN_Model class."""
        return f"{self.SCHEME}://{self.USERNAME}:{self.PASSWORD.get_secret_value()}@{self.IPv4}:{self.PORT}/?"


#############
# VARIABLES #
#############

settings = Settings()
