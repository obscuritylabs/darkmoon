"""Statement imports libraries."""
from pydantic import BaseSettings


class Settings(BaseSettings):
    """Settings class."""

    DATABASE_URL: str = "mongodb://darkmoon:password@10.0.8.8:27017/"

    class Config:
        """Config class."""

        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
