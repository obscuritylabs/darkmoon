"""Statement imports libraries."""

from pydantic import BaseSettings


class Settings(BaseSettings):
    """Settings class."""

    FILE_DIRECTORY: str = ""
    API_URL: str = "http://127.0.0.1:8000"

    class Config:
        """Config class."""

        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
