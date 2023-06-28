"""Statement imports libraries."""

from pydantic import BaseSettings


class Settings(BaseSettings):
    """Settings class."""

    FILE_DIRECTORY: str = "/workspaces/darkmoon/darkmoon-cli/src/darkmoon_cli/win10vmdk"
    API_URL: str = "http://172.16.5.3:8000"

    class Config:
        """Config class."""

        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
