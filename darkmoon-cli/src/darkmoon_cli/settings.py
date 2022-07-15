"""Statement imports libraries."""

from pydantic import BaseSettings


class Settings(BaseSettings):
    """Settings class."""

    FILE_DIRECTORY: str = "/workspaces/darkmoon/darkmoon-cli/src/darkmoon_cli/testing"

    class Config:
        """Congfig class."""

        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
