"""Imports BaseSettings."""

from pydantic import BaseSettings


class Settings(BaseSettings):
    """Set settings."""

    FILE_DIRECTORY: str = "/workspaces/darkmoon/darkmoon-cli/src/darkmoon_cli/testing"

    class Config:
        """Set config."""

        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
