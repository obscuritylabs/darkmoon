from asyncio import AbstractEventLoop, get_event_loop
from collections.abc import Generator
from typing import Any

import pytest
import schemathesis
from fastapi import FastAPI

# from fastapi.testclient import TestClient
from schemathesis.specs.openapi.schemas import BaseOpenAPISchema
from testcontainers.mongodb import MongoDbContainer

from darkmoon.app import get_app
from darkmoon.settings import Settings


@pytest.fixture(scope="module")
def event_loop() -> Generator[AbstractEventLoop, Any, Any]:
    """Attempt to return the current running event loop."""
    loop = get_event_loop()
    yield loop


@pytest.fixture
def database() -> Generator[str, Any, Any]:
    """Database fixture for testing the app."""
    with MongoDbContainer("mongo:6") as mongo:
        yield mongo.get_connection_url()


@pytest.fixture
def settings(database: str) -> Settings:
    """Return the database connection settings using the database fixture."""
    return Settings.parse_obj({"MONGODB_CONN": database})


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    """Use the settings fixture to override default app settings."""
    return get_app(settings)


@pytest.fixture
def app_schema(app: FastAPI) -> BaseOpenAPISchema:
    """Return the OpenAPI schema of the app."""
    schema: BaseOpenAPISchema = schemathesis.from_asgi("/openapi.json", app=app)
    return schema
