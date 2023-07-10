from asyncio import get_event_loop
from collections.abc import Generator
from typing import Any

import pytest
import schemathesis
from fastapi import FastAPI
from fastapi.testclient import TestClient
from schemathesis.specs.openapi.schemas import BaseOpenAPISchema
from testcontainers.mongodb import MongoDbContainer

from darkmoon.app import get_app
from darkmoon.settings import Settings


@pytest.fixture(scope="module")
def event_loop():
    loop = get_event_loop()
    yield loop


@pytest.fixture
def database() -> Generator[str, Any, Any]:
    with MongoDbContainer("mongo:6") as mongo:
        yield mongo.get_connection_url()


@pytest.fixture
def settings(database: str) -> Settings:
    return Settings.parse_obj({"MONGODB_CONN": database})


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    return get_app(settings)


@pytest.fixture
def app_schema(app: FastAPI) -> BaseOpenAPISchema:
    return schemathesis.from_asgi("/openapi.json", app=app)
