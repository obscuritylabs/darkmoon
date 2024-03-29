from asyncio import AbstractEventLoop, get_event_loop
from collections.abc import Generator
from typing import Any

import pytest
import schemathesis
from anyio import Path
from beanie import PydanticObjectId
from fastapi import FastAPI
from schemathesis.specs.openapi.schemas import BaseOpenAPISchema
from testcontainers.mongodb import MongoDbContainer

from darkmoon.api.v1.metadata.schema import (
    Metadata,
    MetadataEntity,
)
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


@pytest.fixture
def test_metadata_entity() -> dict[str, Any]:
    """Represent a test metadata object."""
    file: dict[str, Any] = MetadataEntity.parse_obj(
        {
            "base_file_type": "exe",
            "_id": PydanticObjectId(),
            "name": [
                "Test Name",
            ],
            "file_extension": [
                ".jpeg",
            ],
            "file_type": [
                "exe",
            ],
            "hashes": {
                "md5": "0d41402abc4b2a76b9719d911017c591",
                "sha1": "0af4c61ddcc5e8a2dabede0f3b482cd9aea9434a",
                "sha256": "0cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9823",  # noqa: E501
                "sha512": "05d527c368f2efe848ecd5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84979",  # noqa: E501
            },
            "source_iso_name": [
                "Win_XP",
            ],
            "operating_system": [
                "WindowsXP",
            ],
            "header_info": {
                "machine_type": "0x14c",
                "timestamp": "12/2/23 17:57:43",
                "compile_time": "15",
                "signature": "example",
                "rich_header_hashes": {
                    "md5": "0d41402abc4b2a76b9719d911017c591",
                    "sha1": "0af4c61ddcc5e8a2dabede0f3b482cd9aea9434a",
                    "sha256": "0cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9823",  # noqa: E501
                    "sha512": "05d527c368f2efe848ecd5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84979",  # noqa: E501
                },
            },
        },
    ).dict()
    return file


@pytest.fixture
def test_suspicious_metadata_entity() -> dict[str, Any]:
    """Represent a test metadata object."""
    file: dict[str, Any] = MetadataEntity.parse_obj(
        {
            "base_file_type": "doc",
            "_id": PydanticObjectId(),
            "name": ["test4.rtf"],
            "file_extension": [".rtf"],
            "file_type": ["text/rtf"],
            "hashes": {
                "md5": "",
                "sha1": "",
                "sha256": "",
                "sha512": "",
            },
            "source_iso_name": ["Win_XP"],
            "operating_system": ["Windows XP"],
        },
    ).dict()
    return file


@pytest.fixture
def populated_database(
    test_metadata_entity: dict[str, Any],
    test_suspicious_metadata_entity: dict[str, Any],
) -> Generator[str, Any, Any]:
    """Represent a database with an object already inserted."""
    with MongoDbContainer("mongo:6") as mongo:
        db = mongo.get_connection_client().get_database("darkmoon")
        db.get_collection("FieldMetadata").insert_one(test_metadata_entity["__root__"])
        db.get_collection("FieldMetadata").insert_one(
            test_suspicious_metadata_entity["__root__"],
        )
        yield mongo.get_connection_url()


@pytest.fixture
def populated_app(populated_database: str) -> FastAPI:
    """Darkmoon app with populated database."""
    return get_app(Settings.parse_obj({"MONGODB_CONN": populated_database}))


@pytest.fixture
def test_metadata() -> Metadata:
    """Represent a test metadata object."""
    file: Metadata = Metadata.parse_obj(
        {
            "base_file_type": "exe",
            "name": [
                "End_Of_The_World",
            ],
            "file_extension": [
                ".jpeg",
            ],
            "file_type": [
                "exe",
            ],
            "hashes": {
                "md5": "5d41402abc4b2a76b9719d911017c592",
                "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",  # noqa: E501
                "sha512": "75d527c368f2efe848ecd5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976",  # noqa: E501
            },
            "source_iso_name": [
                "Win_XP",
            ],
            "operating_system": [
                "WindowsXP",
            ],
            "header_info": {
                "machine_type": "0x14c",
                "timestamp": "12/2/23 17:57:43",
                "compile_time": "15",
                "signature": "example",
                "rich_header_hashes": {
                    "md5": "5d41402abc4b2a76b9719d911017c592",
                    "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",  # noqa: E501
                    "sha512": "75d527c368f2efe848ecd5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976",  # noqa: E501
                },
            },
        },
    )
    return file


HERE = Path(__file__).parent


@pytest.fixture()
def test_hash_comparison_without_file() -> Path:
    """Load the test file as a fixture."""
    file = HERE / "test3.rtf"
    assert file.exists()
    return file


@pytest.fixture()
def test_suspicious_hash_comparison_file() -> Path:
    """Load the test file as a fixture."""
    file = HERE / "test4.rtf"
    assert file.exists()
    return file


@pytest.fixture()
def test_vmdk_file() -> Path:
    """Load the test file as a fixture."""
    file = HERE / "test.vmdk"
    assert file.exists()
    return file


@pytest.fixture()
def test_bad_vmdk_file() -> Path:
    """Load the test file as a fixture."""
    file = HERE / "bad.vmdk"
    assert file.exists()
    return file
