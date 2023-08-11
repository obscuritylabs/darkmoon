from typing import Any

import schemathesis
from anyio import Path
from fastapi import FastAPI
from schemathesis.constants import DataGenerationMethod
from schemathesis.lazy import LazySchema
from schemathesis.models import Case
from starlette_testclient import TestClient

from darkmoon.api.v1.metadata.schema import Metadata

schemathesis.fixups.install()
schema: LazySchema = schemathesis.from_pytest_fixture(
    "app_schema",
    data_generation_methods=[
        DataGenerationMethod.positive,
        DataGenerationMethod.negative,
    ],
)


@schema.parametrize()
def test_api_schema(case: Case, app: FastAPI) -> None:
    """Validate the api matches the openAPI schema."""
    with TestClient(app) as session:
        case.call_and_validate(session=session)


def test_list_metadata(
    populated_app: FastAPI,
    test_metadata_entity: dict[str, Any],
) -> None:
    """Test GET /metadata correctly receives object from database."""
    test_metadata_entity = test_metadata_entity["__root__"]
    with TestClient(populated_app) as app:
        response = app.get(
            "/metadata/",
        )
        assert response.status_code == 200
        del test_metadata_entity["id"]
        test_metadata_entity["_id"] = str(test_metadata_entity["_id"])
        assert dict(response.json())["data"][0] == test_metadata_entity


def test_hash_search(
    populated_app: FastAPI,
    test_metadata_entity: dict[str, Any],
) -> None:
    """Test GET /metadata/hash_searches correctly receives object from database."""
    test_metadata_entity = test_metadata_entity["__root__"]
    with TestClient(populated_app) as app:
        # positive case, should get a copy of the MetaDataEntity fixture
        response = app.get(
            "/metadata/hash-search",
            params={
                "file_name": "Test Name",
                "fullHash": "md5:0d41402abc4b2a76b9719d911017c591",
            },
        )
        # remove extra data added by mongo db, reformat _id key value
        del test_metadata_entity["id"]
        test_metadata_entity["_id"] = str(test_metadata_entity["_id"])
        assert response.status_code == 200
        assert dict(response.json())["data"][0] == test_metadata_entity

        # negative case, incorrect parameters
        response = app.get(
            "/metadata/hash-search",
            params={
                "file_name": "invalid",
                "fullHash": "md5",
            },
        )

        assert response.status_code == 422


def test_get_metadata_by_id(
    populated_app: FastAPI,
    test_metadata_entity: dict[str, Any],
) -> None:
    """Test GET /metadata/{id} endpoint correctly receives object from database."""
    test_metadata_entity = test_metadata_entity["__root__"]
    with TestClient(populated_app) as app:
        # positive case, should get a copy of the MetaDataEntity fixture
        # remove extra data added by mongo db, reformat _id key value
        del test_metadata_entity["id"]
        test_metadata_entity["_id"] = str(test_metadata_entity["_id"])
        response = app.get(
            f"/metadata/{str(test_metadata_entity['_id'])}",
        )
        assert response.status_code == 200
        assert response.json() == test_metadata_entity

        # negative case, incorrect id
        response = app.get(f"/metadata/{'0123456789ab0123456789ab'}")
        assert response.status_code == 404


def test_upload_metadata(
    populated_app: FastAPI,
    test_metadata: Metadata,
) -> None:
    """Test POST /metadata endpoint with multiple test cases."""
    with TestClient(populated_app) as app:
        response = app.post("/metadata/", data=test_metadata.json())
        assert response.status_code == 201
        assert response.json()["data"] == test_metadata.dict()["__root__"]
        response = app.post("/metadata/", data=test_metadata.json())
        assert response.status_code == 409

        test_metadata.__root__.name = ["different name"]
        response = app.post("/metadata/", data=test_metadata.json())
        assert response.status_code == 201
        assert response.json()["data"] == test_metadata.dict()["__root__"]

        test_metadata.__root__.name = []
        response = app.post("/metadata/", data=test_metadata.json())
        assert response.status_code == 422


def test_hash_comparison_negative(
    populated_app: FastAPI,
    test_hash_comparison_without_file: Path,
) -> None:
    """Test POST /metadata/hash_comparison with bad data."""
    with TestClient(populated_app) as app:
        with open(test_hash_comparison_without_file, "rb") as testFile:
            response = app.post(
                "/metadata/hash-comparison",
                files={
                    "fileInput": testFile,
                },
                data={
                    "sourceIsoName": "Windows",
                },
            )
            assert response.status_code == 404


def test_hash_comparison(
    populated_app: FastAPI,
    test_suspicious_hash_comparison_file: Path,
) -> None:
    """Test POST /metadata/hash_comparison with good data."""
    with TestClient(populated_app) as app:
        response = app.post(
            "/metadata/hash-comparison",
            files={"fileInput": open(test_suspicious_hash_comparison_file, "rb")},
            data={
                "sourceIsoName": "Windows",
            },
        )
        assert response.status_code == 406
        response = app.get("/metadata/suspicious-metadata")
        assert len(dict(response.json())["data"]) > 0


def test_extract_files(populated_app: FastAPI, test_vmdk_file: Path) -> None:
    """Test /metadata/extract_files accurately counts uploaded data."""
    with TestClient(populated_app) as app:
        response = app.post(
            "/metadata/extract-files",
            files={"file": open(test_vmdk_file, "rb")},
            data={
                "source_iso": "Windows",
            },
        )

        assert response.status_code == 200
        assert response.json()["summary"]["created_objects"] == 1
        assert response.json()["summary"]["updated_objects"] == 0
        assert response.json()["summary"]["duplicate_objects"] == 0

        response = app.post(
            "/metadata/extract-files",
            files={"file": open(test_vmdk_file, "rb")},
            data={
                "source_iso": "Windows",
            },
        )

        assert response.status_code == 200
        assert response.json()["summary"]["created_objects"] == 0
        assert response.json()["summary"]["updated_objects"] == 0
        assert response.json()["summary"]["duplicate_objects"] == 1
