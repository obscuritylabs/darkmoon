import schemathesis
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


def test_get(
    populated_app: FastAPI,
    test_metadata_entity: dict[
        str,
        list[str] | dict[str, str] | dict[str, str | dict[str, str]] | str,
    ],
) -> None:
    """Test GET /metadata/ endpoint correctly receives object from database."""
    with TestClient(populated_app) as app:
        # positive case, should get a copy of the MetaDataEntity fixture
        response = app.get(
            "/metadata/",
            params={
                "hash_type": "md5",
                "hash": "0d41402abc4b2a76b9719d911017c591",
            },
        )
        # remove extra data added by mongo db, reformat _id key value
        del test_metadata_entity["id"]
        test_metadata_entity["_id"] = str(test_metadata_entity["_id"])

        assert response.status_code == 200
        assert response.json()[0] == test_metadata_entity

        # negative case, missing parameters
        response = app.get("/metadata/")

        assert response.status_code == 422
        assert response.json() == {
            "detail": [
                {
                    "loc": ["query", "hash_type"],
                    "msg": "field required",
                    "type": "value_error.missing",
                },
                {
                    "loc": ["query", "hash"],
                    "msg": "field required",
                    "type": "value_error.missing",
                },
            ],
        }


def test_get_id(
    populated_app: FastAPI,
    test_metadata_entity: dict[
        str,
        list[str] | dict[str, str] | dict[str, str | dict[str, str]] | str,
    ],
) -> None:
    """Test GET /metadata/{id} endpoint correctly receives object from database."""
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
        assert response.json() == {"detail": "Item not found."}


def test_post(
    populated_app: FastAPI,
    test_metadata: Metadata,
) -> None:
    """Test post endpoint with a variety of inputs."""
    with TestClient(populated_app) as app:
        response = app.post("/metadata/", data=test_metadata.json())
        assert response.status_code == 201
        assert response.json()["message"] == "Successfully Inserted Object."
        assert response.json()["data"] == test_metadata.dict()

        response = app.post("/metadata/", data=test_metadata.json())
        assert response.status_code == 409
        assert response.json()["detail"] == "File is a duplicate."

        test_metadata.name = ["different name"]
        response = app.post("/metadata/", data=test_metadata.json())
        assert response.status_code == 201
        assert response.json()["message"] == "Successfully Updated Object."
        assert response.json()["data"] == test_metadata.dict()

        test_metadata.name = [""]
        response = app.post("/metadata/", data=test_metadata.json())
        assert response.status_code == 422
        assert (
            response.json()["detail"][0]["msg"]
            == 'string does not match regex "^(?!\\s*$).+"'
        )
