import schemathesis
from fastapi import FastAPI
from schemathesis.constants import DataGenerationMethod
from schemathesis.lazy import LazySchema
from schemathesis.models import Case
from starlette_testclient import TestClient

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
    """Test stuff."""
    with TestClient(populated_app) as app:
        # positive case, should get a copy of the MetaDataEntity fixture
        response = app.get(
            "/metadata/",
            params={
                "hash_type": "md5",
                "hash": "5d41402abc4b2a76b9719d911017c592",
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
