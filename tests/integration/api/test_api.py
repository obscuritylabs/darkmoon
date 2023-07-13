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
def test_api(case: Case, app: FastAPI) -> None:
    """Validate the api matches the openAPI schema."""
    with TestClient(app) as session:
        case.call_and_validate(session=session)
