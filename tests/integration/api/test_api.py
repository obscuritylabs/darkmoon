import schemathesis
from fastapi import FastAPI
from schemathesis.lazy import LazySchema
from schemathesis.models import Case
from starlette_testclient import TestClient

schemathesis.fixups.install()
schema: LazySchema = schemathesis.from_pytest_fixture("app_schema")


@schema.parametrize()
def test_api(case: Case, app: FastAPI) -> None:
    """Do stuff."""
    with TestClient(app) as session:
        case.call_and_validate(session=session)
