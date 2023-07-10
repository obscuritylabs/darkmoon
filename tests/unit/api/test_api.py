import schemathesis
from fastapi import FastAPI
from schemathesis.models import Case
from starlette_testclient import TestClient

schemathesis.fixups.install()
schema = schemathesis.from_pytest_fixture("app_schema")


@schema.parametrize()
def test_api(case: Case, app: FastAPI) -> None:
    with TestClient(app) as session:
        case.call_and_validate(session=session)
