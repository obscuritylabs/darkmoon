import schemathesis

schema = schemathesis.from_uri("http://localhost:8000/openapi.json")


@schema.parametrize()  # type: ignore
def test_api(case) -> None:
    """Does stuff."""
    case.call_and_validate()
