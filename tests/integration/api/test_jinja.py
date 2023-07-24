from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_jinja(populated_app: FastAPI) -> None:
    """Test jinja webpages endpoint."""
    with TestClient(populated_app) as app:
        response = app.get(
            "/webpages/",
        )
        assert (
            '<link href="http://testserver/static/styles.css" rel="stylesheet">'
            in response.content.decode("utf-8")
        )
        assert response.status_code == 200
