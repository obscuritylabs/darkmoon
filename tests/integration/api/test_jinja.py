from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_jinja_homepage(populated_app: FastAPI) -> None:
    """Test jinja webpages endpoint for the home page."""
    with TestClient(populated_app) as app:
        response = app.get(
            "/webpages/",
        )
        assert (
            '<link href="http://testserver/static/style.css" rel="stylesheet">'
            in response.content.decode("utf-8")
        )
        assert (
            '<link href="http://testserver/static/variables.css" rel="stylesheet">'
            in response.content.decode("utf-8")
        )
        assert response.status_code == 200


def test_jinja_hashpage(populated_app: FastAPI) -> None:
    """Test jinja webpages endpoint for the hash page."""
    with TestClient(populated_app) as app:
        response = app.get(
            "/webpages/hash-lookup",
        )
        assert (
            '<link href="http://testserver/static/style.css" rel="stylesheet">'
            in response.content.decode("utf-8")
        )
        assert (
            '<link href="http://testserver/static/variables.css" rel="stylesheet">'
            in response.content.decode("utf-8")
        )
        assert response.status_code == 200


def test_jinja_uploadpage(populated_app: FastAPI) -> None:
    """Test jinja webpages endpoint for the upload page."""
    with TestClient(populated_app) as app:
        response = app.get(
            "/webpages/upload",
        )
        assert (
            '<link href="http://testserver/static/style.css" rel="stylesheet">'
            in response.content.decode("utf-8")
        )
        assert (
            '<link href="http://testserver/static/variables.css" rel="stylesheet">'
            in response.content.decode("utf-8")
        )
        assert response.status_code == 200


def test_jinja_fileupload(populated_app: FastAPI) -> None:
    """Test uploading file for hash comparison."""
    with TestClient(populated_app) as app:
        response = app.post(
            "/webpages/hashcompareresult",
        )

        assert response.status_code == 200
