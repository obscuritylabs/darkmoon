"""Conftest.py file."""

###########
# IMPORTS #
###########

from collections.abc import AsyncGenerator

import pytest
from asgi_lifespan import LifespanManager
from httpx import AsyncClient

from darkmoon.app import get_app
from darkmoon.settings import Settings

############
# FIXTURES #
############


@pytest.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    """Make the client."""
    app = get_app(Settings(MONGODB_CONN="mongodb://localhost:27017"))  # type: ignore

    async with LifespanManager(app):
        async with AsyncClient(app=app, base_url="http://localhost:8000/") as client:
            yield client
