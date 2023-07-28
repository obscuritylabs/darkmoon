# Copyright (C) 2023 Obscurity Labs LLC. <admin@obscuritylabs.com> - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited.
# All rights reserved. No warranty, explicit or implicit, provided.
# Proprietary and confidential.

from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import FastAPI, Request
from motor.motor_asyncio import (
    AsyncIOMotorClient,
    AsyncIOMotorCollection,
    AsyncIOMotorDatabase,
)


def register_database(
    app: FastAPI,
    mongoDB_conn: str,
) -> Callable[[], Coroutine[Any, Any, None]]:
    """Make database client."""

    async def darkmoon_client() -> None:
        app.client: AsyncIOMotorClient = AsyncIOMotorClient(  # type: ignore
            mongoDB_conn,
            serverSelectionTimeoutMS=8000,
        )

    return darkmoon_client


async def get_file_metadata_collection(request: Request) -> AsyncIOMotorCollection:
    """Make collection."""
    client: AsyncIOMotorClient = request.app.client
    db: AsyncIOMotorDatabase = client.get_database("darkmoon")
    return db.get_collection("FieldMetadata")


async def get_suspicious_file_metadata_collection(
    request: Request,
) -> AsyncIOMotorCollection:
    """Make suspicious collection."""
    client: AsyncIOMotorClient = request.app.client
    db: AsyncIOMotorDatabase = client.get_database("darkmoon")
    return db.get_collection("SuspiciousMetadata")
