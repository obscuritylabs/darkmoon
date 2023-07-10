# Copyright (C) 2023 Obscurity Labs LLC. <admin@obscuritylabs.com> - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited.
# All rights reserved. No warranty, explicit or implicit, provided.
# Proprietary and confidential.


from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse as jrp

import darkmoon.api.v1.metadata.views as views
from darkmoon.api.v1.metadata.Exception_Response import (
    DuplicateFileException,
    InvalidIDException,
    ItemNotFoundException,
    MissingHashException,
    MissingHashTypeException,
    ServerNotFoundException,
)
from darkmoon.core.database import register_database
from darkmoon.settings import Settings


def get_app(settings: Settings | None = None) -> FastAPI:
    """Return the FastAPI connection."""
    app_settings = settings or Settings()

    app = FastAPI()

    @app.exception_handler(MissingHashException)
    async def missingHashExcHndlr(rqt: Request, exc: MissingHashException) -> jrp:
        return jrp(
            status_code=400,
            content={"detail": "Enter Hash"},
        )

    @app.exception_handler(MissingHashTypeException)
    async def msngHashTpExcHndlr(rqt: Request, exc: MissingHashTypeException) -> jrp:
        return jrp(
            status_code=400,
            content={"detail": "Enter hash type"},
        )

    @app.exception_handler(InvalidIDException)
    async def invalidIDExcHndlr(rqt: Request, exc: InvalidIDException) -> jrp:
        return jrp(
            status_code=400,
            content={
                "detail": (
                    "This is not a valid ID",
                    "It must be a 12-byte input or a 24-character hex string.",
                ),
            },
        )

    @app.exception_handler(ServerNotFoundException)
    async def srvrNoFoundExcHndlr(rqt: Request, exc: ServerNotFoundException) -> jrp:
        return jrp(
            status_code=408,
            content={
                "detail": (
                    "The computer can't find the server.",
                    "Check the IP Address and the server name.",
                ),
            },
        )

    @app.exception_handler(ItemNotFoundException)
    async def itemNotFoundExcHndlr(rqt: Request, exc: ItemNotFoundException) -> jrp:
        return jrp(
            status_code=404,
            content={"detail": "Item not found"},
        )

    @app.exception_handler(DuplicateFileException)
    async def duplicateFileExcHndlr(rqt: Request, exc: DuplicateFileException) -> jrp:
        return jrp(
            status_code=409,
            content={"detail": "There is a duplicate file."},
        )

    app.on_event("startup")(register_database(app, str(app_settings.MONGODB_CONN)))
    app.add_exception_handler(MissingHashException, missingHashExcHndlr)
    app.add_exception_handler(MissingHashTypeException, msngHashTpExcHndlr)
    app.add_exception_handler(InvalidIDException, invalidIDExcHndlr)
    app.add_exception_handler(ServerNotFoundException, srvrNoFoundExcHndlr)
    app.add_exception_handler(ItemNotFoundException, itemNotFoundExcHndlr)
    app.add_exception_handler(DuplicateFileException, duplicateFileExcHndlr)

    app.include_router(views.router)
    return app
