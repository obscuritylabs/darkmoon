# Copyright (C) 2023 Obscurity Labs LLC. <admin@obscuritylabs.com> - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited.
# All rights reserved. No warranty, explicit or implicit, provided.
# Proprietary and confidential.


from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse as jrp

import darkmoon.api.v1.metadata.views as views
from darkmoon.api.v1.metadata.Exception_Response import (
    Duplicate_File_Exception,
    Invalid_ID_Exception,
    Item_Not_Found_Exception,
    Missing_Hash_Exception,
    Missing_Hash_Type_Exception,
    Server_Not_Found_Exception,
)
from darkmoon.core.database import register_database
from darkmoon.settings import Settings


def get_app(settings: Settings | None = None) -> FastAPI:
    """Return the FastAPI connection."""
    app_settings = settings or Settings()

    app = FastAPI()

    @app.exception_handler(Missing_Hash_Exception)
    async def missingHashExcHndlr(rqt: Request, exc: Missing_Hash_Exception) -> jrp:
        return jrp(
            status_code=400,
            content={"detail": "Enter Hash"},
        )

    @app.exception_handler(Missing_Hash_Type_Exception)
    async def msngHashTpExcHndlr(rqt: Request, exc: Missing_Hash_Type_Exception) -> jrp:
        return jrp(
            status_code=400,
            content={"detail": "Enter hash type"},
        )

    @app.exception_handler(Invalid_ID_Exception)
    async def invalidIDExcHndlr(rqt: Request, exc: Invalid_ID_Exception) -> jrp:
        return jrp(
            status_code=400,
            content={
                "detail": (
                    "This is not a valid ID",
                    "It must be a 12-byte input or a 24-character hex string.",
                ),
            },
        )

    @app.exception_handler(Server_Not_Found_Exception)
    async def srvrNoFoundExcHndlr(rqt: Request, exc: Server_Not_Found_Exception) -> jrp:
        return jrp(
            status_code=408,
            content={
                "detail": (
                    "The computer can't find the server.",
                    "Check the IP Address and the server name.",
                ),
            },
        )

    @app.exception_handler(Item_Not_Found_Exception)
    async def itemNotFoundExcHndlr(rqt: Request, exc: Item_Not_Found_Exception) -> jrp:
        return jrp(
            status_code=404,
            content={"detail": "Item not found"},
        )

    @app.exception_handler(Duplicate_File_Exception)
    async def duplicateFileExcHndlr(rqt: Request, exc: Duplicate_File_Exception) -> jrp:
        return jrp(
            status_code=409,
            content={"detail": "There is a duplicate file."},
        )

    app.on_event("startup")(register_database(app, str(app_settings.MONGODB_CONN)))
    app.add_exception_handler(Missing_Hash_Exception, missingHashExcHndlr)
    app.add_exception_handler(Missing_Hash_Type_Exception, msngHashTpExcHndlr)
    app.add_exception_handler(Invalid_ID_Exception, invalidIDExcHndlr)
    app.add_exception_handler(Server_Not_Found_Exception, srvrNoFoundExcHndlr)
    app.add_exception_handler(Item_Not_Found_Exception, itemNotFoundExcHndlr)
    app.add_exception_handler(Duplicate_File_Exception, duplicateFileExcHndlr)

    app.include_router(views.router)
    return app
