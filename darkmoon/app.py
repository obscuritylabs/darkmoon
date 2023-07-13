# Copyright (C) 2023 Obscurity Labs LLC. <admin@obscuritylabs.com> - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited.
# All rights reserved. No warranty, explicit or implicit, provided.
# Proprietary and confidential.


from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

import darkmoon.api.v1.metadata.views as views
from darkmoon.core.database import register_database
from darkmoon.settings import Settings

app = FastAPI()

templates = Jinja2Templates(directory="templates")


@app.get("/items/{id}", response_class=HTMLResponse)
async def read_item(request: Request, id: str) -> Response:
    """Define a GET request.

    Parameters:
        request (Request): The incoming request.
        id (str): The ID of the item.

    Returns:
        Response: HTML response with the item.html template.
    """
    return templates.TemplateResponse("item.html", {"request": request, "id": id})


def get_app(settings: Settings | None = None) -> FastAPI:
    """Return the FastAPI connection.

    Parameters:
        Settings (Optional): Settings object that defines the app settings.

    Returns:
        FastAPI: The FastAPI application.
    """
    app_settings = settings or Settings()

    app.on_event("startup")(register_database(app, str(app_settings.MONGODB_CONN)))

    app.include_router(views.router)
    return app
