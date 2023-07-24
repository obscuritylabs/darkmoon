# Copyright (C) 2023 Obscurity Labs LLC. <admin@obscuritylabs.com> - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited.
# All rights reserved. No warranty, explicit or implicit, provided.
# Proprietary and confidential.


from fastapi import FastAPI

import darkmoon.api.v1.jinja.views as webpages
import darkmoon.api.v1.metadata.views as views
from darkmoon.core.database import register_database
from darkmoon.settings import Settings, static


def get_app(settings: Settings | None = None) -> FastAPI:
    """Return the FastAPI connection.

    Parameters:
        Settings (Optional): Settings object that defines the app settings.

    Returns:
        FastAPI: The FastAPI application.
    """
    app_settings = settings or Settings()

    app = FastAPI()
    app.on_event("startup")(register_database(app, str(app_settings.MONGODB_CONN)))

    app.mount("/static", static, name="static")
    app.include_router(webpages.router)

    app.include_router(views.router)

    app.include_router(webpages.router)

    return app
