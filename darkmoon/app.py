# Copyright (C) 2023 Obscurity Labs LLC. <admin@obscuritylabs.com> - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited.
# All rights reserved. No warranty, explicit or implicit, provided.
# Proprietary and confidential.

from typing import Optional

from fastapi import FastAPI

import darkmoon.api.v1.metadata.views as views
from darkmoon.core.database import register_database
from darkmoon.settings import Settings


def get_app(settings: Optional[Settings] = None) -> FastAPI:
    """Return the FastAPI connection."""
    app_settings = settings or Settings()

    app = FastAPI()

    app.on_event("startup")(register_database(app, str(app_settings.MONGODB_CONN)))

    app.include_router(views.router)
    return app


app = get_app()