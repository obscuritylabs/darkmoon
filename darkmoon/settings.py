# Copyright (C) 2023 Obscurity Labs LLC. <admin@obscuritylabs.com> - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited.
# All rights reserved. No warranty, explicit or implicit, provided.
# Proprietary and confidential.

from pathlib import Path

from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseSettings, Field, MongoDsn


class Settings(BaseSettings):
    """The Settings class."""

    MONGODB_CONN: MongoDsn = Field(default="mongodb://darkmoon:password@localhost:27017/?authMechanism=DEFAULT")  # type: ignore  # noqa


HERE = Path(__file__).parent


templates = Jinja2Templates(directory=HERE / "api" / "templates")
static = StaticFiles(directory=HERE / "api" / "static")
