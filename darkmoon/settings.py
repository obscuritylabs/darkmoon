# Copyright (C) 2023 Obscurity Labs LLC. <admin@obscuritylabs.com> - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited.
# All rights reserved. No warranty, explicit or implicit, provided.
# Proprietary and confidential.


from pydantic import BaseSettings, Field, MongoDsn


class Settings(BaseSettings):  # type: ignore
    """The Settings class."""

    MONGODB_CONN: MongoDsn = Field(default="mongodb://darkmoon:password@mongodb:27017/?authMechanism=DEFAULT")  # type: ignore  # noqa

    PROXMOX_PASS: str = Field(default="")
    PROXMOX_USER: str = Field(default="")
    PROXMOX_HOST: str = Field(default="")
