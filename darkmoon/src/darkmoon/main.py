# flake8: noqa
# Copyright (C) 2022 Obscurity Labs LLC. <admin@obscuritylabs.com> - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited.
# All rights reserved. No warranty, explicit or implicit, provided.
# Proprietary and confidential.

"""This is the main.py file."""
from typing import Any, Union

from fastapi import FastAPI, Header, Response
from server.schema import IncomingFiles

app = FastAPI()


@app.get("/")
def read_root() -> Any:
    """Fast API example."""
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Union[str, None] = None) -> Any:
    """Fast API example."""
    return {"item_id": item_id, "q": q}


@app.get("/IncomingFiles1/{file_id}")
async def getHeader(IncomingFiles: Union[str, None] = Header(default=None)):
    """Fast API example."""
    return {"Header Info": IncomingFiles}


@app.post("/IncomingFiles/{file_id}")
async def WriteFile(file: IncomingFiles):
    """Fast API POST function for Incoming Files."""
    return file


@app.get("/headers-and-object/")
def get_headers(response: Response):
    """Fast API example."""
    response.headers["X-Cat-Dog"] = "alone in the world"
    return {"message": "Hello World"}
