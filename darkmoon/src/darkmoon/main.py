"""This is the main.py file."""
from typing import Any

from fastapi import FastAPI
from server.schema import IncomingFiles

app = FastAPI()


@app.get("/")
def read_root() -> Any:
    """Fast API example."""
    return {"Hello": "World"}


@app.post("/incomingfiles/")
async def WriteFile(file: IncomingFiles) -> Any:
    """Fast API POST function for incoming files."""
    return file
