"""This is the main.py file."""
from typing import Any

from fastapi import FastAPI
from server.schema import IncomingFiles

app = FastAPI()


@app.get("/")
def read_root() -> Any:
    """Fast API example."""
    return {"Hello": "World"}


@app.post("/incoming-files")
async def upload_metadata(file: IncomingFiles) -> Any:
    """Fast API POST function for incoming files."""
    if file.header_info:
        this_dict = {
            "name": file.name,
            "file_extention": file.file_extention,
            "hashes": file.hashes,
            "source_ISO_name": file.source_ISO_name,
            "header_info": file.header_info,
        }
    else:

        this_dict = {
            "name": file.name,
            "file_extention": file.file_extention,
            "hashes": file.hashes,
            "source_ISO_name": file.source_ISO_name,
        }

    return this_dict
