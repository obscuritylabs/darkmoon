# views.py

from fastapi import APIRouter, File, Request, UploadFile
from fastapi.responses import HTMLResponse, Response

import darkmoon.common.name
from darkmoon.settings import HERE, templates

router = APIRouter(prefix="/webpages", tags=["webpages"])


@router.get("", response_class=HTMLResponse)
async def read_item_index(request: Request) -> Response:
    """Read index."""
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/hash-lookup", response_class=HTMLResponse)
async def read_item_hash(request: Request) -> Response:
    """Read hash."""
    return templates.TemplateResponse("hash.html", {"request": request})


@router.get("/upload", response_class=HTMLResponse)
async def read_item_upload(request: Request) -> Response:
    """Read upload."""
    return templates.TemplateResponse("upload.html", {"request": request})


@router.get("/upload", response_class=HTMLResponse)
async def upload_vmdk(request: Request, file: UploadFile = File(...)) -> Response:
    """Handle VMDK file upload and processing."""
    file_path = f"{HERE}/{darkmoon.common.name}"
    with open(file_path, "wb") as f:
        f.write(await file.read())

    results = darkmoon.common.name.process_vmdk(file_path)

    return templates.TemplateResponse(
        "results.html",
        {"request": request, "results": results},
    )
