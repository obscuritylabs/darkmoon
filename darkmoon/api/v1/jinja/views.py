# views.py

from fastapi import APIRouter, File, Path, Request, UploadFile
from fastapi.responses import HTMLResponse, Response

import darkmoon.common.name
from darkmoon.settings import templates

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


@router.post("/upload", response_class=HTMLResponse)
async def upload_vmdk(request: Request, file: UploadFile = File(...)) -> Response:
    """Handle VMDK file upload and processing."""
    upload_dir = Path("path/to/your/upload/directory")
    upload_dir.mkdir(parents=True, exist_ok=True)

    file_path = upload_dir / file.filename
    with open(file_path, "wb") as f:
        f.write(await file.read())

    # Extract the filename from the uploaded file
    extracted_filename = file.filename

    # Process the VMDK file
    results = darkmoon.common.name.process_vmdk(file_path)

    return templates.TemplateResponse(
        "upload.html",
        {
            "request": request,
            "extracted_filename": extracted_filename,
            "results": results,
        },
    )
