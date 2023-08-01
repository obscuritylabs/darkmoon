from pathlib import Path

from fastapi import APIRouter, File, Request, UploadFile
from fastapi.responses import HTMLResponse, Response

from darkmoon.common.main import hash_comparison
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
    """Read hash."""
    return templates.TemplateResponse("upload.html", {"request": request})


@router.get("/hashcompare", response_class=HTMLResponse)
async def output_hash(request: Request) -> Response:
    """Read request from fileupload."""
    return templates.TemplateResponse("hash_compare_result.html", {"request": request})


@router.post(
    "/hashcompareresult",
    response_class=HTMLResponse,
)
async def hash_upload(
    request: Request,
    file: UploadFile = File(...),
) -> Response:
    """POST file to API."""
    try:
        tmp_path = Path("tmpfile")
        tmp_path.write_bytes(file.file.read())
        result = await hash_comparison(tmp_path)

        return templates.TemplateResponse(
            "hash_compare_result.html",
            {
                "request": request,
                "metadata_list": result,
                "filename": file.filename,
            },
        )

    except Exception:
        return templates.TemplateResponse(
            "hash_compare_result.html",
            {
                "request": request,
                "metadata_list": "Internal Server Error",
                "filename": file.filename,
            },
            status_code=500,
        )
