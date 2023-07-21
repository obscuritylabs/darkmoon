from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response

from darkmoon.settings import templates

router = APIRouter(prefix="/webpages", tags=["webpages"])


@router.get("", response_class=HTMLResponse)
async def read_item_index(request: Request) -> Response:
    """Read the request from index page for response."""
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("", response_class=HTMLResponse)
async def read_item_hash(request: Request) -> Response:
    """Read the request from index page for response."""
    return templates.TemplateResponse("hash.html", {"request": request})


@router.post("/process_data", response_class=HTMLResponse)
async def process_data(
    request: Request,
    hash: str,
    hash_type: str,
    file: str,
) -> Response:
    """Will change."""
    return templates.TemplateResponse(
        "result.html",
        {
            "request": Request,
            "hash": hash,
            "hash_type": hash_type,
            "file_name": file,
        },
    )
