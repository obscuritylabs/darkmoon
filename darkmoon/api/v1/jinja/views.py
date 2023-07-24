from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response

from darkmoon.settings import templates

router = APIRouter(prefix="/webpages", tags=["webpages"])


@router.get("", response_class=HTMLResponse)
async def read_home_page(request: Request) -> Response:
    """Read the request from the home page."""
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/upload", response_class=HTMLResponse)
async def read_item_index(request: Request) -> Response:
    """Read the request from ISO upload page for response."""
    return templates.TemplateResponse("upload.html", {"request": request})


@router.get("/hash-lookup", response_class=HTMLResponse)
async def read_item_hash(request: Request) -> Response:
    """Read the request from hash lookup page for response."""
    return templates.TemplateResponse("hash.html", {"request": request})
