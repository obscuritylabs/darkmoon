# views.py

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response

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
