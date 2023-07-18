from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response

from darkmoon.settings import templates

router = APIRouter(prefix="/webpages", tags=["webpages"])


@router.get("", response_class=HTMLResponse)
async def read_item(request: Request) -> Response:
    """Read the request for response."""
    return templates.TemplateResponse("index.html", {"request": request})
