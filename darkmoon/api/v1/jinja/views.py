import os

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

router = APIRouter(prefix="/webpages", tags=["webpages"])

templates = Jinja2Templates(
    directory=os.path.join(os.path.dirname(__file__), "templates"),
)


@router.get("/items/{id}", response_class=HTMLResponse)
async def read_item(request: Request, id: str) -> Response:
    """Read the request for response."""
    return templates.TemplateResponse("index.html", {"request": request, "id": id})
