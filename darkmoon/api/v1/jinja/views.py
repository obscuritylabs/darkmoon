from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

router = APIRouter(prefix="/webpages", tags=["webpages"])

current_dir = Path(__file__).parent

templates_dir = current_dir / "templates"

templates = Jinja2Templates(directory=str(templates_dir))


@router.get("/items/{id}", response_class=HTMLResponse)
async def read_item(request: Request, id: str) -> Response:
    """Read the request for response."""
    return templates.TemplateResponse("index.html", {"request": request, "id": id})
