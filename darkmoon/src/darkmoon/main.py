# example from https://fastapi.tiangolo.com/#create-it

from typing import Any, Union

import uvicorn
from fastapi import FastAPI

if __name__ == "__main__":
    uvicorn.run("server.app:app", host="0.0.0.0", port=8000, reload=True)

app = FastAPI()


@app.get("/")
def read_root() -> Any:
    """Fast API example."""
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Union[str, None] = None) -> Any:
    """Fast API example."""
    return {"item_id": item_id, "q": q}
