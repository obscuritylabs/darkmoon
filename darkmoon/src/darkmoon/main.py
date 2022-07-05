# example from https://fastapi.tiangolo.com/#create-it

from typing import Any, Union

from fastapi import FastAPI

app = FastAPI()

print("Hello world")


@app.get("/")
def read_root() -> Any:
    """Fast API example."""
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Union[str, None] = None) -> Any:
    """Fast API example."""
    return {"item_id": item_id, "q": q}
