"""Import libraries."""
from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def home():
    """Print data."""
    my_dict = {"Data": "Test"}
    print(my_dict)
