from pydantic import BaseModel, Field


class Response(BaseModel):
    """Sets model for other reponse types to inherit from."""

    message: str = Field(
        description="Base response model",
    )
