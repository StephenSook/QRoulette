"""Common API schemas."""

from pydantic import BaseModel


class TodoResponse(BaseModel):
    """Standard placeholder response for unimplemented endpoints."""

    status: str = "not_implemented"
    message: str
