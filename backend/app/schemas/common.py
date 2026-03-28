"""Common API schemas, validators, and response envelopes."""

from typing import Annotated, Any, Generic, Literal, TypeVar

from pydantic import AfterValidator, BaseModel, ConfigDict, HttpUrl


def _validate_web_url(value: HttpUrl) -> HttpUrl:
    """Restrict URLs to the web protocols supported by the backend."""

    if value.scheme not in {"http", "https"}:
        raise ValueError("URL must start with http:// or https://")
    return value


WebUrl = Annotated[HttpUrl, AfterValidator(_validate_web_url)]


class SchemaModel(BaseModel):
    """Base model with shared serialization rules."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        use_enum_values=True,
    )


class ApiErrorDetail(SchemaModel):
    """Machine- and human-readable error payload."""

    code: str
    message: str
    details: dict[str, Any] | None = None


DataT = TypeVar("DataT")


class ApiSuccessResponse(SchemaModel, Generic[DataT]):
    """Consistent envelope for successful API responses."""

    success: Literal[True] = True
    data: DataT
    error: None = None


class ApiErrorResponse(SchemaModel):
    """Consistent envelope for error API responses."""

    success: Literal[False] = False
    data: None = None
    error: ApiErrorDetail


def success_response(data: DataT) -> ApiSuccessResponse[DataT]:
    """Build the success response envelope."""

    return ApiSuccessResponse[DataT](data=data)
