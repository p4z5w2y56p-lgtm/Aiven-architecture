"""The bodies the gateway takes (plan Task 3.3; gateway-design section 4).

Every model refuses a field it does not know (`extra="forbid"`) and takes its values as they are
(`strict`): a number is not a string, true is not 1. A request ID is the agent's own text: up to
128 letters, digits and `._:-`. An action is a catalog action id; `args` is a JSON object that the
wrapper checks against the action's schema (M4).
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ACTION_PATTERN = r"^[a-z][a-z0-9]*\.[a-z][a-z0-9_]*$"
REQUEST_ID_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class StartRequest(_Strict):
    """`POST /v1/runs`: nothing but an empty object; the run's terms come from the policy."""


class CallRequest(_Strict):
    action: str = Field(pattern=ACTION_PATTERN, max_length=64)
    args: dict[str, Any]
    request_id: str = Field(pattern=REQUEST_ID_PATTERN)


class UsageItem(_Strict):
    model: str = Field(min_length=1, max_length=200)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)


class EndRequest(_Strict):
    usage: list[UsageItem] = Field(max_length=100)
    end_reason: Literal["done", "model_refusal", "max_turns", "error"]


class EmptyRequest(_Strict):
    """The control routes take no body, or an empty object."""
