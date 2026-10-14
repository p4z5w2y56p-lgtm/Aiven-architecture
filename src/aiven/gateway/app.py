"""The gateway's HTTP API (plan Task 3.3; gateway-design section 4).

Routes:

    GET  /v1/me
    POST /v1/runs
    POST /v1/runs/{run_id}/calls
    GET  /v1/runs/{run_id}/calls/{call_id}
    POST /v1/runs/{run_id}:end
    POST /v1/control/confirms/{confirm_id}:apply     (the control UI only)
    POST /v1/control/policies:reload                 (the control UI only)

Before anything else, the caller is taken from the ID token (auth.py; 401 without a valid one).
A body is JSON only: at most 2 MiB (413, and reading stops at the limit; a Content-Length over it
is refused unread), UTF-8 (400), one object, at most 32 levels deep (400), with exactly the fields
of its model (api_models.py; 400). An answer to a bad request never repeats what was sent. Then the
registry is refreshed (every 60 s at most) and the pipeline answers (pipeline.py). Anything that
breaks inside is 503, and the fallback line alerts (fail closed: nothing that was not finished is
reported as done).
"""

import json
import os
import re
from collections.abc import Callable
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ValidationError
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from aiven.gateway.api_models import CallRequest, EmptyRequest, EndRequest, StartRequest
from aiven.gateway.auth import Verifier, caller_of
from aiven.gateway.control import fail_closed_line
from aiven.gateway.pipeline import Answer, Gateway
from aiven.gateway.types import Caller

MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 32

_RUN_ID = re.compile(r"r_[0-9a-f]{26}")
_CALL_ID = re.compile(r"c_[0-9a-f]{32}")
_CONFIRM_ID = re.compile(r"q_[0-9a-f]{26}")


class _Refused(Exception):
    def __init__(self, status: int, error: str) -> None:
        self.answer = Answer(status, {"error": error})


def _depth(value: Any) -> int:
    """How deep a parsed JSON value nests, counted without recursion."""
    deepest, todo = 0, [(value, 1)]
    while todo:
        item, depth = todo.pop()
        if isinstance(item, dict | list):
            deepest = max(deepest, depth)
            children = item.values() if isinstance(item, dict) else item
            todo.extend((child, depth + 1) for child in children)
    return deepest


async def _body(request: Request, model: type[BaseModel]) -> BaseModel:
    length = request.headers.get("content-length")
    if length is not None and (not length.isdigit() or int(length) > MAX_BODY_BYTES):
        raise _Refused(413, "the body is over 2 MiB")
    raw = bytearray()
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > MAX_BODY_BYTES:
            raise _Refused(413, "the body is over 2 MiB")
    try:
        data = json.loads(bytes(raw).decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise _Refused(400, "the body is not UTF-8 JSON") from error
    if not isinstance(data, dict):
        raise _Refused(400, "the body is not one JSON object")
    if _depth(data) > MAX_DEPTH:
        raise _Refused(400, "the body nests too deep")
    try:
        return model.model_validate(data)
    except ValidationError as error:
        fields = sorted({".".join(str(part) for part in e["loc"]) for e in error.errors()})
        # The field names only: pydantic's messages repeat the value that was sent.
        raise _Refused(400, "the body does not fit: " + ", ".join(fields)) from error


def _id(value: str, pattern: re.Pattern[str]) -> str:
    if not pattern.fullmatch(value):
        raise _Refused(404, "no such route")
    return value


def create_app(
    gateway: Gateway,
    *,
    verifier: Verifier,
    audience: str,
    control_ui: str,
    clock: Callable[[], datetime] | None = None,
) -> Starlette:
    """The ASGI app of the gateway. See the module docstring."""
    now = clock or gateway.clock

    def handler(work: Callable[[Request, Caller], Any]) -> Callable[[Request], Any]:
        async def endpoint(request: Request) -> JSONResponse:
            caller = caller_of(
                request.headers.get("authorization"),
                verifier=verifier,
                audience=audience,
                control_ui=control_ui,
            )
            if caller is None:
                return JSONResponse({"error": "a valid Google ID token is needed"}, 401)
            try:
                answer = await work(request, caller)
            except _Refused as refused:
                answer = refused.answer
            except Exception:
                fail_closed_line(
                    "GATEWAY_ERROR", run_id=None, call_id=None, agent=None, audit_write_failed=False
                )
                answer = Answer(503, {"error": "the gateway could not finish this request"})
            return JSONResponse(answer.body, answer.status)

        return endpoint

    async def run(task: Callable[[], Answer]) -> Answer:
        def both() -> Answer:
            gateway.policies.refresh(now())
            return task()

        return await run_in_threadpool(both)

    async def me(request: Request, caller: Caller) -> Answer:
        return await run(lambda: gateway.me(caller))

    async def start(request: Request, caller: Caller) -> Answer:
        await _body(request, StartRequest)
        return await run(lambda: gateway.start_run(caller))

    async def call(request: Request, caller: Caller) -> Answer:
        run_id = _id(request.path_params["run_id"], _RUN_ID)
        body = await _body(request, CallRequest)
        assert isinstance(body, CallRequest)
        return await run(
            lambda: gateway.call(caller, run_id, body.action, body.args, body.request_id)
        )

    async def get_call(request: Request, caller: Caller) -> Answer:
        run_id = _id(request.path_params["run_id"], _RUN_ID)
        call_id = _id(request.path_params["call_id"], _CALL_ID)
        return await run(lambda: gateway.get_call(caller, run_id, call_id))

    async def end(request: Request, caller: Caller) -> Answer:
        run_id = _id(request.path_params["run_id"], _RUN_ID)
        body = await _body(request, EndRequest)
        assert isinstance(body, EndRequest)
        usage = [item.model_dump() for item in body.usage]
        return await run(lambda: gateway.end_run(caller, run_id, usage, body.end_reason))

    async def apply(request: Request, caller: Caller) -> Answer:
        confirm_id = _id(request.path_params["confirm_id"], _CONFIRM_ID)
        await _body(request, EmptyRequest)
        return await run(lambda: gateway.apply_confirm(caller, confirm_id))

    async def reload(request: Request, caller: Caller) -> Answer:
        await _body(request, EmptyRequest)
        return await run(lambda: gateway.reload(caller))

    async def http_error(request: Request, error: Exception) -> JSONResponse:
        status = getattr(error, "status_code", 404)
        return JSONResponse({"error": "no such route" if status == 404 else "method"}, status)

    return Starlette(
        exception_handlers={404: http_error, 405: http_error},
        routes=[
            Route("/v1/me", handler(me), methods=["GET"]),
            Route("/v1/runs", handler(start), methods=["POST"]),
            Route("/v1/runs/{run_id}/calls", handler(call), methods=["POST"]),
            Route("/v1/runs/{run_id}/calls/{call_id}", handler(get_call), methods=["GET"]),
            Route("/v1/runs/{run_id}:end", handler(end), methods=["POST"]),
            Route("/v1/control/confirms/{confirm_id}:apply", handler(apply), methods=["POST"]),
            Route("/v1/control/policies:reload", handler(reload), methods=["POST"]),
        ],
    )


def main() -> None:  # pragma: no cover - Cloud Run's entry point; the parts are tested
    """Start the gateway on Cloud Run, with the settings Terraform gives (settings.py)."""
    import uvicorn

    from aiven.gateway.settings import build

    app = build(os.environ)
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), access_log=False)
