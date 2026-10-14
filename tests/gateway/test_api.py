"""The HTTP API and the caller's identity (plan Task 3.3; gateway-design section 4; AT-BYP-2,
AT-BYP-4; review focus 4).

The app is driven as Cloud Run drives it, through ASGI, by a small helper here: no HTTP client
library is needed. The ID token is checked by a stand-in verifier that knows a few tokens; what it
says about a token is the only identity the gateway has.
"""

import asyncio
import json

import pytest

from aiven.gateway.app import MAX_BODY_BYTES, create_app
from tests.gateway.test_pipeline import AGENT, CONTROL_UI, PRINCIPAL, World
from tests.support.gen import valid_iban

AUDIENCE = "https://gateway-123.europe-west4.run.app"
TOKENS = {
    "agent-token": {"email": PRINCIPAL, "email_verified": True},
    "control-token": {"email": CONTROL_UI.email, "email_verified": True},
    "stranger-token": {
        "email": "agent-x@aiven-agents-test.iam.gserviceaccount.com",
        "email_verified": True,
    },  # fmt: skip
    "unverified-token": {"email": PRINCIPAL, "email_verified": False},
}


def verifier(token: str, audience: str) -> dict:
    assert audience == AUDIENCE
    if token not in TOKENS:
        raise ValueError("not a token")
    return TOKENS[token]


class Api:
    def __init__(self, world: World | None = None):
        self.world = world or World()
        self.app = create_app(
            self.world.gateway, verifier=verifier, audience=AUDIENCE, control_ui=CONTROL_UI.email
        )

    def __call__(self, method, path, *, token="agent-token", body=b"", headers=(), chunks=None):
        heads = [(k.lower().encode(), v.encode()) for k, v in headers]
        if token is not None:
            heads.append((b"authorization", f"Bearer {token}".encode()))
        parts = chunks if chunks is not None else [body]

        async def run():
            sent = []
            messages = [
                {"type": "http.request", "body": part, "more_body": i < len(parts) - 1}
                for i, part in enumerate(parts)
            ]
            self.read = 0

            async def receive():
                if messages:
                    message = messages.pop(0)
                    self.read += len(message["body"])
                    return message
                return {"type": "http.disconnect"}

            async def send(message):
                sent.append(message)

            scope = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": method,
                "scheme": "https",
                "path": path,
                "raw_path": path.encode(),
                "query_string": b"",
                "root_path": "",
                "headers": heads,
                "client": ("10.0.0.1", 1234),
                "server": ("gateway", 443),
            }
            await self.app(scope, receive, send)
            return sent

        sent = asyncio.run(run())
        status = sent[0]["status"]
        raw = b"".join(message.get("body", b"") for message in sent[1:])
        return status, json.loads(raw) if raw else None

    def start(self) -> str:
        status, body = self("POST", "/v1/runs", body=b"{}")
        assert status == 200, body
        return body["run_id"]

    def call(self, run_id, payload, **options):
        return self(
            "POST", f"/v1/runs/{run_id}/calls", body=json.dumps(payload).encode(), **options
        )


@pytest.fixture
def api() -> Api:
    return Api()


# --- identity (AT-BYP-4)


def test_identity_comes_only_from_token(api):
    claims = [("X-Goog-Authenticated-User-Email", "accounts.google.com:agent-x@x"),
              ("X-Forwarded-User", "control-ui"), ("From", CONTROL_UI.email)]  # fmt: skip
    status, body = api("GET", "/v1/me", headers=claims)
    assert status == 200 and body["agent"] == AGENT
    status, _ = api("POST", "/v1/control/policies:reload", headers=claims)
    assert status == 403  # the headers do not make an agent the control UI


@pytest.mark.parametrize("token", [None, "forged", "unverified-token"])
def test_no_valid_token_is_401(api, token):
    status, body = api("GET", "/v1/me", token=token)
    assert status == 401 and api.world.drive.executed == []


def test_a_token_that_is_not_bearer_is_401(api):
    status, _ = api("GET", "/v1/me", token=None, headers=[("Authorization", "Basic agent-token")])
    assert status == 401


def test_unmapped_principal_no_policy_alert(api):
    status, body = api("GET", "/v1/me", token="stranger-token")
    assert (status, body["reason"]) == (403, "NO_POLICY")
    assert api.world.audit.entries[-1].alert is True


def test_control_routes_reject_agents(api):
    # AT-BYP-2: an agent cannot reach the control API, whatever it sends.
    run_id = api.start()
    call = api.call(run_id, {"action": "drive.update", "args": {"content": "x", "shared": True},
                             "request_id": "q1"})[1]  # fmt: skip
    for path in (f"/v1/control/confirms/{call['confirm_id']}:apply", "/v1/control/policies:reload"):
        assert api("POST", path, body=b"{}")[0] == 403
    assert api.world.drive.executed == []


# --- what a body may be (review focus 4)


def test_oversized_body_413(api):
    run_id = api.start()
    chunk = b" " * (64 * 1024)
    chunks = [chunk] * (MAX_BODY_BYTES // len(chunk) + 4)
    status, _ = api("POST", f"/v1/runs/{run_id}/calls", chunks=chunks)
    assert status == 413
    assert api.read <= MAX_BODY_BYTES + len(chunk)  # it stopped reading at the limit
    assert api.world.drive.executed == []


def test_a_content_length_over_the_limit_is_413_unread(api):
    run_id = api.start()
    big = [("Content-Length", str(MAX_BODY_BYTES + 1))]
    status, _ = api("POST", f"/v1/runs/{run_id}/calls", headers=big, chunks=[b"{}"])
    assert status == 413 and api.read == 0


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "drive.read", "args": {}, "request_id": "q1", "agent": "control-ui"},
        {"action": "drive.read", "args": [], "request_id": "q1"},
        {"action": "drive.read", "args": {}},
        {"action": "drive.read", "args": {}, "request_id": ""},
        {"action": "drive.read", "args": {}, "request_id": "x" * 129},
        {"action": "drive.read", "args": {}, "request_id": "q 1"},
        {"action": 3, "args": {}, "request_id": "q1"},
    ],
)
def test_unknown_fields_400(api, payload):
    run_id = api.start()
    assert api.call(run_id, payload)[0] == 400
    assert api.world.drive.executed == []


def test_non_utf8_400(api):
    run_id = api.start()
    status, _ = api("POST", f"/v1/runs/{run_id}/calls", body=b'{"action": "\xff\xfe"}')
    assert status == 400


@pytest.mark.parametrize("body", [b"", b"not json", b"[1, 2]", b'"text"', b"{" * 5000])
def test_a_body_that_is_not_one_json_object_is_400(api, body):
    run_id = api.start()
    assert api("POST", f"/v1/runs/{run_id}/calls", body=body)[0] == 400


def test_deep_json_400(api):
    run_id = api.start()
    deep = {"action": "drive.read", "request_id": "q1", "args": {}}
    nested: dict = {}
    for _ in range(200):
        nested = {"a": nested}
    deep["args"] = nested
    assert api.call(run_id, deep)[0] == 400


def test_a_400_never_repeats_what_was_sent(api):
    run_id = api.start()
    iban = valid_iban()
    status, body = api.call(run_id, {"action": iban, "args": {}, "request_id": "q1"})
    assert status == 400 and iban not in json.dumps(body)


def test_end_takes_usage_and_reason_only(api):
    run_id = api.start()
    good = {"usage": [{"model": "m", "input_tokens": 1, "output_tokens": 2}], "end_reason": "done"}
    status, body = api("POST", f"/v1/runs/{run_id}:end", body=json.dumps(good).encode())
    assert status == 200 and body["run_id"] == run_id
    for bad in (
        {**good, "extra": 1},
        {"usage": [{"model": "m", "input_tokens": -1, "output_tokens": 0}], "end_reason": "done"},
        {"usage": [], "end_reason": "bored"},
        {"usage": [{"model": "m", "input_tokens": True, "output_tokens": 0}], "end_reason": "done"},
    ):
        assert api("POST", f"/v1/runs/{run_id}:end", body=json.dumps(bad).encode())[0] == 400


def test_a_run_starts_with_an_empty_body_or_an_empty_object(api):
    assert api("POST", "/v1/runs", body=b"")[0] == 200
    assert api("POST", "/v1/runs", body=b"{}")[0] == 200
    assert api("POST", "/v1/runs", body=b'{"shadow": false}')[0] == 400


# --- the routes of section 4


def test_the_agent_routes(api):
    status, me = api("GET", "/v1/me")
    assert status == 200 and me["policy_hash"].startswith("sha256:")
    run_id = api.start()
    status, call = api.call(run_id, {"action": "drive.read", "args": {}, "request_id": "q1"})
    assert status == 200 and call["outcome"] == "executed"
    status, again = api("GET", f"/v1/runs/{run_id}/calls/{call['call_id']}")
    assert status == 200 and again["outcome"] == "executed"
    status, summary = api(
        "POST", f"/v1/runs/{run_id}:end", body=b'{"usage": [], "end_reason": "done"}'
    )
    assert status == 200 and summary["calls_by_outcome"] == {"executed": 1}


def test_the_control_routes(api):
    run_id = api.start()
    call = api.call(run_id, {"action": "drive.update", "args": {"content": "x", "shared": True},
                             "request_id": "q1"})[1]  # fmt: skip
    from tests.gateway.test_pipeline import decide_on

    decide_on(api.world, call["confirm_id"])
    status, applied = api(
        "POST", f"/v1/control/confirms/{call['confirm_id']}:apply", token="control-token"
    )
    assert status == 200 and applied["outcome"] == "executed"
    status, _ = api("POST", "/v1/control/policies:reload", token="control-token")
    assert status == 200


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/runs"),
        ("POST", "/v1/me"),
        ("GET", "/v1/runs/r_1/calls"),
        ("POST", "/v1/runs/not-a-run-id/calls"),
        ("GET", "/v1/runs/r_1/calls/not-a-call-id"),
        ("POST", "/v1/control/confirms/zzz:apply"),
        ("GET", "/"),
    ],
)
def test_anything_else_is_404_or_405(api, method, path):
    assert api(method, path, body=b"{}")[0] in (404, 405)


def test_the_policies_are_refreshed_before_each_request(api):
    api("GET", "/v1/me")
    api("GET", "/v1/me")
    assert len(api.world.policies.refreshed) == 2
    assert all(force is False for _, force in api.world.policies.refreshed)


def test_a_crash_inside_is_503_and_prints_the_line(api, monkeypatch, capsys):
    def boom(*args, **kwargs):
        raise RuntimeError("an inner detail")

    monkeypatch.setattr(api.world.gateway, "me", boom)
    status, body = api("GET", "/v1/me")
    assert status == 503 and "inner detail" not in json.dumps(body)
    line = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert line["reason"] == "GATEWAY_ERROR" and line["alert"] is True
