"""Google ID tokens (plan Task 3.3; gateway-design section 4).

The verifier is tested with real RS256 tokens, signed by a throwaway key made for each test run,
and that key's certificate standing in for Google's certificate list.
"""

import datetime as dt
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from google.auth import crypt, jwt

from aiven.gateway.auth import GoogleTokenVerifier, caller_of

AUDIENCE = "https://gateway-123.europe-west4.run.app"
EMAIL = "agent-a@aiven-agents-test.iam.gserviceaccount.com"


def key_and_cert(name: str) -> tuple[bytes, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return private, cert.public_bytes(serialization.Encoding.PEM).decode()


GOOGLE_KEY, GOOGLE_CERT = key_and_cert("google")
OTHER_KEY, _ = key_and_cert("other")


def token(key: bytes = GOOGLE_KEY, kid: str = "k1", **claims) -> str:
    now = int(time.time())
    payload = {
        "iss": "https://accounts.google.com",
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 600,
        "email": EMAIL,
        "email_verified": True,
    }
    payload.update(claims)
    signer = crypt.RSASigner.from_string(key, kid)
    return jwt.encode(signer, payload).decode()


class Certs:
    def __init__(self):
        self.fetches = 0
        self.certs = {"k1": GOOGLE_CERT}

    def __call__(self):
        self.fetches += 1
        return dict(self.certs)


def test_a_google_token_for_this_audience_gives_its_claims():
    verify = GoogleTokenVerifier(Certs())
    claims = verify(token(), AUDIENCE)
    assert claims["email"] == EMAIL and claims["email_verified"] is True


@pytest.mark.parametrize(
    "bad",
    [
        lambda: token(aud="https://another.run.app"),
        lambda: token(iss="https://evil.example"),
        lambda: token(exp=int(time.time()) - 3600, iat=int(time.time()) - 7200),
        lambda: token(key=OTHER_KEY),
        lambda: token(kid="unknown"),
        lambda: "not.a.token",
    ],
)
def test_any_other_token_is_refused(bad):
    with pytest.raises(ValueError):
        GoogleTokenVerifier(Certs())(bad(), AUDIENCE)


def test_the_certificates_are_kept_and_fetched_again_for_a_new_key():
    certs = Certs()
    verify = GoogleTokenVerifier(certs)
    verify(token(), AUDIENCE)
    verify(token(), AUDIENCE)
    assert certs.fetches == 1
    certs.certs["k2"] = GOOGLE_CERT
    verify(token(kid="k2"), AUDIENCE)
    assert certs.fetches == 2


def test_the_caller_is_the_email_of_a_verified_token():
    verify = GoogleTokenVerifier(Certs())
    found = caller_of(f"Bearer {token()}", verifier=verify, audience=AUDIENCE, control_ui="ui@x")
    assert (found.email, found.kind) == (EMAIL, "agent")
    ui = token(email="ui@x")
    found = caller_of(f"Bearer {ui}", verifier=verify, audience=AUDIENCE, control_ui="ui@x")
    assert found.kind == "control"
    unverified = token(email_verified=False)
    assert caller_of(f"Bearer {unverified}", verifier=verify, audience=AUDIENCE,
                     control_ui="ui@x") is None  # fmt: skip
    no_email = token(email=None)
    assert caller_of(f"Bearer {no_email}", verifier=verify, audience=AUDIENCE,
                     control_ui="ui@x") is None  # fmt: skip
