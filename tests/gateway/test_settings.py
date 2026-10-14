"""The gateway's settings and its assembly (plan Task 3.10; M3 plan "Names from Terraform").

Terraform sets the environment of the Cloud Run service (modules/gateway/run.tf); the gateway takes
every name from there, never from a file an agent can reach. `build` puts the parts together; here
the Google clients are stand-ins.
"""

import os

import pytest

from aiven.gateway.settings import Settings, SettingsError, build
from tests.gateway.fakes import FakeBucket

ENV = {
    "GATEWAY_URL": "https://gateway-123456789.europe-west4.run.app",
    "GATEWAY_PROJECT": "aiven-gateway-test",
    "CONTROL_PROJECT": "aiven-control-test",
    "AGENTS_PROJECT": "aiven-agents-test",
    "POLICY_BUCKET": "aiven-control-test-policies",
    "SNAPSHOT_BUCKET": "aiven-control-test-snapshots",
    "GATEWAY_PRINCIPAL": "gateway@aiven-gateway-test.iam.gserviceaccount.com",
    "CONTROL_UI_EMAIL": "control-ui@aiven-control-test.iam.gserviceaccount.com",
    "TRUSTED_AUTHORS": "m.vanhoorn@aivenstudios.com",
    "SANDBOX_DRIVE_ID": "0ANG6akvi_bACUk9PVA",
}


def test_the_settings_are_read_from_the_environment():
    settings = Settings.from_env(ENV)
    assert settings.audience == ENV["GATEWAY_URL"]
    assert settings.cfg.agents_project == "aiven-agents-test"
    assert settings.cfg.trusted_authors == ("m.vanhoorn@aivenstudios.com",)
    assert settings.cfg.sandbox_drive_id == "0ANG6akvi_bACUk9PVA"


@pytest.mark.parametrize("name", sorted(set(ENV) - {"SANDBOX_DRIVE_ID"}))
def test_a_missing_setting_is_named(name):
    env = {k: v for k, v in ENV.items() if k != name}
    with pytest.raises(SettingsError, match=name):
        Settings.from_env(env)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("GATEWAY_URL", "http://gateway.example"),
        ("CONTROL_PROJECT", "Not A Project"),
        ("GATEWAY_PRINCIPAL", "someone@gmail.com"),
        ("TRUSTED_AUTHORS", ""),
    ],
)
def test_a_wrong_setting_is_refused(name, value):
    with pytest.raises(SettingsError, match=name):
        Settings.from_env({**ENV, name: value})


def test_no_sandbox_yet_is_allowed():
    assert Settings.from_env({**ENV, "SANDBOX_DRIVE_ID": ""}).cfg.sandbox_drive_id is None


@pytest.fixture(autouse=True)
def keep_path(monkeypatch):
    """build() gives the process the system's PATH (as on Cloud Run); the tests put it back."""
    monkeypatch.setenv("PATH", os.environ["PATH"])


def test_build_assembles_the_gateway_and_refuses_to_start_without_a_catalog(tmp_path):
    from aiven.gateway.policies import StartupRefused

    made = []

    class Clients:
        def firestore(self, project, database):
            made.append(("firestore", project, database))
            return object()

        def bucket(self, project, name):
            made.append(("bucket", project, name))
            return FakeBucket()  # empty: no trust anchor, no catalog

        def audit(self, project):
            from tests.gateway.fakes import FakeAudit

            return FakeAudit()

    with pytest.raises(StartupRefused):
        build(ENV, clients=Clients(), check_ssh_keygen=lambda path: None)
    assert ("firestore", "aiven-gateway-test", "gateway") in made
    assert ("firestore", "aiven-control-test", "control") in made
    assert ("firestore", "aiven-control-test", "releases") in made
    assert ("bucket", "aiven-control-test", "aiven-control-test-policies") in made


def test_a_wrong_sandbox_id_is_refused():
    with pytest.raises(SettingsError, match="SANDBOX_DRIVE_ID"):
        Settings.from_env({**ENV, "SANDBOX_DRIVE_ID": "not/a/drive"})


def test_build_gives_the_app_when_the_catalog_is_signed(tmp_path, monkeypatch):
    from starlette.applications import Starlette

    from tests.support import REPO_ROOT
    from tests.support.signing import make_signer

    signer = make_signer(tmp_path / "keys", namespaces="aiven-policy-v1,aiven-catalog-v1")
    catalog = (REPO_ROOT / "catalog" / "catalog-v1.yaml").read_bytes()
    bucket = FakeBucket()
    bucket.put("allowed_signers", signer.allowed_signers.read_bytes())
    bucket.put("catalog/catalog-v1.yaml", catalog)
    bucket.put("catalog/catalog-v1.yaml.sig", signer.sign(catalog, namespace="aiven-catalog-v1"))

    class Clients:
        def firestore(self, project, database):
            from tests.gateway.fakes import FakeControl

            return FakeControl()  # never read here: no record is asked for in this test

        def bucket(self, project, name):
            return bucket

        def audit(self, project):
            from tests.gateway.fakes import FakeAudit

            return FakeAudit()

    import aiven.gateway.settings as settings_module

    class StubControl:
        def __init__(self, *clients):
            pass

        def policy_versions(self):
            return {}

        def wrapper_live(self, wrapper, agent):
            return False

    import aiven.gateway.control as control_module

    monkeypatch.setattr(control_module, "FirestoreControl", StubControl)
    app = settings_module.build(ENV, clients=Clients(), check_ssh_keygen=lambda path: None)
    assert isinstance(app, Starlette)
