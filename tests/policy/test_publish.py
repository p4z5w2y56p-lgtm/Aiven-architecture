"""`aiven-policy publish` (plan Task 3.5b; M3 flag #1; Matthijs: only he publishes, with a diff
and one confirmation).

Publishing is Matthijs's step with his own login: the file is validated and verified on his
machine against the trust anchor and the catalog in the control project, the diff against what is
published now is shown, one y/n is asked, and then the file, its signature and the version record
are written in that order. The record is written last, and only if it is still the one that was
read: a failure in between leaves the published version as it was, and a file uploaded without its
record is never loaded (policies.py). Here the bucket and the record store are stand-ins.
"""

import hashlib
import io
from datetime import UTC, datetime

import pytest

from aiven.gateway.control import PolicyVersion
from aiven.policy import publish
from tests.gateway.fakes import FakeBucket, FakeReleases
from tests.support import REPO_ROOT
from tests.support.policies import platform_config
from tests.support.rules import setting
from tests.support.signing import make_signer
from tests.support.signing import work_in_a_temporary_folder as work_in_a_temporary_folder
from tests.support.variants import variant_file

AT = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)
AGENT = "invoice-reminder"
CATALOG = (REPO_ROOT / "catalog" / "catalog-v1.yaml").read_bytes()
V1 = variant_file(render=True)
V2 = variant_file(setting("version", 2), render=True)
V3 = variant_file(setting("version", 3), render=True)


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class World:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.signer = make_signer(tmp_path / "keys", namespaces="aiven-policy-v1,aiven-catalog-v1")
        self.bucket = FakeBucket()
        self.bucket.put("allowed_signers", self.signer.allowed_signers.read_bytes())
        self.bucket.put("catalog/catalog-v1.yaml", CATALOG)
        self.bucket.put(
            "catalog/catalog-v1.yaml.sig", self.signer.sign(CATALOG, namespace="aiven-catalog-v1")
        )
        self.releases = FakeReleases()
        self.releases.bucket = self.bucket
        self.answers: list[str] = []
        self.out = io.StringIO()

    def files(self, data: bytes, *, sig: bytes | None = None, name: str = AGENT):
        folder = self.tmp / "policies"
        folder.mkdir(exist_ok=True)
        path = folder / f"{name}.md"
        path.write_bytes(data)
        sig_path = folder / f"{name}.md.sig"
        sig_path.write_bytes(self.signer.sign(data) if sig is None else sig)
        return path, sig_path

    def confirm(self, prompt: str) -> bool:
        self.answers.append(prompt)
        return True

    def policy(self, data: bytes, *, sig: bytes | None = None, confirm=None) -> int:
        path, sig_path = self.files(data, sig=sig)
        return publish.publish_policy(
            path,
            sig_path,
            bucket=self.bucket,
            releases=self.releases,
            cfg=platform_config(),
            by="m.vanhoorn@aivenstudios.com",
            confirm=confirm or self.confirm,
            out=self.out,
            now=lambda: AT,
        )

    def said(self) -> str:
        return self.out.getvalue()


@pytest.fixture
def world(tmp_path) -> World:
    return World(tmp_path)


def test_a_first_version_is_published_after_one_confirmation(world):
    assert world.policy(V1) == 0, world.said()
    assert world.bucket.objects["policies/invoice-reminder.md"].data == V1
    assert world.bucket.objects["policies/invoice-reminder.md.sig"].data
    assert world.releases.records[AGENT] == PolicyVersion(
        1, sha(V1), "m.vanhoorn@aivenstudios.com", AT
    )
    (prompt,) = world.answers
    assert "invoice-reminder" in prompt and "version 1" in prompt
    assert "published" in world.said()
    # The published catalog still has every wrapper planned: publishing is fine, loading waits.
    assert "note: sheets.read needs the Drive wrapper, which is not built yet" in world.said()


def test_the_diff_against_the_published_version_is_shown(world):
    world.policy(V1)
    world.answers.clear()
    assert world.policy(V2) == 0
    said = world.said()
    assert "-version: 1" in said and "+version: 2" in said
    assert "version 1 -> 2" in said


def test_record_written_only_after_both_uploads(world):
    world.policy(V1)
    assert world.releases.uploads_seen == [
        ["policies/invoice-reminder.md", "policies/invoice-reminder.md.sig"]
    ]
    # The file goes before its signature: in between, the gateway keeps the active version (R184).


def test_publish_refuses_a_lower_or_equal_version(world):
    world.policy(V2)
    world.answers.clear()
    uploads = len(world.bucket.uploads)
    other_v2 = variant_file(
        setting("version", 2), setting("limits.records_per_run", 9), render=True
    )
    assert world.policy(V1) == 1
    assert world.policy(other_v2) == 1
    assert "E-VERSION-ORDER" in world.said()
    assert world.answers == [] and len(world.bucket.uploads) == uploads
    assert world.releases.records[AGENT].version == 2


def test_publishing_what_is_published_does_nothing(world):
    world.policy(V1)
    uploads = len(world.bucket.uploads)
    assert world.policy(V1) == 0
    assert "already published" in world.said() and len(world.bucket.uploads) == uploads


def test_publish_refuses_an_unsigned_file(world, tmp_path):
    thief = make_signer(tmp_path / "thief")
    assert world.policy(V1, sig=thief.sign(V1)) == 1
    assert "E-SIG-INVALID" in world.said()
    assert world.bucket.uploads == [] and world.releases.records == {}


def test_a_no_publishes_nothing(world):
    assert world.policy(V1, confirm=lambda prompt: False) == 1
    assert world.bucket.uploads == [] and world.releases.records == {}
    assert "nothing was published" in world.said()


def test_a_bucket_that_changed_meanwhile_stops_before_the_record(world):
    world.bucket.fail_upload_of = "policies/invoice-reminder.md.sig"
    assert world.policy(V1) == 1
    assert world.releases.records == {}  # the record stays as it was
    assert "changed" in world.said()


def test_a_record_that_changed_meanwhile_is_not_overwritten(world):
    world.policy(V1)

    def someone_else_published(prompt):
        world.releases.records[AGENT] = PolicyVersion(3, sha(V3), "other", AT)
        return True

    assert world.policy(V2, confirm=someone_else_published) == 1
    assert world.releases.records[AGENT].version == 3
    assert "Run publish again" in world.said()


def test_publish_needs_the_trust_anchor_and_the_catalog_in_the_bucket(world):
    del world.bucket.objects["catalog/catalog-v1.yaml.sig"]
    assert world.policy(V1) == 1
    assert "catalog" in world.said()
    del world.bucket.objects["allowed_signers"]
    assert world.policy(V1) == 1
    assert "allowed_signers" in world.said()


def test_publish_never_prints_a_value(world):
    # What goes wrong with Google is named by its class only: a message can hold a token.
    class Leaky(FakeReleases):
        def get(self, agent):
            raise RuntimeError("ya29.a0-secret-token-value")

    world.releases = Leaky()
    assert world.policy(V1) == 2
    assert "ya29" not in world.said() and "RuntimeError" in world.said()


# --- the catalog and the trust anchor


def test_the_catalog_is_published_under_its_own_namespace(world, tmp_path):
    new = CATALOG + b"# reviewed again\n"
    path, sig = tmp_path / "catalog-v1.yaml", tmp_path / "catalog-v1.yaml.sig"
    path.write_bytes(new)
    sig.write_bytes(world.signer.sign(new, namespace="aiven-catalog-v1"))
    status = publish.publish_catalog(
        path, sig, bucket=world.bucket, confirm=world.confirm, out=world.out
    )
    assert status == 0 and world.bucket.objects["catalog/catalog-v1.yaml"].data == new
    assert "+# reviewed again" in world.said()


def test_a_catalog_signed_as_a_policy_is_refused(world, tmp_path):
    path, sig = tmp_path / "catalog-v1.yaml", tmp_path / "catalog-v1.yaml.sig"
    path.write_bytes(CATALOG)
    sig.write_bytes(world.signer.sign(CATALOG, namespace="aiven-policy-v1"))
    uploads = len(world.bucket.uploads)
    assert publish.publish_catalog(path, sig, bucket=world.bucket, confirm=world.confirm,
                                   out=world.out) == 1  # fmt: skip
    assert len(world.bucket.uploads) == uploads and world.answers == []


def test_the_trust_anchor_is_published_with_a_diff_and_a_confirmation(world, tmp_path):
    anchor = tmp_path / "allowed_signers"
    anchor.write_bytes(world.signer.allowed_signers.read_bytes() + b"# second line\n")
    status = publish.publish_allowed_signers(
        anchor, bucket=world.bucket, confirm=world.confirm, out=world.out
    )
    assert status == 0 and "+# second line" in world.said()
    assert len(world.answers) == 1


def test_a_trust_anchor_without_the_catalog_namespace_is_refused(world, tmp_path):
    anchor = tmp_path / "allowed_signers"
    anchor.write_text('matthijs namespaces="aiven-policy-v1" ssh-ed25519 AAAA\n')
    status = publish.publish_allowed_signers(
        anchor, bucket=world.bucket, confirm=world.confirm, out=world.out
    )
    assert status == 1 and "aiven-catalog-v1" in world.said() and world.answers == []


def test_a_catalog_in_the_bucket_that_is_badly_signed_or_invalid_stops_a_policy(world):
    world.bucket.put("catalog/catalog-v1.yaml", CATALOG + b"# changed\n")
    assert world.policy(V1) == 1 and "not validly signed" in world.said()
    bad = b"schema: aiven-catalog/v9\n"
    world.bucket.put("catalog/catalog-v1.yaml", bad)
    world.bucket.put(
        "catalog/catalog-v1.yaml.sig", world.signer.sign(bad, namespace="aiven-catalog-v1")
    )
    assert world.policy(V1) == 1 and "not valid catalog v1" in world.said()


def test_a_signed_catalog_that_is_not_valid_v1_is_not_published(world, tmp_path):
    bad = b"schema: aiven-catalog/v9\n"
    path, sig = tmp_path / "c.yaml", tmp_path / "c.yaml.sig"
    path.write_bytes(bad)
    sig.write_bytes(world.signer.sign(bad, namespace="aiven-catalog-v1"))
    assert publish.publish_catalog(path, sig, bucket=world.bucket, confirm=world.confirm,
                                   out=world.out) == 1  # fmt: skip
    assert "not valid catalog v1" in world.said()


def test_the_published_catalog_again_does_nothing_and_a_no_does_nothing(world, tmp_path):
    path, sig = tmp_path / "c.yaml", tmp_path / "c.yaml.sig"
    path.write_bytes(CATALOG)
    sig.write_bytes(world.signer.sign(CATALOG, namespace="aiven-catalog-v1"))
    run = lambda confirm: publish.publish_catalog(  # noqa: E731
        path, sig, bucket=world.bucket, confirm=confirm, out=world.out
    )
    assert run(world.confirm) == 0 and "already published" in world.said()
    path.write_bytes(CATALOG + b"# x\n")
    sig.write_bytes(world.signer.sign(CATALOG + b"# x\n", namespace="aiven-catalog-v1"))
    assert run(lambda prompt: False) == 1 and "nothing was published" in world.said()


def test_a_trust_anchor_that_trusts_nobody_is_refused(world, tmp_path):
    anchor = tmp_path / "allowed_signers"
    anchor.write_text("# only a comment\n")
    assert publish.publish_allowed_signers(anchor, bucket=world.bucket, confirm=world.confirm,
                                           out=world.out) == 1  # fmt: skip
    assert "trusts nobody" in world.said()


@pytest.mark.parametrize(
    ("typed", "answer"),
    [("y\n", True), ("YES\n", True), ("n\n", False), ("\n", False), ("", False)],
)
def test_only_y_or_yes_publishes(monkeypatch, typed, answer):
    def fake_input(prompt):
        if not typed:
            raise EOFError
        return typed.rstrip("\n")

    monkeypatch.setattr("builtins.input", fake_input)
    assert publish._ask("Publish? (y/n) ") is answer


def test_the_records_in_firestore(tmp_path):
    import os
    import uuid

    if not os.environ.get("FIRESTORE_EMULATOR_HOST"):
        if os.environ.get("AIVEN_REQUIRE_EMULATOR") == "1":
            pytest.fail("AIVEN_REQUIRE_EMULATOR=1, but FIRESTORE_EMULATOR_HOST is not set")
        pytest.skip("the Firestore emulator is not running (FIRESTORE_EMULATOR_HOST)")
    from google.cloud import firestore

    client = firestore.Client(project=f"rel-{uuid.uuid4().hex[:12]}", database="releases")
    releases = publish.FirestoreReleases(client)
    v1 = PolicyVersion(1, sha(V1), "m", AT)
    v2 = PolicyVersion(2, sha(V2), "m", AT)
    assert releases.get(AGENT) is None
    assert releases.put_if(AGENT, None, v1) is True
    assert releases.get(AGENT) == v1
    assert releases.put_if(AGENT, None, v2) is False  # someone published meanwhile
    assert releases.put_if(AGENT, v1, v2) is True and releases.get(AGENT) == v2


def test_no_note_for_a_tool_whose_wrapper_is_built(world):
    built = CATALOG.replace(b"drive: planned", b"drive: built")
    world.bucket.put("catalog/catalog-v1.yaml", built)
    world.bucket.put(
        "catalog/catalog-v1.yaml.sig", world.signer.sign(built, namespace="aiven-catalog-v1")
    )
    assert world.policy(V1) == 0
    assert "sheets.read needs" not in world.said() and "gmail.send needs" in world.said()


def test_the_command_line_hands_publish_to_its_own_parser(monkeypatch):
    from aiven.policy import cli

    seen = []
    monkeypatch.setattr(publish, "main", lambda argv: seen.append(list(argv)) or 0)
    assert cli.main(["publish", "policies/a.md", "--sig", "s"]) == 0
    assert seen == [["policies/a.md", "--sig", "s"]]
