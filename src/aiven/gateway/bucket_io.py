"""Capped reads from the policy bucket (plan Task 3.5; M3 flag #3).

Every object the gateway reads from the bucket has a cap: a policy, the catalog, `allowed_signers`
and the price list `MAX_FILE_BYTES`, a signature `MAX_SIG_BYTES`. `read_capped` checks the size in
the object's metadata first, and refuses an object over the cap without reading any of it. The
object can change between the metadata and the read, so the read itself is ranged to `cap + 1`
bytes: an object that grew is refused after `cap + 1` bytes at most, never read whole.
"""

from typing import Any, Protocol


class Missing(Exception):
    """The object does not exist."""


class TooLarge(Exception):
    """The object is over its cap; it was not read past `cap + 1` bytes."""


class Bucket(Protocol):
    """What the reader needs of a bucket: google.cloud.storage's Bucket has it."""

    def get_blob(self, name: str) -> Any: ...


def read_capped(bucket: Bucket, name: str, cap: int) -> bytes:
    """The bytes of object `name`, which must be at most `cap` bytes. See the module docstring."""
    blob = bucket.get_blob(name)
    if blob is None:
        raise Missing(name)
    if blob.size is None or blob.size > cap:
        raise TooLarge(name)
    data = blob.download_as_bytes(start=0, end=cap)  # `end` is inclusive: cap + 1 bytes at most
    if len(data) > cap:
        raise TooLarge(name)
    return bytes(data)
