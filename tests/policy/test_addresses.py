"""The address rule of `scope.email_to`, which the platform values and the config guard share."""

import pytest

from aiven.policy.addresses import is_address, split_address


@pytest.mark.parametrize(
    "text",
    [
        "author@aivenstudios.com",
        "first.last+tag@aivenstudios.com",
        "a_b%c-d@sub.example.nl",
        "x@xn--bcher-kva.example",
        "7@a.b",
    ],
)
def test_a_full_address(text):
    assert is_address(text)
    assert split_address(text) == tuple(text.split("@"))


@pytest.mark.parametrize(
    "text",
    [
        "",
        "author",
        "@aivenstudios.com",  # a whole domain is a scope entry, not an address
        "Author@aivenstudios.com",
        "author@AivenStudios.com",
        "author@aivenstudios",
        "author@-aivenstudios.com",
        "author@aivenstudios-.com",
        "author@aivenstudios..com",
        "a b@aivenstudios.com",
        "author@@aivenstudios.com",
        "author@aivenstudios.com\n",
        "author@aivenstudios.com ",
        "*@aivenstudios.com",
    ],
)
def test_not_a_full_address(text):
    assert not is_address(text)


def test_a_whole_domain_splits_with_an_empty_local_part():
    assert split_address("@aivenstudios.com") == ("", "aivenstudios.com")
    assert split_address("@aivenstudios") is None
