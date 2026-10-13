"""The address rule of `scope.email_to` (validator-spec section 3.5), shared with the platform values.

An address is `local@domain` in lower case. The local part is letters, digits and `._%+-`; the
domain is two or more labels of letters and digits, with hyphens inside a label (so punycode
passes). A scope entry may leave the local part out (`@domain`, the whole domain); an address in
the platform values (`trusted_authors`) and the Terraform values (`alert_email`) may not.
"""

import re

# Every pattern is used with fullmatch: `$` would accept a trailing newline.
_LOCAL_PART = re.compile(r"[a-z0-9._%+-]+")
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")


def split_address(text: str) -> tuple[str, str] | None:
    """`(local, domain)` when `text` is `local@domain` or `@domain` by the rule, else None.

    The local part is empty for `@domain`.
    """
    local, at, domain = text.partition("@")
    labels = domain.split(".")
    if (
        not at
        or (local and not _LOCAL_PART.fullmatch(local))
        or len(labels) < 2
        or not all(_DOMAIN_LABEL.fullmatch(label) for label in labels)
    ):
        return None
    return local, domain


def is_address(text: str) -> bool:
    """Whether `text` is one full address, `local@domain`, by the rule."""
    parts = split_address(text)
    return parts is not None and parts[0] != ""
