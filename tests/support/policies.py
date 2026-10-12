"""The valid base policy that the code tests mutate (validator-spec section 9).

`valid_base()` is the template turned into a real policy: the two placeholders are filled in, and
since the generated sections are a faithful render of the front matter, a plain text substitution
equals re-rendering. Task 1.5 adds a test that proves this.
"""

from pathlib import Path

from tests.support import REPO_ROOT

TEMPLATE_PATH = REPO_ROOT / "templates" / "policy-template.md"

# The path that tests pass to the validator: the base, saved under its agent's name.
BASE_PATH = Path("policies/invoice-reminder.md")

AGENTS_PROJECT = "aiven-agents-test"
FOLDER_ID = "1aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"


def valid_base() -> bytes:
    """The template with `REPLACE_ME_AGENTS_PROJECT` and `REPLACE_ME_FOLDER_ID` filled in."""
    text = TEMPLATE_PATH.read_bytes().decode("utf-8")
    text = text.replace("REPLACE_ME_AGENTS_PROJECT", AGENTS_PROJECT)
    text = text.replace("REPLACE_ME_FOLDER_ID", FOLDER_ID)
    return text.encode("utf-8")


def line_of(text: str, needle: str) -> int:
    """The 1-based number of the one line of `text` that contains `needle`.

    Tests find their target lines by content, so they survive an edit of the template.
    """
    found = [number for number, line in enumerate(text.split("\n"), start=1) if needle in line]
    if len(found) != 1:
        raise LookupError(f"expected exactly one line containing {needle!r}, found {len(found)}")
    return found[0]
