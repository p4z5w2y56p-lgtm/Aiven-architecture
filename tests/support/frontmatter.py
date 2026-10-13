"""Front matter texts for the tests: what the template says, and edited copies of it.

`DATA` is what the front matter of `valid_base()` says, as Python values. `edited(change)` writes
a changed copy of it as YAML, so that a test can remove or add a field without YAML by hand.
`swap` does the same on the template's own text, comments and all.
"""

from copy import deepcopy

from aiven.policy.frontmatter import split
from tests.support.policies import AGENTS_PROJECT, FOLDER_ID, line_of, valid_base

BASE_TEXT = valid_base().decode("utf-8")
FRONT, _, _ = split(BASE_TEXT)

DATA = {
    "schema": "aiven-policy/v1",
    "agent": "invoice-reminder",
    "version": 1,
    "principal": f"agent-invoice-reminder@{AGENTS_PROJECT}.iam.gserviceaccount.com",
    "max_class": "R2",
    "tools": ["sheets.read", "gmail.draft", "gmail.send"],
    "forbidden": ["payments.*", "drive.delete", "drive.share", "gmail.send_bulk"],
    "untrusted_input": "strict",
    "limits": {
        "emails_per_day": 10,
        "records_per_run": 10,
        "spend_eur_per_run": 0,
        "max_runtime_s": 300,
        "runs_per_day": 1,
    },
    "scope": {
        "drive_folder_id": FOLDER_ID,
        "drive_folder_path": "AIVEN Architecture Sandbox / Invoices",
        "email_to": ["@aivenstudios.com"],
    },
    "shadow": {"min_runs": 10},
}


def emit(data: dict, indent: int = 0) -> list[str]:
    """YAML lines for `data`: a mapping of strings, integers, lists of strings and mappings."""
    pad = " " * indent
    lines = []
    for key, value in data.items():
        if isinstance(value, dict) and value:
            lines += [f"{pad}{key}:", *emit(value, indent + 2)]
        elif isinstance(value, dict):
            lines.append(f"{pad}{key}: {{}}")
        elif isinstance(value, list):
            lines += [f"{pad}{key}:", *[f'{pad}  - "{item}"' for item in value]]
        else:
            lines.append(f"{pad}{key}: {value}")
    return lines


def lookup(data: dict, parents: list[str]):
    """The mapping inside `data` that the keys in `parents` lead to."""
    for parent in parents:
        data = data[parent]
    return data


def edited(change) -> str:
    """Front matter text of a copy of `DATA` that `change(data)` has edited."""
    data = deepcopy(DATA)
    change(data)
    return "\n".join(emit(data)) + "\n"


def front_without(*paths: str) -> str:
    """Front matter text of `DATA` minus the given fields (`limits.runs_per_day`, `scope`)."""

    def remove(data):
        for path in paths:
            *parents, name = path.split(".")
            del lookup(data, parents)[name]

    return edited(remove)


def swap(old: str, new: str) -> str:
    """The template's front matter with the one place where `old` stands replaced by `new`."""
    assert FRONT.count(old) == 1, old
    return FRONT.replace(old, new)


def at(needle: str) -> int:
    """The file line of the one template line that holds `needle`."""
    return line_of(BASE_TEXT, needle)


def places(result, code: str | None = None) -> list[tuple[str, int | None, int | None]]:
    """(code, line, column) of the findings of a `load` result, of one code if one is given."""
    return [(f.code, f.line, f.column) for f in result.findings if code in (None, f.code)]


def only(result, code: str | None = None):
    """The one finding of a `load` result (of the given code), which must be the only one."""
    (finding,) = [f for f in result.findings if code in (None, f.code)]
    return finding
