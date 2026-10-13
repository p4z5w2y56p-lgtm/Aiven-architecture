"""Every message code has a failing case (validator-spec appendix A).

A code that no test can trigger is a check that nobody has seen fail. The codes of the messages
(`messages/en.json`) are held against what the tests of the validator declare:

- the tables of test_codes.py: `CASES` (a change to the valid file gives that code, and only that
  one) and `SET_CASES` (the checks across the files);
- `COVERED_ELSEWHERE` of test_codes.py: the codes that a test function of its own covers, because
  the table cannot (E-FILENAME changes the path and not the bytes);
- `CODES_TRIGGERED` of test_verify.py and of test_cli.py: the codes that the tests of those modules
  trigger, and that no table has.

Each of the three declarations is a mapping from a code to the name of the test, in the same
module, that triggers it. Nothing here looks into a test to find the codes it triggers. Every claim
is a declaration, and the tests below hold the declarations to what they can be held to: they name
codes that exist, and the tests that they name exist and mention the code.
"""

import inspect

import pytest

from aiven.policy.findings import load_messages
from tests.policy import test_cli, test_codes, test_verify

CODES = frozenset(load_messages("en"))

TABLES = frozenset(param.values[0] for param in (*test_codes.CASES, *test_codes.SET_CASES))
# For each declaration: the module whose tests it names, and the mapping from a code to a test.
DECLARED = {
    "COVERED_ELSEWHERE of test_codes.py": (test_codes, test_codes.COVERED_ELSEWHERE),
    "CODES_TRIGGERED of test_verify.py": (test_verify, test_verify.CODES_TRIGGERED),
    "CODES_TRIGGERED of test_cli.py": (test_cli, test_cli.CODES_TRIGGERED),
}


def test_every_code_has_a_failing_case():
    covered = TABLES.union(*(set(declared) for _, declared in DECLARED.values()))
    assert sorted(CODES - covered) == []


def test_the_tables_and_the_declarations_name_codes_that_exist():
    # A code that is mistyped or was renamed covers nothing, and must not look as if it did.
    assert sorted(TABLES - CODES) == []
    for where, (_, declared) in DECLARED.items():
        assert sorted(set(declared) - CODES) == [], where


@pytest.mark.parametrize("where", DECLARED)
def test_each_declared_code_names_a_test_that_exists_and_mentions_the_code(where):
    module, declared = DECLARED[where]
    for code, name in declared.items():
        triggering = getattr(module, name, None)
        assert name.startswith("test_") and inspect.isfunction(triggering), (code, name)
        assert code in inspect.getsource(triggering), (code, name)
