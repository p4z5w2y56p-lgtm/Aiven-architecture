"""Counting the calls of the functions of a module while they run.

The tests of `validate_policy` and of `verify` use this to show that every check of validate.py runs
once for a file, and that none of them has run before the signature of a file holds.
"""

from collections import Counter

# The checks of validate.py that read a file. Each of them runs once for a file, whatever is done
# with the result.
CHECKS = (
    "decode_text",
    "check_file",
    "scan",
    "split",
    "load",
    "build_policy",
    "check_filename",
    "check_body",
)


def _counting(name, real, calls):
    """A stand-in for the function `real` that counts its calls under `name`, and lets it run."""

    def spy(*args, **kwargs):
        calls[name] += 1
        return real(*args, **kwargs)

    return spy


def spy_on(monkeypatch, module, names, calls: Counter | None = None) -> Counter:
    """Count the calls of the functions `names` of `module` in `calls`, and let them run.

    Give the `calls` of an earlier call to count the functions of more than one module together.
    """
    calls = Counter() if calls is None else calls
    for name in names:
        monkeypatch.setattr(module, name, _counting(name, getattr(module, name), calls))
    return calls
