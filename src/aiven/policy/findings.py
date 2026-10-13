"""Validator findings and their messages (validator-spec section 1 and appendix A).

A finding carries a code, a place and the parameters of its message. The text itself lives in
`messages/en.json` and `messages/nl.json`, copied verbatim from appendix A.

Text from a file reaches a finding only through its `params` and its `path`. A finding cleans both
when it is made (see `content.safe_text`), and `message` cleans the params again as it fills them
in. So whichever check builds a finding, it cannot put what `content.is_sensitive` recognises (a
credential, a bank detail, an ID number) into a message, and it cannot start a second line, not
even when a param is changed afterwards. What is read from `params` directly (a JSON writer, say)
was cleaned when the finding was made; the dict is not frozen, so such a reader runs `safe_text`
over the values itself.

A check that quotes only a part of a longer word must judge the whole word with `is_sensitive`
first, as E-PLACEHOLDER does: a part that is cut inside the characters of a key no longer matches
by itself, so the guard cannot see what it was cut from.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import cache
from importlib import resources
from types import MappingProxyType
from typing import Literal

from aiven.policy.content import escape_unprintable, safe_text

Severity = Literal["error", "warning"]
Lang = Literal["en", "nl"]

LANGUAGES: tuple[Lang, ...] = ("en", "nl")


@dataclass(frozen=True)
class Finding:
    """One result of a check.

    `line` and `column` are 1-based; `line` is None for a finding about the whole file. `params`
    fills the `{placeholders}` of the message. It is left out of the hash because a dict cannot
    be hashed; equal findings still hash equal.

    Making a finding cleans it. Each value in `params` goes through `safe_text`: a value that
    holds a credential, a bank detail or an ID number becomes `[hidden]`, unprintable and
    invisible characters are written as escapes, and a long value is cut to 200 characters. The
    `path` only gets the escapes. Cleaning again (`dataclasses.replace` does, and so does
    `message`) never shows more than the first time. It can hide more: the escape of one
    character ends in hex digits, and digits next to them can make a window that passes a
    checksum.
    """

    code: str
    severity: Severity
    path: str
    line: int | None = None
    column: int | None = None
    params: dict[str, str] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        # The dataclass is frozen, so the cleaned values go in with object.__setattr__.
        object.__setattr__(self, "path", escape_unprintable(self.path))
        object.__setattr__(
            self, "params", {name: safe_text(value) for name, value in self.params.items()}
        )


@cache
def load_messages(lang: Lang) -> Mapping[str, str]:
    """The message templates for one language, keyed by code."""
    if lang not in LANGUAGES:
        raise ValueError(f"unknown language {lang!r}; use one of {', '.join(LANGUAGES)}")
    source = resources.files("aiven.policy").joinpath("messages", f"{lang}.json")
    return MappingProxyType(json.loads(source.read_text(encoding="utf-8")))


def message(f: Finding, lang: Lang) -> str:
    """The message of a finding in `en` or `nl`, with its parameters filled in.

    Every param goes through `safe_text` again as it is filled in, so a param that was changed
    after the finding was made (the dict is not frozen) is still hidden, escaped and cut. That can
    only hide more than `f.params` shows.

    A missing parameter or an unknown code raises KeyError: that is a bug in a check, and it
    must not turn into a half-filled message.
    """
    params = {name: safe_text(value) for name, value in f.params.items()}
    return load_messages(lang)[f.code].format_map(params)


def format_line(f: Finding) -> str:
    """`<severity> <CODE> <path>[:<line>]: <English message>`, the one-line form of a finding."""
    where = f.path if f.line is None else f"{f.path}:{f.line}"
    return f"{f.severity} {f.code} {where}: {message(f, 'en')}"
