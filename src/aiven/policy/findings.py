"""Validator findings and their messages (validator-spec section 1 and appendix A).

A finding carries a code, a place and the parameters of its message. The text itself lives in
`messages/en.json` and `messages/nl.json`, copied verbatim from appendix A.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import cache
from importlib import resources
from types import MappingProxyType
from typing import Literal

Severity = Literal["error", "warning"]
Lang = Literal["en", "nl"]

LANGUAGES: tuple[Lang, ...] = ("en", "nl")


@dataclass(frozen=True)
class Finding:
    """One result of a check.

    `line` and `column` are 1-based; `line` is None for a finding about the whole file. `params`
    fills the `{placeholders}` of the message. It is left out of the hash because a dict cannot
    be hashed; equal findings still hash equal.
    """

    code: str
    severity: Severity
    path: str
    line: int | None = None
    column: int | None = None
    params: dict[str, str] = field(default_factory=dict, hash=False)


@cache
def load_messages(lang: Lang) -> Mapping[str, str]:
    """The message templates for one language, keyed by code."""
    if lang not in LANGUAGES:
        raise ValueError(f"unknown language {lang!r}; use one of {', '.join(LANGUAGES)}")
    source = resources.files("aiven.policy").joinpath("messages", f"{lang}.json")
    return MappingProxyType(json.loads(source.read_text(encoding="utf-8")))


def message(f: Finding, lang: Lang) -> str:
    """The message of a finding in `en` or `nl`, with its parameters filled in.

    A missing parameter or an unknown code raises KeyError: that is a bug in a check, and it
    must not turn into a half-filled message.
    """
    return load_messages(lang)[f.code].format_map(f.params)


def format_line(f: Finding) -> str:
    """`<severity> <CODE> <path>[:<line>]: <English message>`, the one-line form of a finding."""
    where = f.path if f.line is None else f"{f.path}:{f.line}"
    return f"{f.severity} {f.code} {where}: {message(f, 'en')}"
