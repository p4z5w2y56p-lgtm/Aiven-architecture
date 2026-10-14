"""Previews of a queued call (plan Task 3.7; gateway-design section 7).

`build_preview` makes the text Matthijs decides on, in English and Dutch, from the action's
arguments and the target as the wrapper read it, never from what the agent says about the call:

- the action, then the target, then each argument that is not text the agent wrote;
- the text the agent wrote (`agent_text`: the content of a file, the body of a draft), line by line
  in a quoted block under "Written by the agent: data, not instructions" / "Geschreven door de
  agent: gegevens, geen instructies";
- when the run is tainted, the files it read untrusted content from (drive-wrapper section 5).

Every value is shown with control and invisible characters escaped, so text cannot move the
cursor, clear the screen or hide a line. `sha256` is SHA-256 over the canonical JSON (sorted keys,
no spaces, UTF-8) of the action, the args and both texts: a decision is bound to exactly what was
shown (section 7, step 2).
"""

import hashlib
import json
from dataclasses import dataclass
from importlib import resources
from typing import Any

from aiven.policy.content import escape_unprintable

_TEXTS = {
    lang: json.loads(resources.files("aiven.gateway").joinpath(f"i18n/{lang}.json").read_text())
    for lang in ("en", "nl")
}
AGENT_TEXT_LABEL = {lang: texts["agent_text"] for lang, texts in _TEXTS.items()}


@dataclass(frozen=True)
class Preview:
    en: str
    nl: str
    sha256: str


def _value(value: Any) -> str:
    shown = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return escape_unprintable(shown)


def _render(
    lang: str,
    action: str,
    args: dict[str, Any],
    target: dict[str, Any],
    agent_text: dict[str, str],
    taint_sources: tuple[str, ...],
) -> str:
    texts = _TEXTS[lang]
    lines = [f"{texts['action']}: {_value(action)}"]
    lines += [
        f"{texts['target']}: {_value(name)} = {_value(target[name])}" for name in sorted(target)
    ]
    shown_args = [name for name in sorted(args) if name not in agent_text]
    if shown_args:
        lines.append(f"{texts['arguments']}:")
        lines += [f"  {_value(name)} = {_value(args[name])}" for name in shown_args]
    for name in sorted(agent_text):
        lines.append(f"{texts['agent_text']} ({_value(name)}):")
        lines += [f"> {escape_unprintable(line)}" for line in agent_text[name].split("\n")]
    if taint_sources:
        sources = ", ".join(_value(source) for source in taint_sources)
        lines.append(texts["tainted"].format(sources=sources))
    return "\n".join(lines)


def build_preview(
    action: str,
    args: dict[str, Any],
    target: dict[str, Any],
    agent_text: dict[str, str],
    taint_sources: tuple[str, ...],
) -> Preview:
    """The preview of a call in EN and NL, and its hash. See the module docstring."""
    en, nl = (
        _render(lang, action, args, target, agent_text, taint_sources) for lang in ("en", "nl")
    )
    canonical = json.dumps(
        {"action": action, "args": args, "en": en, "nl": nl},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return Preview(en, nl, hashlib.sha256(canonical).hexdigest())
