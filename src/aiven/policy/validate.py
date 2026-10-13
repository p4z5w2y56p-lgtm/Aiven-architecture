"""The validator's single entry point: every check, and one sorted list of findings.

Task by task the other checks join the two here (front matter, fields, tools, limits, body). The
CLI and `verify` call `validate_file` and nothing below it.
"""

from pathlib import Path

from aiven.policy.catalog import Catalog
from aiven.policy.config import PlatformConfig
from aiven.policy.content import KIND_CODES, ContentHit, scan
from aiven.policy.fileformat import check_file, decode_text
from aiven.policy.findings import Finding
from aiven.policy.frontmatter import check_filename, load, split


def validate_file(path: Path, data: bytes, cfg: PlatformConfig, catalog: Catalog) -> list[Finding]:
    """All findings for the policy file `data` that is called `path`.

    The file checks, the content checks and the front matter checks need neither `cfg` nor
    `catalog`; the checks that follow do. The result is in report order: findings about the whole
    file first, then by line, then by column, then by code.
    """
    text = decode_text(data)
    findings = check_file(path, data, text)
    findings.extend(_content_finding(str(path), hit) for hit in scan(text))
    findings.extend(_front_matter_findings(path, text))
    return sorted(findings, key=_report_order)


def _front_matter_findings(path: Path, text: str) -> list[Finding]:
    """The front matter checks (section 3.2) and E-FILENAME, which needs the agent id.

    This is where every check that needs the front matter belongs. When there is none, or it
    cannot be trusted (`split` or `load` gives no data), they are all skipped (section 1): what
    still runs are the file, hidden-character, placeholder and content-safety checks above.
    """
    parts = split(text)
    if parts is None:
        return [Finding("E-FM-MISSING", "error", str(path), 1)]
    front, _body, _body_line = parts
    loaded = load(front, path)
    findings = list(loaded.findings)
    if loaded.data is None:
        return findings
    findings.extend(check_filename(path, loaded))
    # Later tasks add their checks here, with loaded.data and loaded.lines: the values, tools,
    # limits and scope (1.4), and the body, which starts on _body_line (1.5).
    return findings


def _content_finding(path: str, hit: ContentHit) -> Finding:
    code = KIND_CODES[hit.kind]
    # E-ID-NUMBER names no kind: its message is about a BSN, and nothing else is needed.
    params = {} if code == "E-ID-NUMBER" else {"kind": hit.kind}
    return Finding(code, "error", path, hit.line, hit.column, params)


def _report_order(finding: Finding) -> tuple[bool, int, int, str]:
    return (finding.line is not None, finding.line or 0, finding.column or 0, finding.code)
