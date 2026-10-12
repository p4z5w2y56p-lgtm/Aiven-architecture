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


def validate_file(path: Path, data: bytes, cfg: PlatformConfig, catalog: Catalog) -> list[Finding]:
    """All findings for the policy file `data` that is called `path`.

    The file checks and the content checks need neither `cfg` nor `catalog`; the checks that
    follow do. The result is in report order: findings about the whole file first, then by line,
    then by column, then by code.
    """
    findings = check_file(path, data)
    findings.extend(_content_finding(str(path), hit) for hit in scan(decode_text(data)))
    return sorted(findings, key=_report_order)


def _content_finding(path: str, hit: ContentHit) -> Finding:
    code = KIND_CODES[hit.kind]
    # E-ID-NUMBER names no kind: its message is about a BSN, and nothing else is needed.
    params = {} if code == "E-ID-NUMBER" else {"kind": hit.kind}
    return Finding(code, "error", path, hit.line, hit.column, params)


def _report_order(finding: Finding) -> tuple[bool, int, int, str]:
    return (finding.line is not None, finding.line or 0, finding.column or 0, finding.code)
