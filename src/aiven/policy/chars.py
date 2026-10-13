"""Characters that can hide text from a reader (validator-spec section 3.1).

One definition, used by the E-HIDDEN-CHAR check (`fileformat.py`) and by the guard that escapes
text before a finding shows it (`content.py`). `content.py` cannot import `fileformat.py`:
`fileformat` imports `findings` and `findings` imports `content`, which would be a cycle. So the
definition lives here, and this module only imports the constants.
"""

import unicodedata

from aiven.policy.constants import HIDDEN_CATEGORIES, HIDDEN_RANGES


def is_hidden(char: str) -> bool:
    """Whether `char` is in the hidden set of section 3.1.

    That is every character of the categories in `HIDDEN_CATEGORIES` and of the ranges in
    `HIDDEN_RANGES`, except LF and the normal space. CR is in the set (it is a control character).
    The E-HIDDEN-CHAR check leaves CR to E-LINE-ENDINGS, one defect and one code; the definition
    itself does not.
    """
    if char in "\n ":
        return False
    if unicodedata.category(char) in HIDDEN_CATEGORIES:
        return True
    code = ord(char)
    return any(low <= code <= high for low, high in HIDDEN_RANGES)
