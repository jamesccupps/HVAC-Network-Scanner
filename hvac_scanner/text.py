"""
Text that came from a device, made safe for where it goes next.

Anything a device says about itself (a name, a banner, a page title, an SNMP
description) is chosen by whoever controls that device, and BACnet names in
particular are writable by anyone on the network. Two places it can bite:

- a terminal or log, where control characters and escape sequences can
  rewrite what the operator sees (`clean_text`);
- a spreadsheet, where a cell starting with `=`, `+`, `-` or `@` is a
  formula (`spreadsheet_cell`).
"""

from __future__ import annotations

from typing import Any

# C0 controls, DEL and C1 controls are dropped; tab and line breaks become
# spaces so a multi-line banner still reads as words. The bidirectional
# overrides can make text display in a different order than it is stored.
_DROP = {c: None for c in (*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0),
                           0x200E, 0x200F, *range(0x202A, 0x202F),
                           *range(0x2066, 0x206A))}
_TO_SPACE = {0x09: ' ', 0x0A: ' ', 0x0D: ' '}
_TABLE = {**_DROP, **_TO_SPACE}


def clean_text(value: Any) -> Any:
    """`value` without control characters, if it is a string."""
    if not isinstance(value, str):
        return value
    return value.translate(_TABLE)


# For a whole log message: the scanner's own line breaks and indents stay.
_LOG_TABLE = {c: v for c, v in _DROP.items() if c not in (0x09, 0x0A)}


def clean_log_line(message: str) -> str:
    """A log message as it may be shown in a terminal: control characters
    and escape sequences (which device-chosen text can carry) removed."""
    return message.translate(_LOG_TABLE) if isinstance(message, str) else message


# Excel, LibreOffice and Google Sheets all read a cell starting with one of
# these as a formula (the full-width forms too, in some locales). Tab and line
# breaks lead the list OWASP gives for the same reason.
_FORMULA_LEAD = ('=', '+', '-', '@', '\t', '\r', '\n',
                 '＝', '＋', '－', '＠')


def spreadsheet_cell(value: Any) -> Any:
    """`value` as a spreadsheet will read it as text, not a formula.

    A string that would start a formula gets a leading apostrophe, which
    spreadsheets treat as "this is text". A plain number such as ``-12.5``
    is left alone so it still sorts and sums as a number.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_LEAD):
        try:
            float(value)
            return value
        except ValueError:
            return "'" + value
    return value
