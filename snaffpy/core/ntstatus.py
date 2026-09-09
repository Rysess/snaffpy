from __future__ import annotations

import re

from impacket import nt_errors

AUTH_FAILURE_CODES = {
    nt_errors.STATUS_LOGON_FAILURE,
    nt_errors.STATUS_WRONG_PASSWORD,
    nt_errors.STATUS_PASSWORD_EXPIRED,
    nt_errors.STATUS_PASSWORD_MUST_CHANGE,
    nt_errors.STATUS_PASSWORD_RESTRICTION,
    nt_errors.STATUS_ACCOUNT_DISABLED,
    nt_errors.STATUS_ACCOUNT_EXPIRED,
    nt_errors.STATUS_ACCOUNT_RESTRICTION,
    nt_errors.STATUS_ACCOUNT_LOCKED_OUT,
    nt_errors.STATUS_INVALID_LOGON_HOURS,
    nt_errors.STATUS_INVALID_WORKSTATION,
}
LOCKOUT_CODES = {nt_errors.STATUS_ACCOUNT_LOCKED_OUT}

# Plain-language reasons for the codes an operator is most likely to hit, so the
# output says what actually went wrong instead of only the raw NT status name.
FRIENDLY = {
    nt_errors.STATUS_LOGON_FAILURE: "wrong username or password",
    nt_errors.STATUS_WRONG_PASSWORD: "wrong password",
    nt_errors.STATUS_PASSWORD_EXPIRED: "password has expired",
    nt_errors.STATUS_PASSWORD_MUST_CHANGE: "password must be changed before logon",
    nt_errors.STATUS_PASSWORD_RESTRICTION: "password does not meet the domain policy",
    nt_errors.STATUS_ACCOUNT_DISABLED: "account is disabled",
    nt_errors.STATUS_ACCOUNT_EXPIRED: "account has expired",
    nt_errors.STATUS_ACCOUNT_RESTRICTION: "account is not allowed to log on here",
    nt_errors.STATUS_ACCOUNT_LOCKED_OUT: "account is locked out",
    nt_errors.STATUS_INVALID_LOGON_HOURS: "logon not permitted at this time of day",
    nt_errors.STATUS_INVALID_WORKSTATION: "logon not permitted from this host",
    nt_errors.STATUS_ACCESS_DENIED: "access denied",
}


def status_name(code: int) -> str:
    if code in nt_errors.ERROR_MESSAGES:
        return nt_errors.ERROR_MESSAGES[code][0]
    return "0x%08x" % (code & 0xFFFFFFFF) if code is not None else "unknown error"


def describe_status(code: int) -> str:
    """A human reason plus the raw status name, e.g. 'wrong username or password (STATUS_LOGON_FAILURE)'."""
    name = status_name(code)
    reason = FRIENDLY.get(code)
    return "%s (%s)" % (reason, name) if reason else name


def clean_error(err) -> str:
    """Flatten an exception into one printable line (impacket messages carry NULs/newlines)."""
    return re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f]", " ", str(err))).strip()


def is_auth_failure(code: int) -> bool:
    return code in AUTH_FAILURE_CODES


def is_lockout(code: int) -> bool:
    return code in LOCKOUT_CODES
