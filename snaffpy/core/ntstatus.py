from __future__ import annotations

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


def status_name(code: int) -> str:
    if code in nt_errors.ERROR_MESSAGES:
        return nt_errors.ERROR_MESSAGES[code][0]
    return "0x%08x" % (code & 0xFFFFFFFF) if code is not None else "unknown"


def is_auth_failure(code: int) -> bool:
    return code in AUTH_FAILURE_CODES


def is_lockout(code: int) -> bool:
    return code in LOCKOUT_CODES
