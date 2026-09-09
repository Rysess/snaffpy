from __future__ import annotations

from ipaddress import ip_network
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

    from snaffpy.core.Logger import Logger
    from snaffpy.types.Credentials import Credentials

LDAP_SUBCODES = {
    "525": "user not found",
    "52e": "invalid credentials (wrong password)",
    "530": "not permitted to logon at this time",
    "531": "not permitted to logon from this workstation",
    "532": "password expired",
    "533": "account disabled",
    "701": "account expired",
    "773": "user must reset password",
    "775": "account locked out",
}


class DiscoveryAuthError(Exception):
    """Raised when an LDAP bind fails; carries whether the account is locked."""

    def __init__(self, message: str, locked: bool = False):
        super().__init__(message)
        self.locked = locked


def _classify_ldap_error(err: Exception) -> tuple[str, bool]:
    text = str(err)
    for code, meaning in LDAP_SUBCODES.items():
        if ("data %s" % code) in text.lower():
            return meaning, code == "775"
    return text, False


def expand_targets(cidrs: list, files: list) -> list[str]:
    """Expand CIDRs and host files into a deduplicated, sorted host list."""
    hosts = []
    for cidr in cidrs or []:
        try:
            hosts += [str(ip) for ip in ip_network(cidr, strict=False).hosts()]
        except ValueError:
            hosts.append(cidr)
    for path in files or []:
        with open(path) as fh:
            hosts += [line.strip() for line in fh
                      if line.strip() and not line.startswith("#")]
    return sorted(set(hosts))


def discover_hosts_ldap(credentials: Credentials, base_dn: Optional[str] = None,
                        enabled_only: bool = True, logger: Optional[Logger] = None) -> list[str]:
    """Enumerate computer dNSHostNames from Active Directory."""
    from impacket.ldap import ldap, ldapasn1

    if base_dn is None:
        base_dn = ",".join("DC=%s" % part for part in credentials.domain.split("."))
    server = credentials.ldap_server
    identity = "%s\\%s" % (credentials.domain or ".", credentials.username or "(null)")

    try:
        conn = ldap.LDAPConnection("ldap://%s" % server, base_dn, credentials.kdcHost)
        conn.login(credentials.username, credentials.password, credentials.domain,
                   credentials.lm_hex, credentials.nt_hex)
    except Exception as err:
        meaning, locked = _classify_ldap_error(err)
        message = "LDAP bind failed as %s@%s: %s" % (identity, server, meaning)
        if logger is not None:
            logger.error(message)
            if locked:
                logger.error("account is LOCKED OUT -- stop and coordinate before retrying")
        raise DiscoveryAuthError(message, locked=locked)

    search_filter = "(&(objectCategory=computer)"
    if enabled_only:
        search_filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    search_filter += ")"

    hosts = []

    def collect(item):
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return
        for attribute in item["attributes"]:
            if str(attribute["type"]) == "dNSHostName":
                value = str(attribute["vals"][0])
                if value:
                    hosts.append(value)

    try:
        conn.search(searchFilter=search_filter, attributes=["dNSHostName"],
                    sizeLimit=0, perRecordCallback=collect)
    except Exception as err:
        meaning, _ = _classify_ldap_error(err)
        if hosts:
            if logger is not None:
                logger.warn("LDAP search stopped early (%s); continuing with %d host(s) "
                            "already retrieved" % (meaning, len(set(hosts))))
        elif logger is not None:
            logger.error("LDAP search returned no hosts: %s" % meaning)
    return sorted(set(hosts))
