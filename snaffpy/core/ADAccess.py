from __future__ import annotations

from typing import TYPE_CHECKING

from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldaptypes import LDAP_SID

if TYPE_CHECKING:
    from typing import Optional

    from snaffpy.types.Credentials import Credentials

IMPLICIT_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "NT AUTHORITY\\Authenticated Users",
    "S-1-5-32-545": "BUILTIN\\Users",
}
IN_CHAIN = "1.2.840.113556.1.4.1941"


def _attrs(item) -> dict:
    out = {}
    for at in item["attributes"]:
        key = str(at["type"])
        out[key] = [bytes(v) if key.lower() == "objectsid" else str(v) for v in at["vals"]]
    return out


class ADAccess(object):
    """LDAP-side access reasoning: which groups an account holds, and who is in a group."""

    def __init__(self, credentials: Credentials, base_dn: Optional[str] = None):
        super(ADAccess, self).__init__()
        self.credentials = credentials
        self.base_dn = base_dn or ",".join(
            "DC=%s" % p for p in credentials.domain.split("."))
        self.conn = None

    def connect(self) -> "ADAccess":
        from snaffpy.core.Discovery import DiscoveryAuthError, _classify_ldap_error
        server = self.credentials.kdcHost or self.credentials.domain
        identity = "%s\\%s" % (self.credentials.domain or ".", self.credentials.username or "(null)")
        try:
            self.conn = ldap.LDAPConnection("ldap://%s" % server, self.base_dn,
                                            self.credentials.kdcHost)
            self.conn.login(self.credentials.username, self.credentials.password,
                            self.credentials.domain, self.credentials.lm_hex,
                            self.credentials.nt_hex)
        except Exception as err:
            meaning, locked = _classify_ldap_error(err)
            raise DiscoveryAuthError(
                "LDAP bind failed as %s@%s: %s" % (identity, server, meaning), locked=locked)
        return self

    def __search(self, search_filter: str, attributes: list) -> list:
        rows = []
        self.conn.search(searchFilter=search_filter, attributes=attributes,
                         sizeLimit=0,
                         perRecordCallback=lambda i: rows.append(_attrs(i))
                         if isinstance(i, ldapasn1.SearchResultEntry) else None)
        return rows

    def token_group_sids(self, sam: str) -> dict[str, str]:
        """SID -> name for every group the account transitively belongs to, plus its own SID."""
        user = self.__search("(sAMAccountName=%s)" % sam,
                             ["distinguishedName", "objectSid"])
        if not user:
            return dict(IMPLICIT_SIDS)
        user_dn = user[0]["distinguishedName"][0]
        result = dict(IMPLICIT_SIDS)
        if user[0].get("objectSid"):
            result[LDAP_SID(data=user[0]["objectSid"][0]).formatCanonical()] = sam
        for row in self.__search("(member:%s:=%s)" % (IN_CHAIN, user_dn),
                                 ["objectSid", "sAMAccountName"]):
            if row.get("objectSid"):
                sid = LDAP_SID(data=row["objectSid"][0]).formatCanonical()
                name = row.get("sAMAccountName", [sid])[0]
                result[sid] = name
        return result

    def members_recursive(self, group_sid: str) -> list[str]:
        """sAMAccountNames of all principals nested under a group SID."""
        group = self.__search("(objectSid=%s)" % group_sid, ["distinguishedName"])
        if not group:
            return []
        group_dn = group[0]["distinguishedName"][0]
        rows = self.__search("(member:%s:=%s)" % (IN_CHAIN, group_dn), ["sAMAccountName"])
        return sorted({r["sAMAccountName"][0] for r in rows if r.get("sAMAccountName")})

    def close(self):
        try:
            if self.conn is not None:
                self.conn.close()
        except Exception:
            pass
