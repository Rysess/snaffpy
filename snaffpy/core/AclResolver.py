from __future__ import annotations

from typing import TYPE_CHECKING

from impacket.dcerpc.v5 import lsad, lsat, transport
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED as LSA_MAX_ALLOWED
from impacket.dcerpc.v5.lsat import DCERPCSessionError
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.nt_errors import STATUS_NONE_MAPPED, STATUS_SOME_NOT_MAPPED
from impacket.smb3structs import (
    DACL_SECURITY_INFORMATION, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_READ_ATTRIBUTES, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, READ_CONTROL, SMB2_0_INFO_SECURITY,
    SMB2_SEC_INFO_00,
)

if TYPE_CHECKING:
    from snaffpy.core.Logger import Logger
    from snaffpy.core.SMBSession import SMBSession

# Access-mask bits that imply the ability to read file data / list a directory.
FILE_READ_DATA = 0x00000001
GENERIC_READ = 0x80000000
GENERIC_ALL = 0x10000000
MAXIMUM_ALLOWED = 0x02000000
READ_BITS = FILE_READ_DATA | GENERIC_READ | GENERIC_ALL | MAXIMUM_ALLOWED

ACE_ALLOW = {0x00, 0x05}   # ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE
ACE_DENY = {0x01, 0x06}    # ACCESS_DENIED_ACE, ACCESS_DENIED_OBJECT_ACE

SID_NAME_USE = {
    1: "user", 2: "group", 3: "domain", 4: "alias",
    5: "wellknown", 6: "deleted", 7: "invalid", 8: "unknown",
}
GROUP_USES = {"group", "alias", "wellknown"}


class Trustee(object):
    """A principal referenced by an ACE, with a resolved name and type."""

    def __init__(self, sid: str, mask: int):
        self.sid = sid
        self.mask = mask
        self.name = sid
        self.use = "unknown"

    @property
    def is_group(self) -> bool:
        return self.use in GROUP_USES


class AclResolver(object):
    """Resolves who can read a remote file by parsing its DACL and mapping SIDs."""

    def __init__(self, session: SMBSession, logger: Logger):
        super(AclResolver, self).__init__()
        self.session = session
        self.logger = logger
        self.cache = {}
        self.__dce = None

    def __lsat(self):
        if self.__dce is None:
            rpc = transport.SMBTransport(445, filename="lsarpc")
            rpc.set_smb_connection(self.session.conn)
            self.__dce = rpc.get_dce_rpc()
            self.__dce.connect()
            self.__dce.bind(lsat.MSRPC_UUID_LSAT)
        return self.__dce

    def security_descriptor(self, share: str, path: str, is_dir: bool) -> bytes:
        smb = self.session.conn.getSMBServer()
        tid = self.session.conn.connectTree(share)
        try:
            fid = smb.create(
                tid, path, READ_CONTROL | FILE_READ_ATTRIBUTES, 0,
                FILE_DIRECTORY_FILE if is_dir else FILE_NON_DIRECTORY_FILE,
                FILE_OPEN, 0,
            )
            try:
                return smb.queryInfo(
                    tid, fid, infoType=SMB2_0_INFO_SECURITY,
                    fileInfoClass=SMB2_SEC_INFO_00,
                    additionalInformation=OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
                    flags=0,
                )
            finally:
                smb.close(tid, fid)
        finally:
            self.session.conn.disconnectTree(tid)

    def read_trustees(self, sd_bytes: bytes) -> tuple[str, list[Trustee]]:
        """Return (owner_sid, trustees) for principals with effective read on the DACL."""
        sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
        owner = sd["OwnerSid"].formatCanonical() if sd["OwnerSid"] else ""
        dacl = sd["Dacl"]
        if not dacl:
            # Null DACL means everyone has full access.
            return owner, [Trustee("S-1-1-0", GENERIC_ALL)]

        allow, deny = {}, set()
        for ace in dacl["Data"]:
            sid = ace["Ace"]["Sid"].formatCanonical()
            mask = ace["Ace"]["Mask"]["Mask"]
            if not (mask & READ_BITS):
                continue
            if ace["AceType"] in ACE_DENY:
                deny.add(sid)
            elif ace["AceType"] in ACE_ALLOW:
                allow.setdefault(sid, mask)

        return owner, [Trustee(sid, mask) for sid, mask in allow.items()
                       if sid not in deny]

    def resolve(self, trustees: list[Trustee]) -> None:
        """Populate .name/.use for trustees via LSAT, using a local cache."""
        pending = [t.sid for t in trustees if t.sid not in self.cache]
        if pending:
            self.__lookup(pending)
        for trustee in trustees:
            name, use = self.cache.get(trustee.sid, (trustee.sid, "unknown"))
            trustee.name, trustee.use = name, use

    def __lookup(self, sids: list) -> None:
        dce = self.__lsat()
        handle = lsad.hLsarOpenPolicy2(dce, LSA_MAX_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policy = handle["PolicyHandle"]
        try:
            resp = lsat.hLsarLookupSids(dce, policy, sids,
                                        lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        except DCERPCSessionError as err:
            if err.error_code == STATUS_SOME_NOT_MAPPED and err.packet is not None:
                resp = err.packet
            elif err.error_code == STATUS_NONE_MAPPED:
                return
            else:
                raise
        names = resp["TranslatedNames"]["Names"]
        domains = resp["ReferencedDomains"]["Domains"]
        for i, item in enumerate(names):
            use = SID_NAME_USE.get(int(item["Use"]), "unknown")
            if len(item["Name"]) == 0:
                name = sids[i]
            else:
                domain = domains[item["DomainIndex"]]["Name"] if item["DomainIndex"] >= 0 else ""
                name = "%s\\%s" % (domain, item["Name"]) if domain else str(item["Name"])
            self.cache[sids[i]] = (name, use)

    def describe(self, share: str, path: str, is_dir: bool = False) -> dict:
        """One-shot: SD -> read trustees -> resolved names. Returns a summary dict."""
        sd = self.security_descriptor(share, path, is_dir)
        owner, trustees = self.read_trustees(sd)
        self.resolve(trustees)
        return {
            "owner": self.cache.get(owner, (owner, "unknown"))[0] if owner else "",
            "readers": [{"name": t.name, "sid": t.sid, "type": t.use,
                         "group": t.is_group} for t in trustees],
        }

    def close(self):
        if self.__dce is not None:
            try:
                self.__dce.disconnect()
            except Exception:
                pass
