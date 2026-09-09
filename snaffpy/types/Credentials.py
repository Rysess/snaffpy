from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional


def parse_lm_nt_hashes(hashes: Optional[str]) -> tuple[str, str]:
    """Split a '[LM]:NT' string into (lm_hex, nt_hex), padding empties with zeros."""
    if not hashes:
        return "", ""
    if ":" in hashes:
        lm, nt = hashes.split(":", 1)
    else:
        lm, nt = "", hashes
    lm = lm.strip() or ("0" * 32)
    nt = nt.strip() or ("0" * 32)
    return lm, nt


class Credentials(object):
    """Credentials used for SMB and LDAP authentication."""

    domain: Optional[str]
    username: Optional[str]
    password: Optional[str]
    lm_hex: str
    nt_hex: str
    use_kerberos: bool
    aesKey: Optional[str]
    dc_ip: Optional[str]
    dc_host: Optional[str]
    kdcHost: Optional[str]

    def __init__(
        self,
        domain: str = "",
        username: str = "",
        password: str = "",
        hashes: Optional[str] = None,
        use_kerberos: bool = False,
        aesKey: Optional[str] = None,
        dc_ip: Optional[str] = None,
        dc_host: Optional[str] = None,
    ):
        super(Credentials, self).__init__()
        self.domain = domain
        self.username = username
        self.password = password
        self.lm_hex, self.nt_hex = parse_lm_nt_hashes(hashes)
        self.use_kerberos = use_kerberos or (aesKey is not None)
        self.aesKey = aesKey
        self.dc_ip = dc_ip
        self.dc_host = dc_host
        # The KDC needs a name for SPNs, so prefer the FQDN, then fall back to the IP.
        self.kdcHost = dc_host or dc_ip

    @property
    def ldap_server(self) -> str:
        """Host to direct LDAP discovery/enrichment at: DC IP, then FQDN, then domain."""
        return self.dc_ip or self.dc_host or self.domain

    @property
    def has_hashes(self) -> bool:
        return bool(self.nt_hex) and self.nt_hex != ("0" * 32)

    @property
    def identity(self) -> str:
        return "%s\\%s" % (self.domain or ".", self.username or "")
