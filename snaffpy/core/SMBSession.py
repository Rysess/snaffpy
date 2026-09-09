from __future__ import annotations

from typing import TYPE_CHECKING

from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import (
    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_READ_DATA, FILE_SHARE_READ,
)

from snaffpy.core.ntstatus import clean_error, describe_status

if TYPE_CHECKING:
    from typing import Optional

    from snaffpy.core.Logger import Logger
    from snaffpy.types.Config import Config
    from snaffpy.types.Credentials import Credentials


class SMBSession(object):
    """A single authenticated SMB session against one host."""

    host: str
    credentials: Credentials
    config: Config
    conn: Optional[SMBConnection]

    def __init__(self, host: str, credentials: Credentials, config: Config, logger: Logger):
        super(SMBSession, self).__init__()
        self.host = host
        self.credentials = credentials
        self.config = config
        self.logger = logger
        self.conn = None
        self.error = None
        self.error_code = None
        self.connected = False

    def init_smb_session(self) -> bool:
        creds = self.credentials
        try:
            self.logger.verbose("%s: connecting on tcp/%d" % (self.host, self.config.port))
            self.conn = SMBConnection(
                self.host, self.host, sess_port=self.config.port, timeout=self.config.timeout
            )
            self.connected = True
        except Exception as err:
            self.error, self.error_code, self.connected = err, None, False
            self.logger.verbose("%s: could not connect on tcp/%d: %s"
                                % (self.host, self.config.port, err))
            return False

        try:
            if creds.use_kerberos:
                self.conn.kerberosLogin(
                    creds.username, creds.password, creds.domain,
                    creds.lm_hex, creds.nt_hex, creds.aesKey, creds.kdcHost,
                )
            else:
                self.conn.login(
                    creds.username, creds.password, creds.domain,
                    creds.lm_hex, creds.nt_hex,
                )
            self.logger.verbose("%s: authenticated as %s\\%s"
                                % (self.host, creds.domain or ".", creds.username))
            return True
        except SessionError as err:
            self.error = err
            self.error_code = err.getErrorCode()
            self.logger.verbose("%s: logon rejected: %s"
                                % (self.host, describe_status(self.error_code)))
            return False
        except Exception as err:
            self.error, self.error_code = err, None
            self.logger.verbose("%s: unexpected error during logon: %s"
                                % (self.host, clean_error(err)))
            return False

    def list_shares(self) -> list[str]:
        shares = []
        for entry in self.conn.listShares():
            name = entry["shi1_netname"][:-1]
            upper = name.upper()
            if not self.config.admin_shares and name.endswith("$") \
                    and upper not in ("SYSVOL", "NETLOGON"):
                continue
            shares.append(name)
        self.logger.verbose("%s: %d share(s) after filtering: %s"
                            % (self.host, len(shares), ", ".join(shares)))
        return shares

    def is_share_readable(self, share: str) -> bool:
        try:
            self.conn.listPath(share, "\\*")
            return True
        except Exception:
            return False

    def list_path(self, share: str, path: str) -> list:
        query = path.rstrip("\\") + "\\*"
        return self.conn.listPath(share, query)

    def read_bounded(self, share: str, path: str, max_bytes: int) -> bytes:
        tid = self.conn.connectTree(share)
        try:
            fid = self.conn.openFile(
                tid, path, desiredAccess=FILE_READ_DATA, shareMode=FILE_SHARE_READ,
                creationOption=FILE_NON_DIRECTORY_FILE, creationDisposition=FILE_OPEN,
            )
            try:
                return self.conn.readFile(tid, fid, 0, max_bytes)
            finally:
                self.conn.closeFile(tid, fid)
        finally:
            self.conn.disconnectTree(tid)

    def close(self):
        try:
            if self.conn is not None:
                self.conn.close()
        except Exception:
            pass
