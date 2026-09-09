from __future__ import annotations

import fnmatch
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event, Lock
from typing import TYPE_CHECKING

from snaffpy.core.AclResolver import AclResolver
from snaffpy.core.SMBSession import SMBSession
from snaffpy.core.ntstatus import clean_error, describe_status, is_auth_failure, is_lockout

if TYPE_CHECKING:
    from snaffpy.core.Logger import Logger
    from snaffpy.core.RuleEngine import RuleEngine
    from snaffpy.types.Config import Config
    from snaffpy.types.Credentials import Credentials


class Snaffler(object):
    """Drives discovery and rule evaluation across a set of target hosts."""

    def __init__(self, credentials: Credentials, config: Config,
                 engine: RuleEngine, logger: Logger):
        super(Snaffler, self).__init__()
        self.credentials = credentials
        self.config = config
        self.engine = engine
        self.logger = logger
        self.__lock = Lock()
        self.__abort = Event()
        self.creds_validated = False
        self.stats = {"shares": 0, "files": 0, "reads": 0, "auth_fail": 0}

    def run(self, targets: list[str]):
        start = time.time()
        if not self.creds_validated and not self.__preflight(targets):
            return
        self.logger.info("Snaffling %d host(s) with %d thread(s)"
                         % (len(targets), self.config.threads))
        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = [pool.submit(self.__process_host, host) for host in targets]
            for _ in as_completed(futures):
                pass
        if self.__abort.is_set():
            self.logger.error("Run aborted early to protect the account from lockout.")
        self.logger.info("Done: %d share(s) scanned, %d file(s) seen, %d read, %.1fs elapsed"
                         % (self.stats["shares"], self.stats["files"],
                            self.stats["reads"], time.time() - start))

    def __preflight(self, targets: list[str]) -> bool:
        """Validate credentials against the first reachable host before fanning out.

        This spends at most one failed logon on bad credentials, instead of one per
        host across the whole range, which is what would otherwise lock the account.
        """
        creds = self.credentials
        identity = "%s\\%s" % (creds.domain or ".", creds.username or "(null)")
        self.logger.verbose("Validating %s against a live host before scanning %d target(s)"
                            % (identity, len(targets)))
        for host in targets:
            session = SMBSession(host, creds, self.config, self.logger)
            ok = session.init_smb_session()
            session.close()
            if ok:
                self.logger.info("Credentials for '%s' validated on %s" % (identity, host))
                return True
            if not session.connected:
                continue
            code = session.error_code
            if is_lockout(code):
                self.logger.critical("Account '%s' is locked out on %s: %s"
                                     % (identity, host, describe_status(code)))
                self.logger.error("Stopping now. Do not retry until the lockout is cleared.")
                return False
            if is_auth_failure(code):
                self.logger.error("Authentication failed for '%s' on %s: %s"
                                  % (identity, host, describe_status(code)))
                self.logger.error("Aborting run so repeated failed logons cannot lock the account.")
                return False
            if code is None and session.error is not None:
                # Reached the host but the logon itself failed (bad hash format, Kerberos/KDC
                # problem, etc.). This is a config issue that will repeat on every host.
                self.logger.error("Could not log on to %s as '%s': %s"
                                  % (host, identity, clean_error(session.error)))
                self.logger.error("This is a credential/Kerberos configuration problem, not host "
                                  "reachability -- check -p/--hashes/-k/--dc-host and try again.")
                return False
            self.logger.verbose("%s: reachable but returned a non-auth error, trying the next host"
                                % host)
        self.logger.error("No target answered on tcp/%d. Check connectivity, the port, and the "
                          "target list (--cidr / --targets / --ldap)." % self.config.port)
        return False

    def __bump(self, key: str):
        with self.__lock:
            self.stats[key] += 1

    def __process_host(self, host: str):
        if self.__abort.is_set():
            return
        session = SMBSession(host, self.credentials, self.config, self.logger)
        if not session.init_smb_session():
            if session.connected and session.error_code is not None:
                if is_lockout(session.error_code):
                    self.__abort.set()
                    self.logger.critical("%s: account locked out mid-run: %s -- aborting the whole run"
                                         % (host, describe_status(session.error_code)))
                elif is_auth_failure(session.error_code):
                    self.__bump("auth_fail")
                    self.logger.error("%s: authentication failed: %s"
                                      % (host, describe_status(session.error_code)))
            elif session.connected and session.error is not None:
                self.logger.error("%s: could not log on: %s" % (host, clean_error(session.error)))
            return
        resolver = AclResolver(session, self.logger) if self.config.acls else None
        try:
            for share in session.list_shares():
                if self.config.share_allow and not any(
                        fnmatch.fnmatch(share.lower(), pattern.lower())
                        for pattern in self.config.share_allow):
                    continue
                if not self.engine.share_allowed(share.lower()):
                    continue
                if not session.is_share_readable(share):
                    continue
                self.__bump("shares")
                self.__walk_share(session, resolver, host, share)
        finally:
            if resolver is not None:
                resolver.close()
            session.close()

    def __walk_share(self, session: SMBSession, resolver, host: str, share: str):
        stack = ["\\"]
        while stack:
            current = stack.pop()
            try:
                listing = session.list_path(share, current)
            except Exception:
                continue
            for entry in listing:
                name = entry.get_longname()
                if name in (".", ".."):
                    continue
                path = current.rstrip("\\") + "\\" + name
                if entry.is_directory():
                    depth = path.count("\\")
                    if depth <= self.config.max_depth and self.engine.dir_allowed(path.lower()):
                        stack.append(path)
                    continue
                self.__inspect_file(session, resolver, host, share, path, name,
                                    entry.get_filesize())

    def __inspect_file(self, session, resolver, host, share, path, name, size):
        self.__bump("files")
        ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""

        hit = self.engine.classify_file(name.lower(), ext, path.lower())
        if hit and self.engine.reportable(hit[0]):
            self.logger.finding(host, share, path, size, hit[0], hit[1])
            self.__report_acl(resolver, share, path)

        if (not self.config.no_content and 0 < size <= self.config.max_file_size
                and self.engine.wants_content(ext)):
            try:
                raw = session.read_bounded(share, path, min(size, self.config.max_file_size))
                self.__bump("reads")
                text = raw.decode("utf-8", "ignore")
                reported = False
                for triage, rule, snippet in self.engine.grep_content(text):
                    if self.engine.reportable(triage):
                        self.logger.finding(host, share, path, size, triage, rule, snippet.strip())
                        reported = True
                if reported:
                    self.__report_acl(resolver, share, path)
            except Exception:
                pass

        if self.config.delay:
            time.sleep(self.config.delay + random.uniform(0, self.config.jitter))

    def __report_acl(self, resolver, share, path):
        if resolver is None:
            return
        try:
            info = resolver.describe(share, path, is_dir=False)
        except Exception as err:
            self.logger.debug("acl query failed for %s: %s" % (path, err))
            return
        groups = [r["name"] for r in info["readers"] if r["group"]]
        if groups:
            self.logger.print("           read-groups: %s" % ", ".join(groups))
