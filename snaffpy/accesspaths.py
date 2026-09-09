from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict

from snaffpy.core.ADAccess import ADAccess
from snaffpy.core.AclResolver import AclResolver
from snaffpy.core.Discovery import DiscoveryAuthError
from snaffpy.core.Logger import Logger
from snaffpy.core.ntstatus import describe_status
from snaffpy.core.SMBSession import SMBSession
from snaffpy.types.Config import Config
from snaffpy.types.Credentials import Credentials
from snaffpy.types.Rule import Triage

GREEN, YELLOW, RED, RESET = "\x1b[92m", "\x1b[93m", "\x1b[91m", "\x1b[0m"


def load_findings(path: str, min_triage: str) -> list[dict]:
    floor = Triage.rank(min_triage)
    findings = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if Triage.rank(rec.get("triage", "Green")) >= floor:
                findings.append(rec)
    return findings


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="snaffpy-accesspaths",
        description="Map snaffpy findings to the AD groups that grant read access.")
    parser.add_argument("findings", help="snaffpy JSONL findings file (from -o).")
    parser.add_argument("--min-triage", choices=list(Triage.ORDER), default="Red")
    parser.add_argument("--whoami", help="Account to compute access for (default: -u user).")
    parser.add_argument("--expand", action="store_true",
                        help="List nested members of each granting group (heavier LDAP).")
    parser.add_argument("--no-ldap", action="store_true",
                        help="Skip LDAP; only resolve readers via LSAT, no 'your access' marking.")
    parser.add_argument("--base-dn")
    parser.add_argument("-d", "--domain", default="")
    parser.add_argument("-u", "--user", default="")
    parser.add_argument("-p", "--password", default="")
    parser.add_argument("--hashes", metavar="[LMHASH:]NTHASH")
    parser.add_argument("--aes-key", dest="aes_key")
    parser.add_argument("-k", "--kerberos", action="store_true")
    parser.add_argument("--dc-ip", dest="dc_ip", metavar="IP",
                        help="IP of the domain controller for LDAP (and KDC unless --dc-host given).")
    parser.add_argument("--dc-host", dest="dc_host", metavar="FQDN",
                        help="FQDN of the domain controller; used as the Kerberos KDC.")
    parser.add_argument("--no-colors", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--debug", action="store_true")
    return parser


def main():
    options = build_argument_parser().parse_args()
    config = Config(no_colors=options.no_colors, debug=options.debug, verbose=options.verbose)
    credentials = Credentials(
        domain=options.domain, username=options.user, password=options.password,
        hashes=options.hashes, use_kerberos=options.kerberos,
        aesKey=options.aes_key, dc_ip=options.dc_ip, dc_host=options.dc_host)
    logger = Logger(config)

    findings = load_findings(options.findings, options.min_triage)
    if not findings:
        logger.error("no findings at or above %s" % options.min_triage)
        return
    logger.info("enriching %d finding(s) at >= %s" % (len(findings), options.min_triage))

    token = {}
    ad = None
    if not options.no_ldap:
        try:
            ad = ADAccess(credentials, options.base_dn).connect()
        except DiscoveryAuthError as err:
            if err.locked:
                logger.critical(str(err))
                logger.error("Account is locked out. Stop and coordinate before retrying.")
            else:
                logger.error(str(err))
            sys.exit(2)
        token = ad.token_group_sids(options.whoami or options.user)
        logger.info("Account holds %d group SID(s)" % len(token))

    by_host = defaultdict(list)
    for rec in findings:
        by_host[rec["host"]].append(rec)

    for host, records in by_host.items():
        session = SMBSession(host, credentials, config, logger)
        if not session.init_smb_session():
            if session.connected and session.error_code is not None:
                logger.error("%s: could not authenticate (%s), skipping its findings"
                             % (host, describe_status(session.error_code)))
            else:
                logger.error("%s: could not connect on tcp/%d, skipping its findings"
                             % (host, config.port))
            continue
        resolver = AclResolver(session, logger)
        try:
            for rec in records:
                _report(logger, resolver, ad, token, options, rec)
        finally:
            resolver.close()
            session.close()

    if ad is not None:
        ad.close()


def _report(logger, resolver, ad, token, options, rec):
    unc = "\\\\%s\\%s%s" % (rec["host"], rec["share"], rec["path"])
    logger.print("\n[%s] %s" % (rec.get("triage", "?"), unc))
    try:
        info = resolver.describe(rec["share"], rec["path"], is_dir=False)
    except Exception as err:
        logger.error("  could not read ACL: %s" % err)
        return
    if info["owner"]:
        logger.print("  owner: %s" % info["owner"])

    for reader in info["readers"]:
        mine = reader["sid"] in token
        tag = "group" if reader["group"] else reader["type"]
        mark = ("%s<= grants YOU read%s" % (GREEN, RESET)) if mine else ""
        color = YELLOW if reader["group"] else ""
        logger.print("  read: %s%s%s (%s) %s"
                     % (color, reader["name"], RESET, tag, mark))
        if options.expand and reader["group"] and ad is not None:
            members = ad.members_recursive(reader["sid"])
            if members:
                logger.print("        members: %s" % ", ".join(members[:25])
                             + (" ..." if len(members) > 25 else ""))


if __name__ == "__main__":
    main()
