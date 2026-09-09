from __future__ import annotations

import argparse
import sys

from snaffpy import __version__
from snaffpy.core.Discovery import DiscoveryAuthError, discover_hosts_ldap, expand_targets
from snaffpy.core.Logger import Logger
from snaffpy.core.RuleEngine import RuleEngine
from snaffpy.core.Snaffler import Snaffler
from snaffpy.rules import dump_rules, load_default_rules, load_rules, packaged_rules_path
from snaffpy.types.Config import Config
from snaffpy.types.Credentials import Credentials
from snaffpy.types.Rule import Triage

BANNER = r"""
                     ________
   _________  ____ _/ __/ __/___  __  __
  / ___/ __ \/ __ `/ /_/ /_/ __ \/ / / /
 (__  ) / / / /_/ / __/ __/ /_/ / /_/ /
/____/_/ /_/\__,_/_/ /_/ / .___/\__, /
                        /_/    /____/   v%s  snaffler, ported to linux
""" % __version__


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="snaffpy", description="Snaffle sensitive files off SMB shares from Linux.")

    group_config = parser.add_argument_group("Config")
    group_config.add_argument("--debug", action="store_true", help="Enable debug output.")
    group_config.add_argument("-v", "--verbose", action="store_true",
                              help="Verbose step-by-step output for debugging.")
    group_config.add_argument("--no-colors", action="store_true", help="Disable colored output.")
    group_config.add_argument("-T", "--timeout", type=int, default=8, help="SMB timeout (default: 8s).")
    group_config.add_argument("-o", "--outfile", help="Write findings as JSONL to this file.")

    group_targets = parser.add_argument_group("Targets")
    group_targets.add_argument("--ldap", action="store_true", help="Autodiscover hosts from AD (T1018).")
    group_targets.add_argument("--base-dn", help="LDAP base DN (default derived from domain).")
    group_targets.add_argument("--cidr", action="append", help="Target CIDR or host (repeatable).")
    group_targets.add_argument("--targets", action="append", help="File of hosts (repeatable).")

    group_scope = parser.add_argument_group("Rules & Scope")
    group_scope.add_argument("--rules", help="External rules JSON (replaces defaults).")
    group_scope.add_argument("--dump-rules", metavar="PATH", help="Write default rules to JSON and exit.")
    group_scope.add_argument("--interest", choices=list(Triage.ORDER), default=Triage.GREEN,
                             help="Minimum triage to report (default: Green).")
    group_scope.add_argument("--share-allow", action="append", help="Only these shares, glob (repeatable).")
    group_scope.add_argument("--admin-shares", action="store_true", help="Include C$/ADMIN$ etc (noisy).")
    group_scope.add_argument("--max-depth", type=int, default=12, help="Max directory depth.")
    group_scope.add_argument("--max-file-size", type=int, default=10 * 1024 * 1024,
                             help="Max bytes read per file for content grep (default: 10MB).")
    group_scope.add_argument("--no-content", action="store_true", help="Skip content grep (quieter).")
    group_scope.add_argument("--acls", action="store_true",
                             help="Resolve read-ACL groups inline for each finding (LSAT; extra RPC).")

    group_opsec = parser.add_argument_group("OPSEC & Performance")
    group_opsec.add_argument("--threads", type=int, default=10, help="Host concurrency (higher = louder).")
    group_opsec.add_argument("--delay", type=float, default=0.0, help="Per-file delay seconds.")
    group_opsec.add_argument("--jitter", type=float, default=0.0, help="Added random 0..J seconds.")

    group_auth = parser.add_argument_group("Authentication & Connection")
    group_auth.add_argument("-d", "--domain", default="", help="Authentication domain.")
    group_auth.add_argument("-u", "--user", default="", help="Username for authentication.")
    group_auth.add_argument("--dc-ip", dest="dc_ip", metavar="IP",
                            help="IP address of the domain controller to use for LDAP discovery "
                                 "(and as the KDC unless --dc-host is given).")
    group_auth.add_argument("--dc-host", dest="dc_host", metavar="FQDN",
                            help="Hostname/FQDN of the domain controller; used as the Kerberos KDC "
                                 "(SPNs need a name, not an IP).")

    group_secrets = parser.add_argument_group("Secrets")
    group_secrets.add_argument("-p", "--password", default="", help="Password.")
    group_secrets.add_argument("--hashes", metavar="[LMHASH:]NTHASH", help="NT/LM hashes.")
    group_secrets.add_argument("--aes-key", dest="aes_key", help="AES key for Kerberos.")
    group_secrets.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication.")

    return parser


def main():
    print(BANNER, file=sys.stderr)
    parser = build_argument_parser()
    options = parser.parse_args()

    if options.dump_rules:
        dump_rules(options.dump_rules)
        print("[+] wrote default rules -> %s" % options.dump_rules)
        return

    config = Config(
        timeout=options.timeout, interest=options.interest, admin_shares=options.admin_shares,
        share_allow=options.share_allow, max_depth=options.max_depth,
        max_file_size=options.max_file_size, no_content=options.no_content, acls=options.acls,
        threads=options.threads, delay=options.delay, jitter=options.jitter,
        no_colors=options.no_colors, debug=options.debug, verbose=options.verbose,
        outfile=options.outfile,
    )
    credentials = Credentials(
        domain=options.domain, username=options.user, password=options.password,
        hashes=options.hashes, use_kerberos=options.kerberos,
        aesKey=options.aes_key, dc_ip=options.dc_ip, dc_host=options.dc_host,
    )
    logger = Logger(config)

    if options.rules:
        rules = load_rules(options.rules)
        logger.verbose("loaded %d rule(s) from %s" % (len(rules), options.rules))
    else:
        logger.verbose("rules install path: %s" % packaged_rules_path())
        rules = load_default_rules(logger)
    engine = RuleEngine(rules, config.interest)

    snaffler = Snaffler(credentials, config, engine, logger)

    targets = expand_targets(options.cidr, options.targets)
    if options.ldap:
        logger.info("LDAP host discovery (T1018)")
        try:
            discovered = discover_hosts_ldap(credentials, options.base_dn, logger=logger)
        except DiscoveryAuthError:
            sys.exit(2)
        targets = sorted(set(targets) | set(discovered))
        snaffler.creds_validated = True
        logger.info("discovered %d host(s) via LDAP" % len(discovered))
    if not targets:
        parser.error("no targets: use --ldap, --cidr, and/or --targets")

    snaffler.run(targets)


if __name__ == "__main__":
    main()
