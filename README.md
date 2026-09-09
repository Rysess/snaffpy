# Snaffpy

Snaffler, ported to Linux. Discovers SMB shares across a network, walks the readable ones, and triages files against a Snaffler-style rule set to surface credentials and other sensitive data.

## Install

```
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Quick setup

0. Get valid domain credentials (password, NT hash, or Kerberos ticket)
1. Pick your targets: `--ldap` to pull hosts from AD, or `--cidr` / `--targets`
2. Run `snaffpy -d DOMAIN -u USER -p PASSWORD --ldap`
3. Read the findings, or write them with `-o loot.jsonl`

## Usage

Autodiscover hosts from Active Directory and snaffle:

```
snaffpy -d corp.local -u svc_scan -p 'Passw0rd!' --ldap -o loot.jsonl
```

Scan a subnet with pass-the-hash, name and extension rules only:

```
snaffpy -d corp.local -u svc_scan --hashes :aad3b435...31d6 --cidr 10.0.20.0/24 --no-content
```

Kerberos (the KDC wants a name for SPNs, so point `--dc-host` at the DC's FQDN):

```
snaffpy -d corp.local -u svc_scan -k --dc-host dc01.corp.local --cidr 10.0.20.0/24
```

## Discovery

`--ldap` queries Active Directory for enabled computer objects and resolves their
DNS host names. It can be combined with `--cidr` and `--targets`. A successful LDAP
bind also validates the credentials before any SMB logon is attempted.

Point the LDAP and Kerberos traffic at a specific domain controller with `--dc-ip`
(its IP, used for the LDAP bind and, on its own, as the KDC) and/or `--dc-host` (its
FQDN, used as the Kerberos KDC since SPNs need a name). When both are given, LDAP uses
the IP and Kerberos uses the FQDN; with neither, the domain name is resolved instead.

## Rules

The default rules live in `snaffpy/rules/default_rules.json` and are loaded on every
run. Edit that file in place, point at another file with `$SNAFFPY_RULES`, or override
per run with `--rules rules.json`. Export a fresh copy to edit with `--dump-rules rules.json`.

Rules run in four stages: share, directory, file name/extension, and file content.
Each match is triaged Black, Red, Yellow, or Green. Use `--interest` to set the
minimum level reported.

## Access paths

With `--acls`, each finding is annotated with the AD groups that grant read access,
resolved over LSAT. For deeper analysis, run the enrichment tool on a findings file
to map each hit to the groups that grant access and flag the ones your account holds:

```
snaffpy-accesspaths loot.jsonl -d corp.local -u svc_scan -p 'Passw0rd!' \
  --dc-ip 10.0.0.10 --min-triage Red --expand
```

## Account safety

Before scanning a range, the credentials are validated against the first reachable
host. If they are rejected, the run aborts immediately instead of repeating a failed
logon on every host, which would lock the account. A lockout detected mid-run also
stops the scan.

## Options

```
--dc-ip IP             Domain controller IP for LDAP discovery (and KDC unless --dc-host set)
--dc-host FQDN         Domain controller FQDN, used as the Kerberos KDC
--interest LEVEL       Minimum triage to report: Black, Red, Yellow, Green
--share-allow GLOB     Only scan matching shares (repeatable)
--admin-shares         Include C$, ADMIN$ and other hidden shares
--no-content           Skip content reads (name and extension rules only)
--max-file-size N      Max bytes read per file for content rules
--threads N            Host concurrency
--delay / --jitter     Per-file pacing
-v / --verbose         Step-by-step output
--debug                Errors with tracebacks
-o FILE                Write findings as JSONL
```

## Notes

As specified by the original snaffler repo, this collection is noisy. The tool will connect to each server and to each share.

## Requirements

- Python 3.9+
- impacket

## Credits

The one and only Snaffler https://github.com/SnaffCon/Snaffler
