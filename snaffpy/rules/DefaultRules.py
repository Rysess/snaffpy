from __future__ import annotations

from snaffpy.types.Rule import Rule, Scope, Triage


def default_rules() -> list[Rule]:
    """High-signal subset of Snaffler's DefaultRules, ported for the Linux engine.

    NOTE: kept in sync with rules/default_rules.json, which is the ruleset actually
    loaded at runtime. This embedded copy is only the fallback used when that file is
    missing or unparseable. Edit the JSON; regenerate this list to match.
    """
    R = Rule
    return [
        R('discard-shares', Scope.SHARE, 'sharename', 'exact',
          ['ipc$', 'print$'], Triage.GREEN, 'discard'),
        R('discard-dirs', Scope.DIRECTORY, 'filepath', 'contains',
          ['\\winsxs', '\\syswow64', '\\systemapps', '\\servicing', '\\windows\\immersivecontrolpanel', '\\windows\\diagnostics', '\\windows\\debug', '\\node_modules', '\\wsuscontent', '\\assembly\\gac', '\\windows\\assembly', '\\microsoft.net\\framework', '\\reference assemblies\\microsoft\\framework', '\\dotnet\\shared', '\\dotnet\\sdk', '\\windowspowershell\\modules', '\\chocolatey\\helpers', '\\sources\\sxs', '\\lib\\ruby', '\\site-packages', '\\vendor\\bundle', '\\vendor\\cache', '\\appdata\\local\\microsoft', '\\appdata\\roaming\\microsoft\\windows', '\\locale', '\\localization'], Triage.GREEN, 'discard'),
        R('file-name-black', Scope.FILE, 'filename', 'exact',
          ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'ntds.dit', 'shadow', 'sam', 'system', 'security', 'unattend.xml', 'autounattend.xml', 'sysprep.inf', 'groups.xml', 'scheduledtasks.xml', 'services.xml', 'printers.xml', 'drives.xml', 'datasources.xml', '.netrc', '.pgpass', 'shadow.bak'], Triage.BLACK),
        R('file-ext-black', Scope.FILE, 'fileext', 'exact',
          ['.kdbx', '.kdb', '.ppk', '.pfx', '.p12', '.keychain', '.ovpn', '.jks', '.psafe3', '.mdf', '.sqldump', '.rdg'], Triage.BLACK),
        R('file-name-ends-black', Scope.FILE, 'filename', 'endswith',
          ['_rsa', '_dsa', '_ed25519', '_ecdsa', '.npmrc', '.dockercfg'], Triage.BLACK),
        R('file-name-red', Scope.FILE, 'filename', 'exact',
          ['applicationhost.config', '.env', 'config.php', 'wp-config.php', 'local.settings.json', 'tnsnames.ora', '.bash_history', '.zsh_history', '.mysql_history', 'credentials', 'passwords.txt', 'pass.txt', 'secrets.txt', 'passwords.xlsx', 'passwords.docx', 'passwords.csv'], Triage.RED),
        R('file-ext-red', Scope.FILE, 'fileext', 'exact',
          ['.pem', '.key', '.der', '.kirbi', '.ccache', '.rdp', '.vnc', '.cscfg', '.vmdk', '.vhd', '.vhdx', '.ovf', '.sql', '.dmp'], Triage.RED),
        R('grep-ext', Scope.CONTENT, 'fileext', 'exact',
          ['.config', '.ini', '.inf', '.xml', '.yml', '.yaml', '.json', '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.vbs', '.sh', '.php', '.py', '.rb', '.java', '.cs', '.sql', '.properties', '.conf', '.cnf', '.env', '.tf', '.tfvars', '.pl', '.cfg', '.ovpn', '.txt'], Triage.GREEN, 'grep'),
        R('content-private-key', Scope.CONTENT, 'content', 'regex',
          ['-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----'], Triage.BLACK),
        R('content-putty-key', Scope.CONTENT, 'content', 'regex',
          ['PuTTY-User-Key-File-\\d'], Triage.BLACK),
        R('content-gpp-cpassword', Scope.CONTENT, 'content', 'regex',
          ['cpassword\\s*=\\s*"[^"]+"'], Triage.BLACK),
        R('content-aws-secret', Scope.CONTENT, 'content', 'regex',
          ['aws_secret_access_key\\s*=\\s*[\\\'"]?[A-Za-z0-9/+=]{40}'], Triage.BLACK),
        R('content-aws-akid', Scope.CONTENT, 'content', 'regex',
          ['\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b'], Triage.RED),
        R('content-slack-token', Scope.CONTENT, 'content', 'regex',
          ['xox[baprs]-[0-9]{10,}-[0-9A-Za-z-]{10,}'], Triage.RED),
        R('content-connstring', Scope.CONTENT, 'content', 'regex',
          ['(?:Data Source|Initial Catalog)=.{0,120}?(?:Password|Pwd)\\s*=\\s*[^\\s;]+'], Triage.RED),
        R('content-generic-pw', Scope.CONTENT, 'content', 'regex',
          ['(?:password|passwd|pwd|secret|api[_-]?key)\\s*[=:]\\s*[\\\'"][^\\\'"\\s]{4,64}'], Triage.YELLOW),
        R('content-xml-secret', Scope.CONTENT, 'content', 'regex',
          ['<(?:password|connectionString|apiKey)>[^<]{4,}</'], Triage.YELLOW),
    ]
