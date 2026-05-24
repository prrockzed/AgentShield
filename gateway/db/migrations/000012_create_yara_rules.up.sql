CREATE TABLE yara_rules (
    id          UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT    NOT NULL UNIQUE,
    category    TEXT    NOT NULL,
    rule_text   TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'HIGH',
    description TEXT,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_yara_rules_category ON yara_rules (category);
CREATE INDEX idx_yara_rules_active   ON yara_rules (active);

-- ============================================================
-- CRYPTO_MINER (10, severity CRITICAL)
-- ============================================================
INSERT INTO yara_rules (name, category, severity, description, rule_text) VALUES
('CryptoMiner_XMRig', 'CRYPTO_MINER', 'CRITICAL', 'Detects XMRig cryptocurrency miner strings',
$$rule CryptoMiner_XMRig {
    strings:
        $a = "xmrig" nocase
        $b = "--donate-level" nocase
        $c = "cryptonight" nocase
    condition:
        any of them
}$$),

('CryptoMiner_Stratum', 'CRYPTO_MINER', 'CRITICAL', 'Detects Stratum mining pool protocol',
$$rule CryptoMiner_Stratum {
    strings:
        $a = "stratum+tcp://" nocase
        $b = "stratum+ssl://" nocase
    condition:
        any of them
}$$),

('CryptoMiner_MiningPool', 'CRYPTO_MINER', 'CRITICAL', 'Detects common mining pool domain patterns',
$$rule CryptoMiner_MiningPool {
    strings:
        $a = "pool.minexmr.com" nocase
        $b = "xmrpool.eu" nocase
        $c = "moneroocean.stream" nocase
        $d = "supportxmr.com" nocase
    condition:
        any of them
}$$),

('CryptoMiner_XMRigConfig', 'CRYPTO_MINER', 'CRITICAL', 'Detects XMRig JSON configuration patterns',
$$rule CryptoMiner_XMRigConfig {
    strings:
        $a = "\"algo\"" nocase
        $b = "\"pools\"" nocase
        $c = "\"threads\"" nocase
        $d = "\"cpu-priority\"" nocase
    condition:
        3 of them
}$$),

('CryptoMiner_MoneroWallet', 'CRYPTO_MINER', 'CRITICAL', 'Detects Monero wallet address patterns',
$$rule CryptoMiner_MoneroWallet {
    strings:
        $a = /4[0-9A-Za-z]{94}/ fullword
    condition:
        $a
}$$),

('CryptoMiner_NiceHash', 'CRYPTO_MINER', 'CRITICAL', 'Detects NiceHash mining service references',
$$rule CryptoMiner_NiceHash {
    strings:
        $a = "nicehash" nocase
        $b = "nhm.exe" nocase
        $c = "NiceHashMiner" nocase
    condition:
        any of them
}$$),

('CryptoMiner_Ethminer', 'CRYPTO_MINER', 'CRITICAL', 'Detects Ethminer Ethereum miner strings',
$$rule CryptoMiner_Ethminer {
    strings:
        $a = "ethminer" nocase
        $b = "--farm-recheck" nocase
        $c = "ethpool.org" nocase
    condition:
        any of them
}$$),

('CryptoMiner_T-Rex', 'CRYPTO_MINER', 'CRITICAL', 'Detects T-Rex GPU miner strings',
$$rule CryptoMiner_TRex {
    strings:
        $a = "t-rex" nocase
        $b = "--algorithm" nocase
        $c = "kawpow" nocase
        $d = "octopus" nocase
    condition:
        $a and any of ($b, $c, $d)
}$$),

('CryptoMiner_PhoenixMiner', 'CRYPTO_MINER', 'CRITICAL', 'Detects PhoenixMiner GPU miner strings',
$$rule CryptoMiner_PhoenixMiner {
    strings:
        $a = "PhoenixMiner" nocase
        $b = "-pool" nocase
        $c = "-wal" nocase
    condition:
        $a and ($b or $c)
}$$),

('CryptoMiner_NBMiner', 'CRYPTO_MINER', 'CRITICAL', 'Detects NBMiner GPU miner strings',
$$rule CryptoMiner_NBMiner {
    strings:
        $a = "nbminer" nocase
        $b = "--api" nocase
        $c = "ergo" nocase
    condition:
        $a
}$$);

-- ============================================================
-- REVERSE_SHELL (10, severity CRITICAL)
-- ============================================================
INSERT INTO yara_rules (name, category, severity, description, rule_text) VALUES
('ReverseShell_BashDevTcp', 'REVERSE_SHELL', 'CRITICAL', 'Detects bash reverse shell via /dev/tcp',
$$rule ReverseShell_BashDevTcp {
    strings:
        $a = "/dev/tcp/" nocase
        $b = "bash -i" nocase
    condition:
        all of them
}$$),

('ReverseShell_NcExec', 'REVERSE_SHELL', 'CRITICAL', 'Detects netcat reverse shell with -e flag',
$$rule ReverseShell_NcExec {
    strings:
        $a = "nc " nocase
        $b = "-e /bin/sh" nocase
        $c = "-e /bin/bash" nocase
    condition:
        $a and ($b or $c)
}$$),

('ReverseShell_Mkfifo', 'REVERSE_SHELL', 'CRITICAL', 'Detects mkfifo-based reverse shell',
$$rule ReverseShell_Mkfifo {
    strings:
        $a = "mkfifo" nocase
        $b = "/bin/sh" nocase
        $c = "0<&" nocase
    condition:
        $a and $b and $c
}$$),

('ReverseShell_PythonSocket', 'REVERSE_SHELL', 'CRITICAL', 'Detects Python socket reverse shell',
$$rule ReverseShell_PythonSocket {
    strings:
        $a = "socket.socket" nocase
        $b = "os.dup2" nocase
        $c = "subprocess.call" nocase
    condition:
        $a and $b and $c
}$$),

('ReverseShell_PerlSocket', 'REVERSE_SHELL', 'CRITICAL', 'Detects Perl socket reverse shell',
$$rule ReverseShell_PerlSocket {
    strings:
        $a = "use Socket" nocase
        $b = "exec \"/bin/sh\"" nocase
        $c = "STDIN->fdopen" nocase
    condition:
        $a and ($b or $c)
}$$),

('ReverseShell_RubySocket', 'REVERSE_SHELL', 'CRITICAL', 'Detects Ruby socket reverse shell',
$$rule ReverseShell_RubySocket {
    strings:
        $a = "require 'socket'" nocase
        $b = "TCPSocket" nocase
        $c = "exec \"/bin/sh\"" nocase
    condition:
        $a and $b and $c
}$$),

('ReverseShell_Socat', 'REVERSE_SHELL', 'CRITICAL', 'Detects socat-based reverse shell',
$$rule ReverseShell_Socat {
    strings:
        $a = "socat" nocase
        $b = "EXEC:" nocase
        $c = "TCP:" nocase
    condition:
        $a and $b and $c
}$$),

('ReverseShell_PhpShell', 'REVERSE_SHELL', 'CRITICAL', 'Detects PHP reverse shell',
$$rule ReverseShell_PhpShell {
    strings:
        $a = "fsockopen" nocase
        $b = "proc_open" nocase
        $c = "shell_exec" nocase
        $d = "$sock" nocase
    condition:
        ($a or $b) and $c and $d
}$$),

('ReverseShell_PowerShell', 'REVERSE_SHELL', 'CRITICAL', 'Detects PowerShell reverse shell',
$$rule ReverseShell_PowerShell {
    strings:
        $a = "Net.Sockets.TCPClient" nocase
        $b = "GetStream()" nocase
        $c = "powershell" nocase
    condition:
        $a and $b
}$$),

('ReverseShell_Ncat', 'REVERSE_SHELL', 'CRITICAL', 'Detects ncat reverse shell',
$$rule ReverseShell_Ncat {
    strings:
        $a = "ncat" nocase
        $b = "--exec" nocase
        $c = "-e /bin/bash" nocase
    condition:
        $a and ($b or $c)
}$$);

-- ============================================================
-- PERSISTENCE (10, severity HIGH)
-- ============================================================
INSERT INTO yara_rules (name, category, severity, description, rule_text) VALUES
('Persistence_Crontab', 'PERSISTENCE', 'HIGH', 'Detects crontab-based persistence',
$$rule Persistence_Crontab {
    strings:
        $a = "crontab" nocase
        $b = "@reboot" nocase
        $c = "/etc/cron" nocase
    condition:
        any of them
}$$),

('Persistence_Systemctl', 'PERSISTENCE', 'HIGH', 'Detects systemctl service persistence',
$$rule Persistence_Systemctl {
    strings:
        $a = "systemctl enable" nocase
        $b = "systemctl start" nocase
    condition:
        any of them
}$$),

('Persistence_RcLocal', 'PERSISTENCE', 'HIGH', 'Detects /etc/rc.local persistence',
$$rule Persistence_RcLocal {
    strings:
        $a = "/etc/rc.local" nocase
        $b = "rc.local" nocase
    condition:
        any of them
}$$),

('Persistence_BashrcAppend', 'PERSISTENCE', 'HIGH', 'Detects .bashrc modification for persistence',
$$rule Persistence_BashrcAppend {
    strings:
        $a = ".bashrc" nocase
        $b = "echo " nocase
        $c = ">>" nocase
    condition:
        $a and $b and $c
}$$),

('Persistence_ProfileAppend', 'PERSISTENCE', 'HIGH', 'Detects .profile modification for persistence',
$$rule Persistence_ProfileAppend {
    strings:
        $a = ".profile" nocase
        $b = ">>" nocase
        $c = "bash_profile" nocase
        $d = ".zshrc" nocase
    condition:
        ($a or $c or $d) and $b
}$$),

('Persistence_SshAuthorizedKeys', 'PERSISTENCE', 'HIGH', 'Detects SSH authorized_keys modification',
$$rule Persistence_SshAuthorizedKeys {
    strings:
        $a = "authorized_keys" nocase
        $b = ".ssh/" nocase
    condition:
        $a and $b
}$$),

('Persistence_InitD', 'PERSISTENCE', 'HIGH', 'Detects /etc/init.d persistence',
$$rule Persistence_InitD {
    strings:
        $a = "/etc/init.d/" nocase
        $b = "update-rc.d" nocase
        $c = "chkconfig" nocase
    condition:
        any of them
}$$),

('Persistence_Udev', 'PERSISTENCE', 'HIGH', 'Detects udev rule-based persistence',
$$rule Persistence_Udev {
    strings:
        $a = "/etc/udev/rules.d/" nocase
        $b = "udevadm" nocase
    condition:
        any of them
}$$),

('Persistence_AtJob', 'PERSISTENCE', 'HIGH', 'Detects at-job based persistence',
$$rule Persistence_AtJob {
    strings:
        $a = "at now" nocase
        $b = "at -f" nocase
        $c = "/var/spool/cron/atjobs" nocase
    condition:
        any of them
}$$),

('Persistence_Launchd', 'PERSISTENCE', 'HIGH', 'Detects macOS launchd persistence',
$$rule Persistence_Launchd {
    strings:
        $a = "LaunchDaemons" nocase
        $b = "LaunchAgents" nocase
        $c = "launchctl" nocase
    condition:
        any of them
}$$);

-- ============================================================
-- OBFUSCATION (10, severity HIGH)
-- ============================================================
INSERT INTO yara_rules (name, category, severity, description, rule_text) VALUES
('Obfuscation_Base64Pipe', 'OBFUSCATION', 'HIGH', 'Detects base64-decode-pipe execution pattern',
$$rule Obfuscation_Base64Pipe {
    strings:
        $a = "base64 -d" nocase
        $b = "base64 --decode" nocase
    condition:
        any of them
}$$),

('Obfuscation_EvalDecode', 'OBFUSCATION', 'HIGH', 'Detects eval(decode(...)) obfuscation',
$$rule Obfuscation_EvalDecode {
    strings:
        $a = "eval(base64_decode" nocase
        $b = "eval(decode" nocase
        $c = "eval(gzinflate" nocase
    condition:
        any of them
}$$),

('Obfuscation_HexPayload', 'OBFUSCATION', 'HIGH', 'Detects hex-encoded payload execution',
$$rule Obfuscation_HexPayload {
    strings:
        $a = "\\x2f\\x62\\x69\\x6e" nocase
        $b = "echo -e '\\x" nocase
        $c = "$'\\x" nocase
    condition:
        any of them
}$$),

('Obfuscation_RevCmd', 'OBFUSCATION', 'HIGH', 'Detects reversed command string obfuscation',
$$rule Obfuscation_RevCmd {
    strings:
        $a = "rev |" nocase
        $b = "| rev" nocase
        $c = "rev)" nocase
    condition:
        any of them
}$$),

('Obfuscation_IFS', 'OBFUSCATION', 'HIGH', 'Detects IFS-based shell obfuscation',
$$rule Obfuscation_IFS {
    strings:
        $a = "${IFS}" nocase
        $b = "IFS=" nocase
        $c = "$IFS" nocase
    condition:
        any of them
}$$),

('Obfuscation_GzipPipe', 'OBFUSCATION', 'HIGH', 'Detects gzip decompression pipe execution',
$$rule Obfuscation_GzipPipe {
    strings:
        $a = "gunzip" nocase
        $b = "gzip -d" nocase
        $c = "zcat" nocase
    condition:
        any of them
}$$),

('Obfuscation_PythonExec', 'OBFUSCATION', 'HIGH', 'Detects Python exec() obfuscation',
$$rule Obfuscation_PythonExec {
    strings:
        $a = "exec(compile(" nocase
        $b = "exec(__import__" nocase
        $c = "exec(bytes.fromhex" nocase
    condition:
        any of them
}$$),

('Obfuscation_NodeEval', 'OBFUSCATION', 'HIGH', 'Detects Node.js eval obfuscation',
$$rule Obfuscation_NodeEval {
    strings:
        $a = "eval(Buffer.from(" nocase
        $b = "eval(require('fs')" nocase
        $c = "Function(atob(" nocase
    condition:
        any of them
}$$),

('Obfuscation_PowerShellEncode', 'OBFUSCATION', 'HIGH', 'Detects PowerShell encoded command obfuscation',
$$rule Obfuscation_PowerShellEncode {
    strings:
        $a = "-EncodedCommand" nocase
        $b = "-enc " nocase
        $c = "FromBase64String" nocase
    condition:
        any of them
}$$),

('Obfuscation_BashHexExpansion', 'OBFUSCATION', 'HIGH', 'Detects bash hex/octal expansion obfuscation',
$$rule Obfuscation_BashHexExpansion {
    strings:
        $a = "$'\\x62\\x61\\x73\\x68'" nocase
        $b = "printf '\\x" nocase
        $c = "$(printf '\\0" nocase
    condition:
        any of them
}$$);

-- ============================================================
-- EXFILTRATION (10, severity HIGH)
-- ============================================================
INSERT INTO yara_rules (name, category, severity, description, rule_text) VALUES
('Exfiltration_CurlPost', 'EXFILTRATION', 'HIGH', 'Detects curl-based data exfiltration',
$$rule Exfiltration_CurlPost {
    strings:
        $a = "curl" nocase
        $b = "--data" nocase
        $c = "-d " nocase
        $d = "/etc/passwd" nocase
        $e = "/etc/shadow" nocase
    condition:
        $a and ($b or $c) and ($d or $e)
}$$),

('Exfiltration_WgetPost', 'EXFILTRATION', 'HIGH', 'Detects wget-based data exfiltration',
$$rule Exfiltration_WgetPost {
    strings:
        $a = "wget" nocase
        $b = "--post-data" nocase
        $c = "--post-file" nocase
    condition:
        $a and ($b or $c)
}$$),

('Exfiltration_DevTcpWrite', 'EXFILTRATION', 'HIGH', 'Detects /dev/tcp write-based exfiltration',
$$rule Exfiltration_DevTcpWrite {
    strings:
        $a = ">/dev/tcp/" nocase
        $b = "cat /etc" nocase
    condition:
        $a and $b
}$$),

('Exfiltration_SshCopy', 'EXFILTRATION', 'HIGH', 'Detects scp/rsync exfiltration',
$$rule Exfiltration_SshCopy {
    strings:
        $a = "scp " nocase
        $b = "rsync " nocase
        $c = "/etc/passwd" nocase
        $d = "/etc/shadow" nocase
        $e = "~/.ssh/" nocase
    condition:
        ($a or $b) and ($c or $d or $e)
}$$),

('Exfiltration_Base64Curl', 'EXFILTRATION', 'HIGH', 'Detects base64-encoded curl exfiltration',
$$rule Exfiltration_Base64Curl {
    strings:
        $a = "base64" nocase
        $b = "curl" nocase
        $c = "/etc/passwd" nocase
        $d = "/etc/shadow" nocase
        $e = "~/.ssh" nocase
    condition:
        $a and $b and ($c or $d or $e)
}$$),

('Exfiltration_FtpPut', 'EXFILTRATION', 'HIGH', 'Detects FTP-based file exfiltration',
$$rule Exfiltration_FtpPut {
    strings:
        $a = "ftp " nocase
        $b = "put " nocase
        $c = "ftp://" nocase
    condition:
        ($a and $b) or $c
}$$),

('Exfiltration_SmbCopy', 'EXFILTRATION', 'HIGH', 'Detects SMB-based file exfiltration',
$$rule Exfiltration_SmbCopy {
    strings:
        $a = "smbclient" nocase
        $b = "smb://" nocase
        $c = "net use" nocase
    condition:
        any of them
}$$),

('Exfiltration_PythonRequests', 'EXFILTRATION', 'HIGH', 'Detects Python requests-based exfiltration',
$$rule Exfiltration_PythonRequests {
    strings:
        $a = "requests.post" nocase
        $b = "requests.put" nocase
        $c = "open('/etc/" nocase
        $d = "open(\"/etc/" nocase
    condition:
        ($a or $b) and ($c or $d)
}$$),

('Exfiltration_NcSend', 'EXFILTRATION', 'HIGH', 'Detects netcat-based data exfiltration',
$$rule Exfiltration_NcSend {
    strings:
        $a = "nc " nocase
        $b = "cat /etc/passwd" nocase
        $c = "cat /etc/shadow" nocase
        $d = "| nc" nocase
    condition:
        ($b or $c) and ($a or $d)
}$$),

('Exfiltration_DnsLookup', 'EXFILTRATION', 'HIGH', 'Detects DNS-based data exfiltration',
$$rule Exfiltration_DnsLookup {
    strings:
        $a = "nslookup" nocase
        $b = "dig " nocase
        $c = "host " nocase
        $d = "$(cat /etc/passwd)" nocase
        $e = "$(id)" nocase
    condition:
        ($a or $b or $c) and ($d or $e)
}$$);
