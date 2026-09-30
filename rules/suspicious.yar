/*
 * CUSTOMS YARA Rules — Suspicious file patterns.
 * 
 * These rules detect common malware characteristics without targeting
 * specific threat actor tooling. Generic enough to publish, specific
 * enough to be useful.
 * 
 * Usage: yara -r rules/suspicious.yar /path/to/sample
 */

import "math"

rule Suspicious_High_Entropy_Section {
    meta:
        description = "Detects files with overall high entropy (packed/encrypted)"
        severity = "medium"
        stage = "N8_yara"
    condition:
        filesize > 1024 and filesize < 100MB and math.entropy(0, filesize) >= 7.2
}


rule Embedded_Executable_Magic {
    meta:
        description = "Detects PE/ELF/Mach-O headers embedded in non-executable files"
        severity = "high"
        stage = "N8_yara"
    strings:
        $elf = { 7F 45 4C 46 }       // ELF magic
        $mz  = { 4D 5A }              // MZ (PE/DOS) magic
        $macho32 = { CE FA ED FE }    // Mach-O 32-bit
        $macho64 = { CF FA ED FE }    // Mach-O 64-bit
    condition:
        // Force matches AFTER file start (offset 1+) — avoids false positives
        // on legitimate executables where magic is at offset 0.
        ($elf in (1..filesize)) or 
        ($mz in (1..filesize)) or 
        ($macho32 in (1..filesize)) or 
        ($macho64 in (1..filesize))
}


rule Suspicious_Shell_Commands {
    meta:
        description = "Detects embedded shell commands common in malware droppers"
        severity = "high"
        stage = "N8_yara"
    strings:
        $curl_bash = "curl" nocase
        $wget = "wget" nocase
        $nc_rev = "nc -e /bin/" nocase
        $dev_tcp = "/dev/tcp/" 
        $base64_d = "base64 -d" nocase
        $eval_b64 = "eval(base64_decode"
        $rm_rf = "rm -rf /" 
        $powershell_enc = "powershell -enc" nocase
    condition:
        3 of them
}


rule Persistence_Mechanisms {
    meta:
        description = "Detects persistence mechanisms in scripts/binaries"
        severity = "high"
        stage = "N8_yara"
    strings:
        $cron1 = "/etc/cron" nocase
        $cron2 = "crontab" nocase
        $systemd = "systemctl enable" nocase
        $rc_local = "/etc/rc.local"
        $bashrc = ".bashrc"
        $profile = ".profile"
        $reg_run = "CurrentVersion\\Run" nocase
        $schtasks = "schtasks /create" nocase
        $launchd = "LaunchDaemons" nocase
    condition:
        2 of them
}


rule Encoded_Payload {
    meta:
        description = "Detects base64/hex-encoded payloads"
        severity = "medium"
        stage = "N8_yara"
    strings:
        $b64_long = /[A-Za-z0-9+\/]{200,2000}={0,2}/
        $hex_long = /(\\x[0-9a-fA-F]{2}){20,}/
    condition:
        any of them
}


rule Cryptominer_Strings {
    meta:
        description = "Detects cryptominer-related strings"
        severity = "medium"
        stage = "N8_yara"
    strings:
        $xmrig1 = "xmrig" nocase
        $xmrig2 = "donate-level" nocase
        $pool1 = "stratum+tcp://" 
        $pool2 = "cryptonight" nocase
        $pool3 = "randomx" nocase
        $wallet = /[A-Za-z0-9]{90,100}/
    condition:
        ($xmrig1 or $xmrig2) or (($pool1 or $pool2 or $pool3) and $wallet)
}
