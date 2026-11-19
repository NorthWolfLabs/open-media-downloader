# OMD Windows Authenticode signing gate (omd-windows-signing-policy-v1).
# Every signature request (direct engine signing, or Tauri's bundle.windows.signCommand)
# passes through this script. It signs only files a reviewed policy names, refuses
# anything unknown and records every decision in an append-only JSONL audit log.
# Pinned third-party resources are never signed: Tauri asks to sign every unsigned
# resource PE, and the gate answers "skipped" after proving the bytes are unchanged.
# No credential is read or written here: the Artifact Signing client library
# authenticates through the operator's Azure CLI login.
param(
    [Parameter(Mandatory=$true)][string]$Policy,
    [Parameter(Mandatory=$true)][string]$Path
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Sha([string]$p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() }
function Full([string]$p) { [IO.Path]::GetFullPath($p.Replace('\\', '\').Trim('"')) }
function Under([string]$child, [string]$root) {
    $r = (Full $root).TrimEnd('\') + '\'
    return $child.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)
}
$policyPath = Full $Policy
$p = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
if ($p.schema -ne 'omd-windows-signing-policy-v1') { throw 'Unsupported signing policy' }
$file = Full $Path
$log = Full $p.audit_log
$event = [ordered]@{
    time = [DateTime]::UtcNow.ToString('o'); policy = $p.label; policy_sha256 = (Sha $policyPath)
    path = $file; rule = $null; action = 'refused'; pre_sha256 = $null; pre_size = $null
}
function Finish([int]$code, [string]$message) {
    if ($message) { $event.message = $message }
    $line = ($event | ConvertTo-Json -Compress -Depth 6)
    $stream = [IO.File]::Open($log, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $bytes = [Text.Encoding]::UTF8.GetBytes($line + "`n"); $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    if ($code -ne 0) { [Console]::Error.WriteLine("omd-sign-gate: $message") }
    exit $code
}
try {
    if (!(Test-Path -LiteralPath $file -PathType Leaf)) { Finish 2 'Requested file does not exist' }
    $item = Get-Item -LiteralPath $file
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Finish 2 'Reparse points are never signed' }
    $event.pre_sha256 = Sha $file; $event.pre_size = $item.Length
    $bytes = [IO.File]::ReadAllBytes($file)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 77 -or $bytes[1] -ne 90) { Finish 2 'Not a PE file' }

    # 1. Explicit rules: exact path plus exact pre-signature digest.
    $rule = $null
    foreach ($r in @($p.explicit)) { if ($r -and (Full $r.path) -ieq $file) { $rule = $r } }
    if ($rule) {
        $event.rule = 'explicit:' + $rule.role
        if ($event.pre_sha256 -ne $rule.pre_sha256) { Finish 2 "Pre-signature digest differs for $($rule.role)" }
    }
    # 2. The NSIS installer Tauri renames into the bundle directory.
    if (!$rule -and $p.installer -and (Full $p.installer.path) -ieq $file) {
        $text = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
        if ($text.IndexOf('NullsoftInst', [StringComparison]::Ordinal) -lt 0) { Finish 2 'Installer path does not hold an NSIS installer' }
        $rule = $p.installer; $event.rule = 'installer'
    }
    # 3. Skipped roots: pinned third-party resources and Tauri's NSIS plugin copies.
    if (!$rule) {
        foreach ($s in @($p.skip)) {
            if (!$s -or !(Under $file $s.root)) { continue }
            $event.rule = 'skip:' + $s.reason_id
            if ($s.inventory) {
                $inv = Get-Content -LiteralPath $s.inventory -Raw | ConvertFrom-Json
                $rel = $file.Substring((Full $s.root).TrimEnd('\').Length + 1).Replace('\', '/')
                $entry = @($inv.files | Where-Object { $_.path -eq $rel })
                if ($entry.Count -ne 1) { Finish 2 "Resource is not in the staged inventory: $rel" }
                if ($entry[0].sha256 -ne $event.pre_sha256) { Finish 2 "Resource differs from its inventory pin: $rel" }
                foreach ($f in @($s.never_skip)) { if ($rel -ieq $f) { Finish 2 "First-party resource reached the gate unsigned: $rel" } }
            }
            if ($s.expected) {
                $name = Split-Path -Leaf $file
                $ok = @($s.expected | Where-Object { $_.name -ieq $name -and $_.sha256 -eq $event.pre_sha256 })
                if ($ok.Count -ne 1) { Finish 2 "Unreviewed file under skipped root: $name" }
            }
            $event.action = 'skipped'; $event.reason = $s.reason
            Finish 0 $null
        }
    }
    # 4. The NSIS uninstaller produced by makensis !uninstfinalize (temporary path).
    if (!$rule -and $p.uninstaller) {
        $text = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
        if ($text.IndexOf('NullsoftInst', [StringComparison]::Ordinal) -ge 0) { $rule = $p.uninstaller; $event.rule = 'uninstaller' }
    }
    if (!$rule) { Finish 2 'No policy rule allows signing this file' }

    if ($p.dry_run) { $event.action = 'dry-run-not-signed'; Finish 0 $null }

    # Budget: count earlier signatures recorded under this policy label.
    $signed = 0
    if (Test-Path -LiteralPath $log) {
        foreach ($l in [IO.File]::ReadAllLines($log)) { if ($l) { $e = $l | ConvertFrom-Json; if ($e.policy -eq $p.label -and $e.action -eq 'signed') { $signed++ } } }
    }
    if ($signed -ge [int]$p.max_signatures) { Finish 2 'Signature budget for this policy is exhausted' }
    if ($event.rule -eq 'uninstaller' -and $p.uninstaller.max -ne $null) {
        $u = 0; foreach ($l in [IO.File]::ReadAllLines($log)) { if ($l) { $e = $l | ConvertFrom-Json; if ($e.policy -eq $p.label -and $e.action -eq 'signed' -and $e.rule -eq 'uninstaller') { $u++ } } }
        if ($u -ge [int]$p.uninstaller.max) { Finish 2 'Uninstaller signature budget exhausted' }
    }
    $before = Get-AuthenticodeSignature -LiteralPath $file
    if ($before.Status -ne 'NotSigned') { Finish 2 "Refusing to sign a file that already carries a signature ($($before.Status))" }
    foreach ($t in @(@($p.signtool, 'signtool'), @($p.dlib, 'dlib'), @($p.metadata, 'metadata'))) {
        if ((Sha $t[0].path) -ne $t[0].sha256) { Finish 2 "Signing tool digest changed: $($t[1])" }
    }
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $out = Join-Path (Full $p.output_logs) ("sign-$stamp.log")
    $signArgs = @('sign', '/v', '/fd', 'SHA256', '/tr', $p.timestamp_url, '/td', 'SHA256', '/dlib', $p.dlib.path, '/dmdf', $p.metadata.path, $file)
    $event.action = 'sign-attempted'
    & $p.signtool.path @signArgs *> $out
    $event.signtool_exit = $LASTEXITCODE; $event.signtool_log = Split-Path -Leaf $out
    if ($LASTEXITCODE -ne 0) { Finish 2 'signtool sign failed' }
    $event.action = 'signed'
    $after = Get-AuthenticodeSignature -LiteralPath $file
    $event.post_sha256 = Sha $file; $event.post_size = (Get-Item -LiteralPath $file).Length
    $event.status = [string]$after.Status
    $event.signer_subject = $after.SignerCertificate.Subject
    $event.signer_issuer = $after.SignerCertificate.Issuer
    $event.signer_thumbprint = $after.SignerCertificate.Thumbprint
    $event.signer_not_after = $after.SignerCertificate.NotAfter.ToUniversalTime().ToString('o')
    $event.timestamp_subject = if ($after.TimeStamperCertificate) { $after.TimeStamperCertificate.Subject } else { $null }
    $vout = Join-Path (Full $p.output_logs) ("verify-$stamp.log")
    & $p.signtool.path verify /pa /v /tw $file *> $vout
    $event.verify_exit = $LASTEXITCODE; $event.verify_log = Split-Path -Leaf $vout
    $vt = Get-Content -LiteralPath $vout -Raw
    $m = [regex]::Match($vt, 'The signature is timestamped:\s*(.+)')
    $event.timestamped_at = if ($m.Success) { $m.Groups[1].Value.Trim() } else { $null }
    if ($after.Status -ne 'Valid') { Finish 3 'Signature is not valid after signing' }
    if ($after.SignerCertificate.Subject -ne $p.expected_subject) { Finish 3 'Unexpected signer subject' }
    if (!$after.TimeStamperCertificate -or $after.TimeStamperCertificate.Subject -notmatch 'Microsoft') { Finish 3 'Missing Microsoft RFC3161 timestamp countersignature' }
    if ($LASTEXITCODE -ne 0 -or !$event.timestamped_at) { Finish 3 'signtool verify /pa /tw failed' }
    Finish 0 $null
} catch {
    $event.exception = $_.Exception.Message
    Finish 2 'Gate failure'
}
