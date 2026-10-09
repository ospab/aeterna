<#
.SYNOPSIS
    End-to-end test of tomato + the tmt repository in QEMU.

.DESCRIPTION
    Serves three copies of a repository from the host (good / tampered index / tampered
    package) with `python -m http.server`, boots an ISO headless in QEMU (user-mode net:
    the host is 10.0.2.2), and types the tomato / program commands from the script below
    through the QEMU monitor. A PNG screendump is taken after each step; ring-3 program
    output (the write syscall goes to the serial port) lands in serial.log.

    Prepare first:
      apps/build.sh repo <RepoGood>                      (builds, packs, indexes, signs)
      copy the repo to <RepoBadIndex> and <RepoBadPkg>, flip one byte in x86_64/index
      resp. in one .tmt (see tools/tmt/README or the report).

.EXAMPLE
    pwsh tools/tmt/e2e-qemu.ps1 -Iso isos/tmt-test.iso -RepoGood R/repo -RepoBadIndex R/repo_badidx -RepoBadPkg R/repo_badpkg -OutDir R/out
#>
param(
    [Parameter(Mandatory)][string]$Iso,
    [Parameter(Mandatory)][string]$RepoGood,
    [Parameter(Mandatory)][string]$RepoBadIndex,
    [Parameter(Mandatory)][string]$RepoBadPkg,
    [Parameter(Mandatory)][string]$OutDir,
    [string]$Qemu = 'D:\Toolz\qemu\qemu-system-x86_64.exe',
    [int]$MonPort = 0,
    [int]$BootTimeoutSec = 150,
    [int]$MaxSteps = 1000,
    [string[]]$QemuExtra = @()
)
$ErrorActionPreference = 'Stop'
$KeyDelayMs = 45
if ($MonPort -eq 0) {
    $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $l.Start()
    $MonPort = ([Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop()
}

$KeyNames = @{
    ' ' = 'spc'; '-' = 'minus'; '.' = 'dot'; '/' = 'slash'; '=' = 'equal'
    '\' = 'backslash'; ',' = 'comma'; ';' = 'semicolon'; "'" = 'apostrophe'
    '_' = 'shift-minus'; '|' = 'shift-backslash'; ':' = 'shift-semicolon'
    '"' = 'shift-apostrophe'; '$' = 'shift-4'; '^' = 'shift-6'; '*' = 'shift-8'
    '(' = 'shift-9'; ')' = 'shift-0'; '+' = 'shift-equal'; '?' = 'shift-slash'
    '>' = 'shift-dot'; '<' = 'shift-comma'; '%' = 'shift-5'
}
function ConvertTo-QemuKey([char]$c) {
    $s = [string]$c
    if ($s -cmatch '^[a-z0-9]$') { return $s }
    if ($s -cmatch '^[A-Z]$') { return 'shift-' + $s.ToLowerInvariant() }
    if ($KeyNames.ContainsKey($s)) { return $KeyNames[$s] }
    throw "no key for '$s'"
}
function Send-Monitor([string]$Line) {
    $b = [Text.Encoding]::ASCII.GetBytes("$Line`n")
    $st = $script:Mon.GetStream(); $st.Write($b, 0, $b.Length); $st.Flush()
    Start-Sleep -Milliseconds 20
    $buf = [byte[]]::new(4096)
    while ($st.DataAvailable) { if ($st.Read($buf, 0, $buf.Length) -le 0) { break } }
}
function Type-Line([string]$Text) {
    foreach ($ch in $Text.ToCharArray()) { Send-Monitor ("sendkey " + (ConvertTo-QemuKey $ch)); Start-Sleep -Milliseconds $KeyDelayMs }
    Send-Monitor 'sendkey ret'
}
function Read-Shared([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $fs = [IO.FileStream]::new($Path, 'Open', 'Read', ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try { return ([IO.StreamReader]::new($fs)).ReadToEnd() } finally { $fs.Dispose() }
}

# Ports: 8731 good, 8732 tampered index, 8733 tampered package.
$steps = @(
    @{ cmd = 'echo repo=http://10.0.2.2:8731/x86_64/ > /etc/tomato.conf'; wait = 2 }
    @{ cmd = 'cat /etc/tomato.conf'; wait = 2 }
    @{ cmd = 'tomato -Sy'; wait = 12; shot = '01-sync' }
    @{ cmd = 'tomato -Ss'; wait = 3; shot = '02-search' }
    @{ cmd = 'tomato -S calc'; wait = 14; shot = '03-install-calc' }
    @{ cmd = 'calc 2+3*4'; wait = 3 }
    @{ cmd = 'calc "(1+2)^3 / 4"'; wait = 3 }
    @{ cmd = 'echo calc exit status $?'; wait = 2; shot = '04-calc-ran' }
    @{ cmd = 'calc 1/0'; wait = 3 }
    @{ cmd = 'echo calc 1/0 exit status $?'; wait = 2 }
    @{ cmd = 'tomato -S ospab-apps'; wait = 25; shot = '05-install-meta' }
    @{ cmd = 'cowsay hello from ospab'; wait = 3 }
    @{ cmd = 'hello-tmt one two'; wait = 3 }
    @{ cmd = 'tomato -Q'; wait = 2 }
    @{ cmd = 'ls /usr/bin'; wait = 2; shot = '06-query' }
    @{ cmd = 'tomato -R calc'; wait = 2; shot = '07-remove-refused' }
    @{ cmd = 'tomato -R ospab-apps'; wait = 2 }
    @{ cmd = 'tomato -R calc cowsay hello-tmt'; wait = 3 }
    @{ cmd = 'tomato -Q'; wait = 2; shot = '08-removed' }
    @{ cmd = 'calc 1+1'; wait = 2; shot = '09-calc-gone' }
    @{ cmd = 'echo repo=http://10.0.2.2:8732/x86_64/ > /etc/tomato.conf'; wait = 2 }
    @{ cmd = 'tomato -Sy'; wait = 12; shot = '10-tampered-index' }
    @{ cmd = 'echo repo=http://10.0.2.2:8733/x86_64/ > /etc/tomato.conf'; wait = 2 }
    @{ cmd = 'tomato -Sy'; wait = 12 }
    @{ cmd = 'tomato -S hello-tmt'; wait = 12; shot = '11-tampered-package' }
    @{ cmd = 'tomato -S calc'; wait = 14; shot = '12-good-pkg-from-same-repo' }
    @{ cmd = 'tomato -Q'; wait = 2 }
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$serial = Join-Path $OutDir 'serial.log'
Remove-Item -ErrorAction SilentlyContinue $serial
$servers = @()
foreach ($s in @(@(8731, $RepoGood), @(8732, $RepoBadIndex), @(8733, $RepoBadPkg))) {
    $servers += Start-Process -PassThru -WindowStyle Hidden -FilePath python `
        -ArgumentList @('-I', '-m', 'http.server', $s[0], '--bind', '0.0.0.0', '--directory', (Resolve-Path $s[1]).Path) `
        -RedirectStandardError (Join-Path $OutDir "http$($s[0]).log") -RedirectStandardOutput (Join-Path $OutDir "http$($s[0]).out")
}
$proc = $null
for ($attempt = 0; $attempt -lt 8; $attempt++) {
    # Some ports are reserved by Windows (Hyper-V excluded ranges): retry with another one.
    $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $l.Start()
    $MonPort = ([Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop()
    $qargs = @('-m', '512M', '-accel', 'tcg,tb-size=64', '-no-reboot', '-display', 'none',
        '-cdrom', (Resolve-Path $Iso).Path, '-boot', 'd',
        '-netdev', 'user,id=n0', '-device', 'e1000,netdev=n0',
        '-serial', "file:$serial", '-monitor', "tcp:127.0.0.1:$MonPort,server,nowait") + $QemuExtra
    $proc = Start-Process -FilePath $Qemu -ArgumentList $qargs -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 1500
    if (-not $proc.HasExited) { break }
}
try {
    $script:Mon = $null
    for ($i = 0; $i -lt 50 -and -not $script:Mon; $i++) {
        $c = [Net.Sockets.TcpClient]::new()
        try { $c.Connect('127.0.0.1', $MonPort); $script:Mon = $c } catch { $c.Dispose(); Start-Sleep -Milliseconds 200 }
    }
    if (-not $script:Mon) { throw 'no monitor' }
    $deadline = (Get-Date).AddSeconds($BootTimeoutSec); $ready = $false
    while ((Get-Date) -lt $deadline) {
        if ((Read-Shared $serial).Contains('[  OK  ] Console: ready')) { $ready = $true; break }
        Start-Sleep -Milliseconds 400
    }
    if (-not $ready) { throw 'console never became ready' }
    Start-Sleep 2
    foreach ($s in ($steps | Select-Object -First $MaxSteps)) {
        Write-Host "> $($s.cmd)"
        Type-Line $s.cmd
        Start-Sleep -Seconds $s.wait
        if ($s.shot) {
            Send-Monitor ("screendump " + (Join-Path $OutDir ($s.shot + '.png')).Replace('\', '/') + ' -f png')
            Start-Sleep -Milliseconds 700
        }
    }
} finally {
    if ($script:Mon) { $script:Mon.Dispose() }
    if ($proc -and -not $proc.HasExited) { $proc.Kill($true) }
    foreach ($s in $servers) { if (-not $s.HasExited) { $s.Kill($true) } }
}
Write-Host "done: $OutDir"
