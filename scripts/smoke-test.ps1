<#
.SYNOPSIS
    One-command headless smoke test for an ospab.os-v2 ISO in QEMU.

.DESCRIPTION
    Boots the ISO headless, waits for "[  OK  ] Console: ready" in the serial log,
    types shell commands through the QEMU monitor (sendkey), takes a PNG screendump,
    and with -Shutdown types `shutdown` and expects QEMU to exit. Prints the guest's
    status lines and a PASS/FAIL verdict. Outputs go to
    <scratchpad>\smoke\<timestamp>\. Building the ISO is not part of this script.

    Usage (PowerShell 7, any directory):
      scripts\smoke-test.ps1                                  # newest isos\ospab-os-v2-*.iso, BIOS, no disk
      scripts\smoke-test.ps1 -Firmware uefi -Disk ide -Audio hda
      & scripts\smoke-test.ps1 -Commands "date -e","uname -a" -Shutdown
      scripts\smoke-test.ps1 -Iso isos\ospab-os-v2-179.iso -Nic virtio -TimeoutSec 180

    Use "&" (or run from an interactive pwsh) when passing -Commands with several
    values; "pwsh -File" does not bind comma-separated arrays.
    Exit code: 0 = PASS, 1 = FAIL.

.PARAMETER Iso
    ISO to boot. Default: the highest-numbered isos\ospab-os-v2-N.iso in the repo.
.PARAMETER Firmware
    bios (default) or uefi (read-only pflash with the bundled code.fd).
.PARAMETER Disk
    none (default), ide, ahci or nvme. Creates a temporary 256M qcow2, deleted afterwards.
.PARAMETER Nic
    e1000 (default), pcnet, vmxnet3 or virtio.
.PARAMETER Audio
    none (default), hda, ac97 or es1370. Uses a null audio backend.
.PARAMETER TimeoutSec
    Seconds to wait for the console-ready marker (default 120).
.PARAMETER Commands
    Shell commands typed after boot, each followed by Enter.
.PARAMETER Shutdown
    Type `shutdown` at the end; FAIL if QEMU has not exited within 20 s.
#>
[CmdletBinding()]
param(
    [string]$Iso,
    [ValidateSet('bios', 'uefi')]
    [string]$Firmware = 'bios',
    [ValidateSet('none', 'ide', 'ahci', 'nvme')]
    [string]$Disk = 'none',
    [ValidateSet('e1000', 'pcnet', 'vmxnet3', 'virtio')]
    [string]$Nic = 'e1000',
    [ValidateSet('none', 'hda', 'ac97', 'es1370')]
    [string]$Audio = 'none',
    [ValidateRange(10, 3600)]
    [int]$TimeoutSec = 120,
    [string[]]$Commands = @(),
    [switch]$Shutdown
)

$ErrorActionPreference = 'Stop'

$QemuExe         = 'D:\Toolz\qemu\qemu-system-x86_64.exe'
$QemuImg         = 'D:\Toolz\qemu\qemu-img.exe'
$PflashFw        = 'C:\Users\gvopr\AppData\Local\Temp\claude\D--ospab-projects-ospab-os-v2\cd885465-e879-446b-8f97-b11f8da57d17\scratchpad\net\code.fd'
$OutRoot         = 'C:\Users\gvopr\AppData\Local\Temp\claude\D--ospab-projects-ospab-os-v2\cd885465-e879-446b-8f97-b11f8da57d17\scratchpad\smoke'
$RepoRoot        = Split-Path -Parent $PSScriptRoot
$ReadyLine       = '[  OK  ] Console: ready'
$KeyDelayMs      = 60     # gap between keystrokes
$CommandGapMs    = 1500   # time for the shell to run each typed command
$ShutdownWaitSec = 20

# Character -> QEMU sendkey name (letters and digits are handled separately).
$KeyNames = @{
    ' ' = 'spc'; '-' = 'minus'; '.' = 'dot'; '/' = 'slash'; '=' = 'equal'
    '\' = 'backslash'; ',' = 'comma'; ';' = 'semicolon'; "'" = 'apostrophe'
    '`' = 'grave_accent'; '[' = 'bracket_left'; ']' = 'bracket_right'
    '_' = 'shift-minus'; '|' = 'shift-backslash'; ':' = 'shift-semicolon'
    '"' = 'shift-apostrophe'; '!' = 'shift-1'; '@' = 'shift-2'; '#' = 'shift-3'
    '$' = 'shift-4'; '%' = 'shift-5'; '^' = 'shift-6'; '&' = 'shift-7'
    '*' = 'shift-8'; '(' = 'shift-9'; ')' = 'shift-0'; '+' = 'shift-equal'
    '?' = 'shift-slash'; '<' = 'shift-comma'; '>' = 'shift-dot'
    '{' = 'shift-bracket_left'; '}' = 'shift-bracket_right'; '~' = 'shift-grave_accent'
    "`n" = 'ret'; "`r" = 'ret'
}

function Stop-Smoke([string]$Message) {
    Write-Host "smoke: $Message" -ForegroundColor Red
    exit 1
}

function ConvertTo-QemuKey([char]$Char) {
    $s = [string]$Char
    if ($s -cmatch '^[a-z0-9]$') { return $s }
    if ($s -cmatch '^[A-Z]$') { return 'shift-' + $s.ToLowerInvariant() }
    if ($KeyNames.ContainsKey($s)) { return $KeyNames[$s] }
    throw "no QEMU key name for character '$s'"
}

function Send-Monitor([string]$Line) {
    $bytes = [Text.Encoding]::ASCII.GetBytes("$Line`n")
    $stream = $Mon.GetStream()
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
    Start-Sleep -Milliseconds 20
    # Discard the monitor's echo/prompt so the socket buffer never fills up.
    $buf = [byte[]]::new(4096)
    while ($stream.DataAvailable) {
        if ($stream.Read($buf, 0, $buf.Length) -le 0) { break }
    }
}

function Send-Key([string]$Name) {
    Send-Monitor "sendkey $Name"
    Start-Sleep -Milliseconds $KeyDelayMs
}

function Type-Text([string]$Text) {
    foreach ($ch in $Text.ToCharArray()) { Send-Key (ConvertTo-QemuKey $ch) }
    Send-Key 'ret'
}

function Read-SharedText([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    # QEMU keeps the serial file open while writing; read it without locking it.
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $fs = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
    try { return ([IO.StreamReader]::new($fs)).ReadToEnd() } finally { $fs.Dispose() }
}

# ---- preflight (nothing is started until these pass) ------------------------
if (-not $Iso) {
    $Iso = Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'isos') -Filter 'ospab-os-v2-*.iso' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.BaseName -match '-\d+$' } |
        Sort-Object { [int]($_.BaseName -replace '^.*-(\d+)$', '$1') } |
        Select-Object -Last 1 -ExpandProperty FullName
    if (-not $Iso) { Stop-Smoke 'no isos\ospab-os-v2-*.iso found; pass -Iso' }
}
if (-not (Test-Path -LiteralPath $Iso -PathType Leaf)) { Stop-Smoke "ISO not found: $Iso" }
$Iso = (Resolve-Path -LiteralPath $Iso).Path
foreach ($tool in @($QemuExe, $QemuImg)) {
    if (-not (Test-Path -LiteralPath $tool)) { Stop-Smoke "missing tool: $tool" }
}
if ($Firmware -eq 'uefi' -and -not (Test-Path -LiteralPath $PflashFw)) {
    Stop-Smoke "missing UEFI firmware: $PflashFw"
}

# ---- run setup ---------------------------------------------------------------
$stamp      = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$OutDir     = Join-Path $OutRoot $stamp
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$SerialLog  = Join-Path $OutDir 'serial.log'
$Screenshot = Join-Path $OutDir 'screendump.png'
$QemuStdout = Join-Path $OutDir 'qemu-stdout.txt'
$QemuStderr = Join-Path $OutDir 'qemu-stderr.txt'
$DiskImg    = Join-Path $OutDir 'smoke-disk.qcow2'

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$MonPort = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()

$reasons   = [System.Collections.Generic.List[string]]::new()
$ready     = $false
$Proc      = $null
$Mon       = $null
$exitedEarly = $false
$shutdownOk  = $false

try {
    if ($Disk -ne 'none') {
        & $QemuImg create -f qcow2 $DiskImg 256M | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "qemu-img failed to create $DiskImg" }
    }

    $qemuArgs = @('-m', '512M', '-accel', 'tcg,tb-size=64', '-no-reboot', '-display', 'none')
    if ($Firmware -eq 'uefi') {
        $qemuArgs += @('-drive', "if=pflash,format=raw,readonly=on,file=$PflashFw")
    }
    $qemuArgs += @('-cdrom', $Iso, '-boot', 'd')
    switch ($Disk) {
        'ide'  { $qemuArgs += @('-drive', "id=disk0,if=none,format=qcow2,file=$DiskImg", '-device', 'ide-hd,drive=disk0') }
        'ahci' { $qemuArgs += @('-drive', "id=disk0,if=none,format=qcow2,file=$DiskImg", '-device', 'ahci,id=ahci0', '-device', 'ide-hd,drive=disk0,bus=ahci0.0') }
        'nvme' { $qemuArgs += @('-drive', "id=disk0,if=none,format=qcow2,file=$DiskImg", '-device', 'nvme,drive=disk0,serial=ospab0001') }
    }
    $nicDev = @{ e1000 = 'e1000'; pcnet = 'pcnet'; vmxnet3 = 'vmxnet3'; virtio = 'virtio-net-pci' }[$Nic]
    $qemuArgs += @('-netdev', 'user,id=n0', '-device', "$nicDev,netdev=n0")
    switch ($Audio) {
        'hda'    { $qemuArgs += @('-audiodev', 'none,id=a0', '-device', 'intel-hda', '-device', 'hda-duplex,audiodev=a0') }
        'ac97'   { $qemuArgs += @('-audiodev', 'none,id=a0', '-device', 'AC97,audiodev=a0') }
        'es1370' { $qemuArgs += @('-audiodev', 'none,id=a0', '-device', 'ES1370,audiodev=a0') }
    }
    $qemuArgs += @('-serial', "file:$SerialLog", '-monitor', "tcp:127.0.0.1:$MonPort,server,nowait")

    Write-Host "smoke: ISO=$Iso firmware=$Firmware disk=$Disk nic=$Nic audio=$Audio timeout=${TimeoutSec}s"
    $Proc = Start-Process -FilePath $QemuExe -ArgumentList $qemuArgs -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $QemuStdout -RedirectStandardError $QemuStderr

    # Connect to the monitor (QEMU may need a moment to start listening).
    $connectDeadline = (Get-Date).AddSeconds(15)
    while (-not $Mon -and (Get-Date) -lt $connectDeadline -and -not $Proc.HasExited) {
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $client.Connect('127.0.0.1', $MonPort)
            $Mon = $client
        } catch {
            $client.Dispose()
            Start-Sleep -Milliseconds 200
        }
    }
    if (-not $Mon) { throw 'could not connect to the QEMU monitor' }
    Send-Monitor 'info version' | Out-Null

    # Wait for the console-ready marker.
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ((Read-SharedText $SerialLog).Contains($ReadyLine)) { $ready = $true; break }
        if ($Proc.HasExited) { break }
        Start-Sleep -Milliseconds 300
    }

    if ($ready) {
        Write-Host 'smoke: console ready, typing commands'
        Start-Sleep -Milliseconds 1000
        foreach ($cmd in $Commands) {
            Write-Host "smoke: type: $cmd"
            Type-Text $cmd
            Start-Sleep -Milliseconds $CommandGapMs
        }
    }

    if (-not $Proc.HasExited) {
        Start-Sleep -Milliseconds 500
        Send-Monitor ("screendump " + $Screenshot.Replace('\', '/') + " -f png")
        Start-Sleep -Milliseconds 800
    }

    if ($ready -and $Shutdown -and -not $Proc.HasExited) {
        Write-Host 'smoke: typing shutdown'
        Type-Text 'shutdown'
        $shutdownOk = $Proc.WaitForExit($ShutdownWaitSec * 1000)
    }
    $exitedEarly = $Proc.HasExited -and -not ($Shutdown -and $shutdownOk)
}
catch {
    $reasons.Add("error: $($_.Exception.Message)")
}
finally {
    if ($Mon) { $Mon.Dispose() }
    if ($Proc -and -not $Proc.HasExited) {
        try { $Proc.Kill($true) } catch { }
        $Proc.WaitForExit(5000) | Out-Null
    }
    if (Test-Path -LiteralPath $DiskImg) { Remove-Item -LiteralPath $DiskImg -Force -ErrorAction SilentlyContinue }
}

# ---- verdict -----------------------------------------------------------------
$log       = Read-SharedText $SerialLog
$lines     = $log -split "`r?`n"
$statusRx  = '^\[\s*(OK|WARN|FAIL|--|INFO)\s*\]'
$statusLns = @($lines | Where-Object { $_ -match $statusRx })
$failLns   = @($lines | Where-Object { $_ -match '^\[ FAIL \]' })
$panicLns  = @($lines | Where-Object { $_ -cmatch 'panic|PANIC|EXCEPTION' })

Write-Host ''
Write-Host "---- guest status lines ($($statusLns.Count)) ----"
foreach ($l in $statusLns) { Write-Host $l }
Write-Host '----'

if (-not $ready -and $reasons.Count -eq 0) {
    if ($Proc -and $Proc.HasExited) { $reasons.Add("console never became ready (QEMU exited early)") }
    else { $reasons.Add("console never became ready within $TimeoutSec s") }
}
if ($failLns.Count -gt 0) { $reasons.Add("$($failLns.Count) line(s) starting with [ FAIL ]") }
if ($panicLns.Count -gt 0) { $reasons.Add("$($panicLns.Count) panic/EXCEPTION line(s) in the log") }
if ($ready -and $Shutdown -and -not $shutdownOk) { $reasons.Add("QEMU did not exit within $ShutdownWaitSec s after shutdown") }
if ($ready -and -not $Shutdown -and $exitedEarly) { $reasons.Add('QEMU exited unexpectedly (guest reset or crash)') }

$verdictPass = $reasons.Count -eq 0
if ($verdictPass) {
    Write-Host 'VERDICT: PASS'
} else {
    Write-Host 'VERDICT: FAIL'
    foreach ($r in $reasons) { Write-Host "  - $r" }
}
foreach ($l in ($failLns + $panicLns | Select-Object -First 10)) { Write-Host "  > $l" }

Write-Host "Log:        $SerialLog"
if (Test-Path -LiteralPath $Screenshot) { Write-Host "Screenshot: $Screenshot" } else { Write-Host 'Screenshot: not taken' }
Write-Host "Output dir: $OutDir"

exit $(if ($verdictPass) { 0 } else { 1 })
