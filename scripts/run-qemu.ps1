<#
.SYNOPSIS
    Run ospab.os in QEMU with the full set of devices the kernel has drivers for.

.DESCRIPTION
    Boots the newest isos\ospab-os-v2-N.iso (or -Iso) with networking, audio, a disk,
    USB and a monitor. The kernel log (serial port) goes to target\qemu\serial.log,
    and the QEMU monitor listens on telnet 127.0.0.1:<MonitorPort>.

.EXAMPLE
    .\scripts\run-qemu.ps1
    Newest ISO, BIOS, e1000, HDA audio, AHCI disk, window.
.EXAMPLE
    .\scripts\run-qemu.ps1 -Uefi -VMware
    UEFI boot with devices close to a VMware Workstation VM (vmware VGA, PCnet NIC, AC97, AHCI).
.EXAMPLE
    .\scripts\run-qemu.ps1 -Nic pcnet -Audio ac97 -Disk nvme
.EXAMPLE
    .\scripts\run-qemu.ps1 -Headless
    No window; kernel log printed to this console.
.EXAMPLE
    .\scripts\run-qemu.ps1 -Wav C:\temp\out.wav
    Record audio output to a WAV file instead of playing it.
#>
[CmdletBinding()]
param(
    [string]$Iso,
    [switch]$Uefi,
    [ValidateSet('e1000', 'pcnet', 'rtl8139', 'rtl8169', 'virtio', 'vmxnet3', 'none')]
    [string]$Nic = 'e1000',
    [ValidateSet('hda', 'ac97', 'es1370', 'none')]
    [string]$Audio = 'hda',
    [ValidateSet('dsound', 'sdl', 'none')]
    [string]$AudioBackend = 'dsound',
    [string]$Wav,
    [ValidateSet('ahci', 'nvme', 'ide', 'none')]
    [string]$Disk = 'ahci',
    [string]$DiskSize = '2G',
    [ValidateSet('std', 'vmware', 'virtio')]
    [string]$Vga = 'std',
    [switch]$VMware,
    [string]$Mem = '1G',
    [int]$Smp = 1,
    [switch]$Whpx,
    [switch]$Headless,
    [switch]$SerialToConsole,
    [switch]$NoUsb,
    [int]$MonitorPort = 55555,
    [string]$QemuDir = $(if ($env:QEMU_DIR) { $env:QEMU_DIR } else { 'D:\Toolz\qemu' }),
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Extra
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$qemu = Join-Path $QemuDir 'qemu-system-x86_64.exe'
$qemuImg = Join-Path $QemuDir 'qemu-img.exe'
if (-not (Test-Path $qemu)) {
    $found = Get-Command qemu-system-x86_64 -ErrorAction SilentlyContinue
    if (-not $found) { throw "qemu-system-x86_64 not found (use -QemuDir or set QEMU_DIR)" }
    $qemu = $found.Source
}
if (-not (Test-Path $qemuImg)) {
    $found = Get-Command qemu-img -ErrorAction SilentlyContinue
    $qemuImg = if ($found) { $found.Source } else { $null }
}

if ($VMware) { $Vga = 'vmware'; $Nic = 'pcnet'; $Audio = 'ac97'; $Disk = 'ahci' }
if ($Headless) { $SerialToConsole = $true }

# ── ISO ─────────────────────────────────────────────────────────────────────
if (-not $Iso) {
    $Iso = Get-ChildItem (Join-Path $root 'isos') -Filter 'ospab-os-v2-*.iso' -ErrorAction SilentlyContinue |
        Sort-Object { [int]($_.BaseName -replace '.*-(\d+)$', '$1') } |
        Select-Object -Last 1 -ExpandProperty FullName
}
if (-not $Iso -or -not (Test-Path $Iso)) {
    throw "No ISO found. Build one with ./build.sh (in WSL) or pass -Iso."
}

$out = Join-Path $root 'target\qemu'
New-Item -ItemType Directory -Force $out | Out-Null

$args_ = @('-m', $Mem, '-smp', "$Smp", '-cpu', 'max', '-no-reboot')
if ($Whpx) { $args_ += @('-accel', 'whpx', '-accel', 'tcg,tb-size=256') }
else { $args_ += @('-accel', 'tcg,tb-size=256') }

# Firmware
if ($Uefi) {
    $code = Join-Path $QemuDir 'share\edk2-x86_64-code.fd'
    if (-not (Test-Path $code)) { throw "UEFI firmware not found: $code" }
    $args_ += @('-drive', "if=pflash,format=raw,readonly=on,file=$code")
}

# Boot medium
$args_ += @('-cdrom', $Iso, '-boot', 'd')

# Disk (for the installer and persistence)
if ($Disk -ne 'none') {
    $img = Join-Path $out 'disk.qcow2'
    if (-not (Test-Path $img)) {
        if (-not $qemuImg) { throw "qemu-img not found; use -Disk none" }
        & $qemuImg create -f qcow2 $img $DiskSize | Out-Null
        Write-Host "created $img ($DiskSize)"
    }
    $args_ += @('-drive', "id=disk0,if=none,format=qcow2,file=$img")
    switch ($Disk) {
        'ahci' { $args_ += @('-device', 'ahci,id=ahci0', '-device', 'ide-hd,drive=disk0,bus=ahci0.0') }
        'nvme' { $args_ += @('-device', 'nvme,drive=disk0,serial=ospab0001') }
        'ide'  { $args_ += @('-device', 'ide-hd,drive=disk0') }
    }
}

# Network (user-mode: guest 10.0.2.15, gateway 10.0.2.2, DNS 10.0.2.3)
if ($Nic -ne 'none') {
    $dev = @{ e1000 = 'e1000'; pcnet = 'pcnet'; rtl8139 = 'rtl8139'; rtl8169 = 'rtl8169';
              virtio = 'virtio-net-pci'; vmxnet3 = 'vmxnet3' }[$Nic]
    $args_ += @('-netdev', 'user,id=n0', '-device', "$dev,netdev=n0")
} else {
    $args_ += @('-nic', 'none')
}

# Audio
if ($Audio -ne 'none') {
    if ($Wav) { $args_ += @('-audiodev', "wav,id=a0,path=$Wav") }
    else { $args_ += @('-audiodev', "$AudioBackend,id=a0") }
    switch ($Audio) {
        'hda'    { $args_ += @('-device', 'intel-hda', '-device', 'hda-duplex,audiodev=a0') }
        'ac97'   { $args_ += @('-device', 'AC97,audiodev=a0') }
        'es1370' { $args_ += @('-device', 'ES1370,audiodev=a0') }
    }
}

# Video
$args_ += @('-vga', $Vga)
if ($Headless) { $args_ += @('-display', 'none') }

# USB (xHCI + absolute pointer)
if (-not $NoUsb) { $args_ += @('-device', 'qemu-xhci,id=xhci', '-device', 'usb-tablet,bus=xhci.0') }

# Serial = kernel log
$serialLog = Join-Path $out 'serial.log'
if ($SerialToConsole) { $args_ += @('-serial', 'stdio') }
else { $args_ += @('-serial', "file:$serialLog") }

# Monitor
if ($MonitorPort -ne 0) { $args_ += @('-monitor', "telnet:127.0.0.1:$MonitorPort,server,nowait") }

if ($Extra) { $args_ += $Extra }

Write-Host "ISO:      $Iso"
Write-Host "Firmware: $(if ($Uefi) { 'uefi' } else { 'bios' })   NIC: $Nic   Audio: $Audio   Disk: $Disk   VGA: $Vga   Accel: $(if ($Whpx) { 'whpx' } else { 'tcg' })"
if (-not $SerialToConsole) { Write-Host "Serial:   $serialLog" }
if ($MonitorPort -ne 0) { Write-Host "Monitor:  telnet 127.0.0.1 $MonitorPort" }

& $qemu @args_
exit $LASTEXITCODE
