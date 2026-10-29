# SPDX-License-Identifier: AGPL-3.0-only
# Build the sample programs, pack them into .tmt packages and optionally assemble a
# signed repository. Windows / PowerShell 7 version of apps/build.sh.
#
#   .\apps\build.ps1                                  packages -> apps\dist\*.tmt
#   .\apps\build.ps1 -Repo D:\ospab-projects\tmt-repo  also build + sign + verify the repo
#   .\apps\build.ps1 -Repo ... -Upload user@server     and upload it to tmt.ospab.org
#   .\apps\build.ps1 -Only beeb,drift ...              only these packages (cargo package and
#                                                     apps\pkg\<name>.toml share the name)
#
# The signing key is %USERPROFILE%\.ospab\tmt.key (tmt keygen); -Key overrides it.
# Needs: nightly cargo with rust-src (same as the kernel) and stable cargo for tmt;
# -Upload needs the OpenSSH client (scp), which Windows 10/11 ships.

param(
    [string]$Repo,
    [string]$Key,
    [string]$Upload,
    [string]$RemoteDir = '/var/www/tmt.ospab.org/x86_64',
    [string[]]$Only
)

$ErrorActionPreference = 'Stop'
$Apps = $PSScriptRoot
$Root = Split-Path $Apps -Parent
$TmtDir = Join-Path $Root 'tools\tmt'
$Tmt = Join-Path $TmtDir 'bin\tmt.exe'

function Run([string]$What, [scriptblock]$Cmd) {
    Write-Host "--- $What ---"
    & $Cmd
    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
}

# RUSTFLAGS would override the .cargo/config.toml files that carry targets and linker scripts.
$savedRustflags = $env:RUSTFLAGS
Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
try {
    # 1. Host packer. Pass the host triple so the kernel's .cargo/config.toml
    #    (bare-metal target + build-std) from the repository root does not apply.
    if (-not (Test-Path $Tmt)) {
        $hostTriple = ((rustc -vV) -match '^host:' -replace '^host:\s*', '').Trim()
        Push-Location $TmtDir
        try { Run 'Building tmt' { cargo build --release --target $hostTriple } } finally { Pop-Location }
        New-Item -ItemType Directory -Force (Split-Path $Tmt) | Out-Null
        Copy-Item (Join-Path $TmtDir "target\$hostTriple\release\tmt.exe") $Tmt -Force
    }

    # 2. Programs for x86_64-unknown-oos (apps\.cargo\config.toml selects target and linker script).
    Push-Location $Apps
    $pkgArgs = @()
    foreach ($n in $Only) { $pkgArgs += @('-p', $n) }
    try { Run 'Building programs' { cargo +nightly build --release @pkgArgs } } finally { Pop-Location }

    # 3. Packages (manifests use paths relative to apps\).
    $dist = Join-Path $Apps 'dist'
    if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
    New-Item -ItemType Directory $dist | Out-Null
    Push-Location $Apps
    try {
        $manifests = Get-ChildItem (Join-Path $Apps 'pkg\*.toml')
        if ($Only) { $manifests = $manifests | Where-Object { $Only -contains $_.BaseName } }
        foreach ($m in $manifests) {
            Run "Packing $($m.Name)" { & $Tmt pack $m.FullName -o $dist }
        }
    } finally { Pop-Location }

    if (-not $Repo) { Write-Host "Packages are in $dist"; return }

    # 4. Repository: add, index, sign, verify against the key compiled into the OS.
    $tmts = (Get-ChildItem (Join-Path $dist '*.tmt')).FullName
    Run 'Adding packages' { & $Tmt repo add $Repo @tmts }
    Run 'Writing index' { & $Tmt repo index $Repo }
    if ($Key) { Run 'Signing index' { & $Tmt repo sign $Repo --key $Key } }
    else { Run 'Signing index' { & $Tmt repo sign $Repo } }
    Run 'Verifying signature' { & $Tmt repo verify $Repo --pub (Join-Path $Root 'userland\tomato\repo_key.pub') }
    Write-Host "Repository is in $(Join-Path $Repo 'x86_64')"

    # 5. Upload: packages first, then index, signature last, so clients never see
    #    an index whose packages are not there yet.
    if ($Upload) {
        $src = Join-Path $Repo 'x86_64'
        # With -Only, upload just the packages built now; the index still lists the whole repo.
        $pkgs = (Get-ChildItem (Join-Path $src '*.tmt')).FullName
        if ($Only) { $pkgs = $pkgs | Where-Object { $Only -contains ((Split-Path $_ -Leaf) -replace '-[0-9][^-]*\.tmt$', '') } }
        Run 'Uploading packages' { scp @pkgs "${Upload}:$RemoteDir/" }
        Run 'Uploading index' { scp (Join-Path $src 'index') "${Upload}:$RemoteDir/" }
        Run 'Uploading signature' { scp (Join-Path $src 'index.sig') "${Upload}:$RemoteDir/" }
        Write-Host "Uploaded. Check: curl -I https://tmt.ospab.org/x86_64/index"
    }
} finally {
    if ($null -ne $savedRustflags) { $env:RUSTFLAGS = $savedRustflags }
}
