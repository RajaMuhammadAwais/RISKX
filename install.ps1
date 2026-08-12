# RISKX one-command installer (Windows, PowerShell)
#
# Usage (PowerShell 5.1+ / PowerShell Core):
#   irm https://raw.githubusercontent.com/RajaMuhammadAwais/RISKX/main/install.ps1 | iex
#   $env:RISKX_VERSION="v0.4.0"; irm https://raw.githubusercontent.com/RajaMuhammadAwais/RISKX/main/install.ps1 | iex   # specific release
#
# Does exactly four things:
#   1. Resolves the latest stable RISKX release from GitHub (never prereleases
#      unless RISKX_VERSION is set explicitly).
#   2. Downloads ONE executable and its checksums file from the official
#      GitHub Releases (HTTPS only, no git clone, no source tree).
#   3. Verifies the SHA-256 checksum of the downloaded executable.
#   4. Installs the verified executable to a user-local directory and prints
#      the installed version; explains PATH configuration if needed.
#
# Requires no administrator privileges (user-local install).
# It never: hides the binary, obfuscates itself, downloads unrelated files,
# modifies unrelated user files, installs persistence, creates scheduled
# tasks, touches firewall rules, collects telemetry, or executes arbitrary
# remote commands.

$ErrorActionPreference = "Stop"

$repo       = "RajaMuhammadAwais/RISKX"
$binName    = "riskx.exe"
$releasesApi = "https://api.github.com/repos/$repo/releases"

# --- OS sanity check (this script is for Windows) --------------------------
if (-not $IsWindows -and $env:OS -eq $null -and (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption -notmatch "Windows") {
    Write-Error "This installer is for Windows. Use install.sh on Linux/macOS."
    exit 1
}

# --- Architecture detection ------------------------------------------------
$arch = switch (([Environment]::Is64BitOperatingSystem)) {
    $true  { "amd64" }
    $false { "arm64" }
}
# Note: x86 (32-bit) Windows is not a supported build target.

# --- Resolve the release ---------------------------------------------------
$tag = $env:RISKX_VERSION
if ([string]::IsNullOrWhiteSpace($tag)) {
    try {
        $latest = Invoke-RestMethod -Uri "$releasesApi/latest" -UseBasicParsing
        $tag = $latest.tag_name
    } catch {
        Write-Error "Cannot reach GitHub Releases API - check your internet connection.`n$_"
        exit 1
    }
    if ([string]::IsNullOrWhiteSpace($tag)) {
        Write-Error "No release found for $repo."
        exit 1
    }
}
if (-not $tag.StartsWith("v")) { $tag = "v$tag" }
$version = $tag.TrimStart("v")
$assetName = "riskx_windows_$arch.exe"
$base = "https://github.com/$repo/releases/download/$tag"
$binaryUrl = "$base/$assetName"
$checksumsUrl = "$base/checksums.txt"

Write-Host "==> Resolved release: $tag (windows/$arch)"

# --- Download executable + checksums ---------------------------------------
$tempDir = Join-Path $env:TEMP "riskx-install"
if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }
New-Item -ItemType Directory -Path $tempDir | Out-Null

$binary = Join-Path $tempDir $assetName
try {
    (Invoke-WebRequest -Uri $binaryUrl -OutFile $binary -UseBasicParsing)
} catch {
    Write-Error "Download failed: $binaryUrl`nThe release $tag may not exist for windows/$arch.`n$_"
    Remove-Item -Force $binary -ErrorAction SilentlyContinue
    exit 1
}

$checksumsFile = Join-Path $tempDir "checksums.txt"
try {
    (Invoke-WebRequest -Uri $checksumsUrl -OutFile $checksumsFile -UseBasicParsing)
} catch {
    Write-Error "Download failed: $checksumsUrl`nChecksum file missing for release $tag - refusing to install.`n$_"
    Remove-Item -Force $binary -ErrorAction SilentlyContinue
    exit 1
}

# --- SHA-256 verification (install aborts on failure) ----------------------
$line = Get-Content $checksumsFile | Where-Object { $_ -match [regex]::Escape($assetName) }
if (-not $line) {
    Write-Error "checksums.txt does not contain an entry for $assetName.`nChecksum verification failed - downloaded file removed, not installed."
    Remove-Item -Force $binary -ErrorAction SilentlyContinue
    exit 1
}
$want = ($line -split "\s+")[0]
$got = (Get-FileHash -Path $binary -Algorithm SHA256).Hash.ToLower()
if ($got -ne $want.ToLower()) {
    Write-Error ("SHA-256 checksum verification failed for $assetName`n  expected: $want`n  got:      $got`nThe downloaded file has been removed and will NOT be installed.")
    Remove-Item -Force $binary -ErrorAction SilentlyContinue
    exit 1
}
Write-Host "==> SHA-256 checksum verified"

# --- Install ---------------------------------------------------------------
$installDir = $env:RISKX_BIN_DIR
if ([string]::IsNullOrWhiteSpace($installDir)) {
    $installDir = Join-Path $env:USERPROFILE ".local\bin"
}
if (-not (Test-Path $installDir)) { New-Item -ItemType Directory -Path $installDir | Out-Null }

$installed = Join-Path $installDir $binName
Copy-Item -Force $binary $installed

# --- PATH guidance ---------------------------------------------------------
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$inPath = ($userPath -split ";") -contains $installDir
if (-not $inPath) {
    Write-Host ""
    Write-Host "$installDir is not on your PATH. Add it with:"
    Write-Host "  [Environment]::SetEnvironmentVariable('Path',`$env:Path + ';$installDir', 'User')"
    Write-Host "or in a new PowerShell window:"
    Write-Host "  `$newPath = `"$installDir;`" + `$env:Path; [Environment]::SetEnvironmentVariable('Path', `$newPath, 'User')"
    Write-Host "The change applies to new processes after they restart."
}

# --- Verify ----------------------------------------------------------------
try {
    $verOut = & $installed version
    Write-Host ""
    Write-Host "RISKX installed successfully."
    Write-Host "  Binary: $installed"
    Write-Host ("  Version: " + ($verOut | Select-Object -First 1))
} catch {
    Write-Error "Binary installed to $installed but could not be executed.`n$_"
    exit 1
}

# Cleanup
Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
