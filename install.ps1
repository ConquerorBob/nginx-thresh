# Install thresh on Windows from GitHub Releases.
#
#   irm https://raw.githubusercontent.com/ConquerorBob/nginx-thresh/main/install.ps1 | iex
#
# Environment:
#   THRESH_VERSION  release tag to install (default: latest)

$ErrorActionPreference = "Stop"
$repo = "ConquerorBob/nginx-thresh"
$installDir = Join-Path $env:LOCALAPPDATA "thresh\bin"
$exe = Join-Path $installDir "thresh.exe"

if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
    throw "No prebuilt binary for $env:PROCESSOR_ARCHITECTURE. Build from source with: cargo build --release"
}

$version = $env:THRESH_VERSION
if (-not $version) {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest"
    $version = $release.tag_name
}
if (-not $version) {
    throw "Could not find a published release."
}

$target = "x86_64-pc-windows-msvc"
$archive = "thresh-$version-$target.zip"
$baseUrl = "https://github.com/$repo/releases/download/$version"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("thresh-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Force $tmp | Out-Null

try {
    $archivePath = Join-Path $tmp $archive
    $checksumPath = "$archivePath.sha256"
    Write-Host "Downloading $archive"
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/$archive" -OutFile $archivePath
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/$archive.sha256" -OutFile $checksumPath

    $expected = ((Get-Content $checksumPath -Raw) -split '\s+')[0].ToLower()
    $actual = (Get-FileHash $archivePath -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected) {
        throw "Checksum mismatch for $archive"
    }

    Expand-Archive -Path $archivePath -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Force $installDir | Out-Null
    Copy-Item (Join-Path $tmp "thresh.exe") $exe -Force
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
    Write-Host "Added $installDir to your user PATH. Open a new terminal to use it."
}

Write-Host "Installed $exe"
& $exe --version
