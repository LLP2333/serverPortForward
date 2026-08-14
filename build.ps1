$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DistDirectory = Join-Path $ProjectRoot "dist"
$BuildCache = Join-Path $env:TEMP "serverportforward-gocache"

New-Item -ItemType Directory -Force -Path $DistDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $BuildCache | Out-Null

$env:GOCACHE = $BuildCache
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"

function Invoke-Go {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    & go @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "go $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

Push-Location $ProjectRoot
try {
    Invoke-Go @("test", "./...")

    $env:GOARCH = "amd64"
    Invoke-Go @(
        "build", "-trimpath", "-ldflags=-s -w -H=windowsgui",
        "-o", (Join-Path $DistDirectory "server-port-forward-windows-amd64.exe"),
        "./cmd/server-port-forward"
    )

    $env:GOARCH = "arm64"
    Invoke-Go @(
        "build", "-trimpath", "-ldflags=-s -w -H=windowsgui",
        "-o", (Join-Path $DistDirectory "server-port-forward-windows-arm64.exe"),
        "./cmd/server-port-forward"
    )
}
finally {
    Pop-Location
}

Write-Host "Build complete: $DistDirectory"
