$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DistDirectory = Join-Path $ProjectRoot "dist"
$BuildCache = Join-Path $env:TEMP "serverportforward-gocache"

New-Item -ItemType Directory -Force -Path $DistDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $BuildCache | Out-Null

$env:GOCACHE = $BuildCache
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"

Push-Location $ProjectRoot
try {
    go test ./...

    $env:GOARCH = "amd64"
    go build -trimpath -ldflags="-s -w -H=windowsgui" -o (Join-Path $DistDirectory "server-port-forward-windows-amd64.exe") .

    $env:GOARCH = "arm64"
    go build -trimpath -ldflags="-s -w -H=windowsgui" -o (Join-Path $DistDirectory "server-port-forward-windows-arm64.exe") .
}
finally {
    Pop-Location
}

Write-Host "Build complete: $DistDirectory"
