# Verify that committed TypeSpec-generated artifacts are up to date.
#
# Re-runs the TypeSpec compiler against the .tsp sources and fails if
# the resulting OpenAPI / Protobuf files differ from what is currently
# checked in under tsp-output/. Intended to be run from CI so that a
# .tsp change without a matching regenerated artifact cannot land.
#
# Usage:
#   pwsh ./scripts/verify-generated.ps1
#
# Exit codes:
#   0 - all artifacts match
#   1 - drift detected (diff is printed)
#   2 - prerequisites missing (npm / npx / git)

$ErrorActionPreference = 'Stop'

# Resolve repo paths relative to this script (scripts/ lives next to
# package.json under typespec-poc/).
$scriptRoot = Split-Path -Parent $PSCommandPath
$projectRoot = Resolve-Path (Join-Path $scriptRoot '..')
Set-Location $projectRoot

foreach ($cmd in @('npm', 'npx', 'git')) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Error "Required command not found on PATH: $cmd"
        exit 2
    }
}

if (-not (Test-Path 'node_modules')) {
    Write-Host '==> npm install (no node_modules yet)'
    npm install --no-audit --no-fund | Out-Host
}

Write-Host '==> regenerating tsp-output/'
npx --no-install tsp compile . | Out-Host
if ($LASTEXITCODE -ne 0) {
    Write-Error "tsp compile failed (exit $LASTEXITCODE)"
    exit $LASTEXITCODE
}

Write-Host '==> diffing tsp-output/ against checked-in files'
git diff --exit-code -- tsp-output
$diffExit = $LASTEXITCODE
if ($diffExit -ne 0) {
    Write-Host ''
    Write-Error 'Drift detected: tsp-output/ does not match the committed files. Re-run `npm run build` and commit the result.'
    exit 1
}

Write-Host 'OK: generated artifacts match the .tsp sources.'
