# Compare the .proto files generated from the TypeSpec sources against
# the canonical proto files consumed by the C++ Mumble server build
# (src/Mumble.proto, src/MumbleUDP.proto).
#
# This is a *drift report*, not a hard gate: the @typespec/protobuf
# emitter currently cannot reproduce proto2 syntax, oneof, or nested
# messages, so a clean match is not yet achievable for Mumble.proto.
# Running this script regularly tells us when the .tsp definition has
# diverged from the canonical .proto so that one of the two has to be
# updated.
#
# Usage:
#   pwsh ./scripts/diff-against-cpp-protos.ps1
#
# Always exits 0 - the report is informational. CI can grep its output
# if you want to enforce drift policy on a per-file basis.

$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $PSCommandPath
$projectRoot = Resolve-Path (Join-Path $scriptRoot '..')
# Navigate up to the repo root: typespec-poc/ -> file-server/ ->
# mumble-plugin-host/ -> 3rdparty/ -> repo root.
$repoRoot = Resolve-Path (Join-Path $projectRoot '..\..\..\..')

$pairs = @(
    @{
        Generated = Join-Path $projectRoot 'tsp-output\protobuf\MumbleProto.proto'
        Canonical = Join-Path $repoRoot 'src\Mumble.proto'
        Note      = 'proto2; oneof + nested messages; generator cannot match yet'
    },
    @{
        Generated = Join-Path $projectRoot 'tsp-output\protobuf\MumbleUDP.proto'
        Canonical = Join-Path $repoRoot 'src\MumbleUDP.proto'
        Note      = 'proto3; oneof flattened to optionals - wire compatible, source not'
    }
)

foreach ($pair in $pairs) {
    Write-Host ''
    Write-Host "=== $(Split-Path -Leaf $pair.Canonical)"
    Write-Host "    note: $($pair.Note)"
    if (-not (Test-Path $pair.Generated)) {
        Write-Warning "Generated file missing: $($pair.Generated). Run `npm run build` first."
        continue
    }
    if (-not (Test-Path $pair.Canonical)) {
        Write-Warning "Canonical file missing: $($pair.Canonical)."
        continue
    }
    # Use git diff --no-index for a colorized, side-by-side report.
    git --no-pager diff --no-index --stat -- $pair.Canonical $pair.Generated
}

Write-Host ''
Write-Host 'Drift report complete.'
