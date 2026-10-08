# Builds blrecover (WPF app + CLI + engine) with the .NET 10 SDK.
#
#   .\build.ps1                     build everything in Release
#   .\build.ps1 -Run selftest       build, then run the engine self-test suite
#   .\build.ps1 -RunUiSmokeTest     build, then load the real WPF window and walk it
#   .\build.ps1 -SelfContained      publish a single standalone GUI exe (no .NET needed)
#   .\build.ps1 -Clean              remove build output
#
# The program is READ-ONLY unless you explicitly restore a partition entry.

param(
    [string]$Run = '',
    [switch]$RunUiSmokeTest,
    [switch]$SelfContained,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$dotnet = 'C:\Program Files\dotnet\dotnet.exe'
if (-not (Test-Path $dotnet)) { $dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source }
if (-not $dotnet) { throw 'dotnet not found. Install the .NET 10 SDK, or add it to PATH.' }

$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'

# One shared output root keeps every artefact in one place and means a stale process can
# never lock a project's default bin\ folder.
$out = Join-Path $root 'build\bin'
$baseOut = "$out\"

if ($Clean) {
    # build.ps1 redirects BaseOutputPath to build\bin, but earlier layouts (and plain
    # `dotnet build` runs) left output in the default per-project folders. Remove all of them
    # so a clean really is clean, and so no stale assembly from the old source layout survives.
    $stale = @(
        'build', 'dist', 'bin', 'obj', '.altbuild',
        'src\BlRecover.Core\bin', 'src\BlRecover.Core\obj',
        'src\BlRecover.Cli\bin', 'src\BlRecover.Cli\obj',
        'src\BlRecover.App\bin', 'src\BlRecover.App\obj'
    )
    foreach ($rel in $stale) {
        $p = Join-Path $root $rel
        if (Test-Path $p) {
            # Resolve and re-check: $root is the repo root, so anything outside it
            # means a bad $rel above and must not be deleted.
            $resolved = (Resolve-Path -LiteralPath $p).Path
            if (-not $resolved.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
                throw "refusing to delete outside the repo root: $resolved"
            }
            Remove-Item -LiteralPath $resolved -Recurse -Force
            Write-Host "  removed $rel"
        }
    }
    Write-Host 'build output removed'
    exit 0
}

Write-Host "dotnet SDK : $(& $dotnet --version)"
Write-Host "solution   : $root\BlRecover.sln"
Write-Host "output     : $out"
Write-Host ''

if ($SelfContained) {
    $dist = Join-Path $root 'dist'
    & $dotnet publish (Join-Path $root 'src\BlRecover.App\BlRecover.App.csproj') -c Release -r win-x64 `
        --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:DebugType=none -p:EnableCompressionInSingleFile=true `
        "-p:BaseOutputPath=$baseOut" -o $dist
    if ($LASTEXITCODE -ne 0) { throw "publish failed ($LASTEXITCODE)" }
    Write-Host ''
    Write-Host "Standalone GUI (no .NET runtime needed on the target machine):"
    Write-Host "  $(Join-Path $dist 'BlRecover.App.exe')"
    exit 0
}

& $dotnet build (Join-Path $root 'BlRecover.sln') -c Release --nologo "-p:BaseOutputPath=$baseOut"
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }

$bin   = Join-Path $out 'Release\net10.0-windows'
$cli   = Join-Path $bin 'blrecover.exe'
$app   = Join-Path $bin 'BlRecover.App.exe'

Write-Host ''
Write-Host 'Build OK.'
Write-Host "  GUI            $app"
Write-Host "  CLI            $cli"
Write-Host ''

if ($Run) { & $cli $Run; exit $LASTEXITCODE }

if ($RunUiSmokeTest) {
    & $app --ui-smoke-test | Out-Null
    Get-Content (Join-Path $env:TEMP 'blrecover-ui-smoke.log') -ErrorAction SilentlyContinue
    exit 0
}

Write-Host 'Try:'
Write-Host ("  {0} selftest" -f $cli)
Write-Host ("  {0} list" -f $cli)
Write-Host ("  {0} analyze --disk 0        (needs an elevated prompt)" -f $cli)
Write-Host ("  {0}                          (GUI)" -f $app)
Write-Host ("  {0} --ui-demo                (GUI, populated from a synthetic image)" -f $app)
Write-Host ''
