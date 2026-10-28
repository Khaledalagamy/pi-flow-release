param([Parameter(Mandatory)][string]$Project, [string]$Tests = '')
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$root = [IO.Path]::GetFullPath($env:GITHUB_WORKSPACE)
$shared = $PSScriptRoot
function RepoFile([string]$relative) {
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)' -or $relative.StartsWith('-')) { throw 'Invalid project path.' }
    $path = [IO.Path]::GetFullPath((Join-Path $root $relative))
    if (-not $path.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Missing project file.' }
    return $path
}
# These checks run before any MSBuild target from the caller is evaluated.
if ($env:GITHUB_REF -notmatch '^refs/tags/v(\d+\.\d+\.\d+)(-alpha\.\d+)?$') { throw 'Expected a release tag.' }
$baseVersion = $Matches[1]
$version = $env:GITHUB_REF.Substring('refs/tags/v'.Length)
$stable = -not $version.Contains('-')
$manifestPath = RepoFile 'piflow-tool.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.version -ne $baseVersion) { throw 'Manifest version must match the tag base.' }
if ($stable) {
    $branch = $env:PIFLOW_DEFAULT_BRANCH
    if ([string]::IsNullOrWhiteSpace($branch)) { throw 'Missing default branch.' }
    git -C $root merge-base --is-ancestor $env:GITHUB_SHA "origin/$branch"
}
$projectPath = RepoFile $Project
if ([IO.Path]::GetExtension($projectPath) -ne '.csproj') { throw 'Expected csproj.' }
$projects = @($projectPath)
if ($Tests) { $projects += RepoFile $Tests }
foreach ($path in $projects) {
    if (-not (Test-Path -LiteralPath (Join-Path (Split-Path $path) 'packages.lock.json'))) { throw 'Commit packages.lock.json for every project.' }
}
$nuget = Join-Path $env:RUNNER_TEMP 'piflow-nuget.config'
$feed = ''
foreach ($path in $projects) {
    if ((Get-Content -LiteralPath $path -Raw) -match '<PackageReference\s+[^>]*(Include|Update)="PiFlow\.') { $feed = '<add key="piflow" value="https://nuget.pkg.github.com/Khaledalagamy/index.json" />' }
}
Set-Content -LiteralPath $nuget -Value "<configuration><packageSources><clear /><add key=`"nuget.org`" value=`"https://api.nuget.org/v3/index.json`" />$feed</packageSources></configuration>"
if ($feed) { $env:NuGetPackageSourceCredentials_piflow = "Username=$($env:GITHUB_ACTOR);Password=$($env:PIFLOW_PACKAGES_TOKEN);ValidAuthenticationTypes=Basic" }
foreach ($path in $projects) {
    dotnet restore $path --locked-mode --configfile $nuget -p:UseApiPackages=true
    # Deterministic=false removes the reproducible debug-directory marker as required by the backend contract.
    dotnet build $path -c Release --no-restore -p:UseApiPackages=true "-p:Version=$version" -p:DebugType=none -p:DebugSymbols=false -p:Deterministic=false
}
if ($Tests) { dotnet run --project $projects[1] -c Release --no-build -p:UseApiPackages=true "-p:Version=$version" }
$target = dotnet msbuild $projectPath -getProperty:TargetPath -p:Configuration=Release -p:UseApiPackages=true "-p:Version=$version"
if ($target -is [array]) { throw 'Ambiguous tool output path.' }
& (Join-Path $shared 'leak-check/check.ps1') -DllPath $target.Trim()
dotnet restore (Join-Path $shared 'contract-check/CheckContract.csproj') --locked-mode
dotnet run --project (Join-Path $shared 'contract-check/CheckContract.csproj') -c Release --no-restore -- $target.Trim() --manifest $manifestPath --expect-version $version
dotnet restore (Join-Path $shared 'seal/Seal.csproj') --locked-mode
dotnet build (Join-Path $shared 'seal/Seal.csproj') -c Release --no-restore
$out = Join-Path $env:RUNNER_TEMP 'release.pfs'
$hash = dotnet run --project (Join-Path $shared 'seal/Seal.csproj') -c Release --no-build -- $manifestPath $target.Trim() (Join-Path $shared '../keys/tool-intake.pem') (Join-Path $shared '../keys/tool-intake.kid') $version $out
if ($hash -is [array] -or $hash -notmatch '^[a-f0-9]{64}$') { throw 'Invalid sealed output.' }
Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "sealed_sha256=$hash"
