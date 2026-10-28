param([Parameter(Mandatory)][string]$DllPath)
$ErrorActionPreference = 'Stop'
$target = Get-Item -LiteralPath $DllPath
if ($target.Extension -ne '.dll') { throw 'Expected one tool DLL.' }
$files = @(Get-ChildItem -LiteralPath $target.DirectoryName -File -Recurse -Force)
if ($files.Count -ne 1 -or $files[0].FullName -ne $target.FullName) { throw 'Unexpected files in tool output.' }
$autodesk = @('acdbmgd','acmgd','accoremgd','AecBaseMgd','AeccDbMgd','AecPropDataMgd','AeccPressurePipesMgd')
if ($autodesk -contains $target.BaseName) { throw 'Autodesk assemblies must never be packaged.' }
Write-Host 'Tool output contains exactly one DLL.'
