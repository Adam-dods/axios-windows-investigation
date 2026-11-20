@echo off
setlocal
color 07 >nul
set "AXIOS_INSTALLER_PATH=%~f0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$source=[IO.File]::ReadAllText($env:AXIOS_INSTALLER_PATH); $marker=':AXIOS_POWERSHELL'; Invoke-Expression $source.Substring($source.LastIndexOf($marker)+$marker.Length)"
set "AXIOS_EXIT_CODE=%ERRORLEVEL%"
if not "%AXIOS_UNZIP_TEST_MODE%"=="1" pause
exit /b %AXIOS_EXIT_CODE%
:AXIOS_POWERSHELL
$ErrorActionPreference = 'Stop'
$downloadFolder = Split-Path -Parent $env:AXIOS_INSTALLER_PATH
$zip = Join-Path $downloadFolder 'axios-windows-investigation.zip'
if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) {
    throw 'Put axios-unzip.cmd and axios-windows-investigation.zip in the same folder.'
}
$destination = Join-Path $downloadFolder 'AXIOS'
$base = [IO.Path]::GetFullPath($destination).TrimEnd('\') + '\'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($zip)
try {
    $total = $archive.Entries.Count
    if ($total -eq 0) { throw 'The AXIOS ZIP is empty.' }
    $done = 0
    foreach ($entry in $archive.Entries) {
        $target = [IO.Path]::GetFullPath((Join-Path $base $entry.FullName))
        if (-not $target.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The ZIP contains a path outside the AXIOS folder.'
        }
        if ($entry.Name) {
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
        }
        else {
            [void][IO.Directory]::CreateDirectory($target)
        }
        $done++
        $percent = [int][Math]::Floor(($done * 100.0) / $total)
        $filled = [int][Math]::Floor(($percent * 24.0) / 100)
        $line = [string]::Format("`rAXIOS unzip {0,3}% [{1}{2}]", $percent, ('#' * $filled), ('-' * (24 - $filled)))
        [Console]::Write($line)
    }
    [Console]::WriteLine()
}
finally {
    $archive.Dispose()
}
$package = Join-Path $destination 'axios-windows-investigation'
if (-not (Test-Path -LiteralPath (Join-Path $package 'axios.cmd') -PathType Leaf)) {
    throw 'The ZIP did not contain the AXIOS launcher.'
}
Write-Host ('AXIOS folder: {0}' -f $package)
if ($env:AXIOS_UNZIP_TEST_MODE -ne '1') {
    Start-Process explorer.exe -ArgumentList ('"{0}"' -f $package)
}
