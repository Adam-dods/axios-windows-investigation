@echo off
setlocal
color 07 >nul
set "AXIOS_INSTALLER_PATH=%~f0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$source=[IO.File]::ReadAllText($env:AXIOS_INSTALLER_PATH); $start=$source.LastIndexOf(':AXIOS_POWERSHELL'); $end=$source.LastIndexOf(':AXIOS_ARCHIVE_BASE64'); if($start -lt 0 -or $end -le $start){throw 'The AXIOS package is incomplete.'}; Invoke-Expression $source.Substring($start+':AXIOS_POWERSHELL'.Length,$end-$start-':AXIOS_POWERSHELL'.Length)"
set "AXIOS_EXIT_CODE=%ERRORLEVEL%"
exit /b %AXIOS_EXIT_CODE%
:AXIOS_POWERSHELL
$ErrorActionPreference = 'Stop'
$downloadFolder = Split-Path -Parent $env:AXIOS_INSTALLER_PATH
$source = [IO.File]::ReadAllText($env:AXIOS_INSTALLER_PATH)
$marker = ':AXIOS_ARCHIVE_BASE64'
$offset = $source.LastIndexOf($marker)
if ($offset -lt 0) { throw 'The AXIOS package has no archive.' }
$payload = $source.Substring($offset + $marker.Length).Replace('::', '')
$archiveBytes = [Convert]::FromBase64String($payload)
$stream = New-Object IO.MemoryStream(,$archiveBytes)
$destination = Join-Path $downloadFolder 'AXIOS'
$base = [IO.Path]::GetFullPath($destination).TrimEnd('\') + '\'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Read)
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
    $stream.Dispose()
}
$package = Join-Path $destination 'axios-windows-investigation'
if (-not (Test-Path -LiteralPath (Join-Path $package 'axios.cmd') -PathType Leaf)) {
    throw 'The ZIP did not contain the AXIOS launcher.'
}
