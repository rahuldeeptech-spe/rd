<#
.SYNOPSIS
  Read-only checker for the Oct 2026 PHP2Shell / Node.js / Go advisories (Windows PowerShell 5.1+ and PowerShell 7+).
.DESCRIPTION
  Never modifies the system and makes no network calls. Rules come from advisories.tsv next to this script.
  Exit codes: 0 all patched | 1 vulnerable | 2 manual check needed | 64 usage error.
  -Python PATH [PATH...] also checks the Brotli packages (Node2Shell, CVE-2026-111497) of those interpreters, e.g. a virtualenv's python.
  Not detected on Windows: running processes that still hold old code. Restart IIS app pools,
  services and Node processes after upgrading.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\patchcheck.ps1 -Json
#>
[CmdletBinding()]
param(
    [switch]$Json,
    [switch]$Quiet,
    [string]$DataPath,
    [switch]$Version,
    [string[]]$Python = @()
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ToolVersion = '1.4.0'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($Version) { Write-Output "patchcheck $ToolVersion"; exit 0 }

if (-not $DataPath) {
    if ($env:PATCHCHECK_DATA) { $DataPath = $env:PATCHCHECK_DATA }
    else { $DataPath = Join-Path $ScriptDir 'advisories.tsv' }
}
if (-not (Test-Path -LiteralPath $DataPath -PathType Leaf)) {
    [Console]::Error.WriteLine("patchcheck: advisories file not readable: $DataPath")
    exit 64
}

# ---- load rules -------------------------------------------------------------------------------
$Rules = @()
$DataUpdated = 'unknown'
foreach ($raw in Get-Content -LiteralPath $DataPath) {
    $line = $raw.TrimEnd("`r")
    if ($line -match '^#@ updated (.+)$') { $DataUpdated = $Matches[1].Trim(); continue }
    if ($line -eq '' -or $line.StartsWith('#')) { continue }
    $f = $line.Split("`t")
    if ($f.Count -lt 7) { continue }
    $fixed = ''
    if ($f[3] -ne '-') { $fixed = $f[3] }
    $Rules += [pscustomobject]@{ Runtime = $f[0]; Branch = $f[1]; Status = $f[2]; Fixed = $fixed; Id = $f[4]; Note = $f[6] }
}

function ConvertTo-Ver([string]$s) {
    if ($s -notmatch '\.') { $s = "$s.0" }
    return [version]$s
}

function Get-Branch([string]$runtime, [string]$v) {
    $parts = $v.Split('.')
    if ($runtime -eq 'node') { return $parts[0] }
    return ($parts[0] + '.' + $parts[1])
}

function Test-ValidVersion([string]$v) { return ($v -match '^\d+(\.\d+){1,3}$') }

function Get-Rule([string]$runtime, [string]$branch) {
    $rs = @($Rules | Where-Object { $_.Runtime -eq $runtime })
    $exact = $rs | Where-Object { $_.Branch -eq $branch } | Select-Object -First 1
    if ($exact) { return $exact }
    $max = $null
    foreach ($k in ($rs | Where-Object { $_.Branch -ne 'older' -and $_.Branch -ne 'newer' })) {
        $kv = ConvertTo-Ver $k.Branch
        if ($null -eq $max -or $kv -gt $max) { $max = $kv }
    }
    $wanted = 'older'
    if ($null -ne $max -and (ConvertTo-Ver $branch) -gt $max) { $wanted = 'newer' }
    return ($rs | Where-Object { $_.Branch -eq $wanted } | Select-Object -First 1)
}

$Results = New-Object System.Collections.ArrayList
$Seen = @{}

function Add-Result([string]$label, [string]$runtime, [string]$version, [string]$state, [string]$detail, [string]$id) {
    [void]$Results.Add([pscustomobject]@{ label = $label; runtime = $runtime; version = $version; state = $state; detail = $detail; advisory = $id })
}

function Test-Version([string]$label, [string]$runtime, [string]$v) {
    $rule = Get-Rule $runtime (Get-Branch $runtime $v)
    if ($null -eq $rule) {
        Add-Result $label $runtime $v 'CHECK' "no rule for $runtime in advisories file" ''
        return
    }
    switch ($rule.Status) {
        'fixed' {
            if ((ConvertTo-Ver $v) -ge (ConvertTo-Ver $rule.Fixed)) { Add-Result $label $runtime $v 'OK' ">= $($rule.Fixed)" $rule.Id }
            else { Add-Result $label $runtime $v 'VULNERABLE' "update to >= $($rule.Fixed)" $rule.Id }
        }
        'eol' { Add-Result $label $runtime $v 'VULNERABLE' "no upstream fix for this branch. $($rule.Note)" $rule.Id }
        default { Add-Result $label $runtime $v 'CHECK' "fix not confirmed. $($rule.Note)" $rule.Id }
    }
}

# The same file is often reachable under several names (/bin is a link to /usr/bin on most Linux systems), and
# Resolve-Path does not follow links. readlink -f does, so use it where it exists.
function Get-RealPath([string]$p) {
    if ($env:OS -ne 'Windows_NT') {
        $rl = Get-Command readlink -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($rl) {
            $r = & $rl.Source -f $p 2>$null
            if ($LASTEXITCODE -eq 0 -and $r) { return "$r" }
        }
    }
    try { return (Resolve-Path -LiteralPath $p).ProviderPath } catch { return $p }
}

# Like Get-RealPath, but a link AS the file is kept: a virtualenv's python is a link to the base interpreter and must not be
# mistaken for it (they see different packages). Links in the directory part are still resolved.
function Get-CanonPath([string]$p) {
    $dir = Split-Path -Parent $p
    if (-not $dir) { return $p }
    return (Join-Path (Get-RealPath $dir) (Split-Path -Leaf $p))
}

function Test-FirstSeen([string]$key) {
    $k = $key.ToLowerInvariant()
    if ($Seen.ContainsKey($k)) { return $false }
    $Seen[$k] = $true
    return $true
}

function Get-ToolOutput([string]$path, [string[]]$toolArgs) {
    try { return (& $path @toolArgs 2>$null | Select-Object -First 1) } catch { return $null }
}

function Get-ToolLines([string]$path, [string[]]$toolArgs) {
    try { return @(& $path @toolArgs 2>$null) } catch { return @() }
}

# ---- PHP --------------------------------------------------------------------------------------
function Get-PhpCandidates {
    $paths = New-Object System.Collections.ArrayList
    foreach ($n in 'php', 'php-cgi', 'php-fpm') {
        foreach ($c in @(Get-Command $n -All -CommandType Application -ErrorAction SilentlyContinue)) { [void]$paths.Add($c.Source) }
    }
    $dirs = @()
    if ($env:PATCHCHECK_SEARCH_DIRS) { $dirs = $env:PATCHCHECK_SEARCH_DIRS.Split([IO.Path]::PathSeparator) }
    else {
        $dirs = @('C:\php', 'C:\Program Files\PHP*', 'C:\tools\php*', 'C:\xampp\php', 'C:\laragon\bin\php\*', 'C:\wamp64\bin\php\*',
                  '/usr/sbin', '/usr/bin', '/usr/local/bin', '/usr/local/sbin')
    }
    foreach ($d in $dirs) {
        foreach ($dir in @(Get-Item -Path $d -ErrorAction SilentlyContinue)) {
            foreach ($n in 'php', 'php.exe', 'php-cgi', 'php-cgi.exe', 'php-fpm') {
                $p = Join-Path $dir.FullName $n
                if (Test-Path -LiteralPath $p -PathType Leaf) { [void]$paths.Add($p) }
            }
        }
    }
    return $paths
}

$foundPhp = $false
foreach ($p in (Get-PhpCandidates)) {
    $out = Get-ToolOutput $p @('-v')
    if ($out -and ($out -match '^PHP (\d+\.\d+\.\d+)')) {
        $v = $Matches[1]
        $real = $p
        $real = Get-RealPath $p
        if (Test-FirstSeen "php:${real}:$v") {
            $foundPhp = $true
            # strip only Windows executable extensions: "php8.3" must stay "php8.3"
            $leaf = (Split-Path -Leaf $p) -replace '\.(exe|cmd|bat)$', ''
            Test-Version "host $leaf" 'php' $v
        }
    }
}
if (-not $foundPhp) { Add-Result 'host php' 'php' '-' 'NONE' 'no PHP binary found (web PHP may live elsewhere: check php-cgi / IIS FastCGI settings)' '' }

# ---- Node -------------------------------------------------------------------------------------
$foundNode = $false
foreach ($n in 'node', 'nodejs') {
    foreach ($c in @(Get-Command $n -All -CommandType Application -ErrorAction SilentlyContinue)) {
        $out = Get-ToolOutput $c.Source @('-v')
        if ($out -and ($out -match '^v?(\d+\.\d+\.\d+)')) {
            $v = $Matches[1]
            if (Test-FirstSeen "node:$(Get-RealPath $c.Source):$v") { $foundNode = $true; Test-Version "host $n" 'node' $v }
        }
    }
}
if (-not $foundNode) { Add-Result 'host node' 'node' '-' 'NONE' 'node not found' '' }

# ---- Go ---------------------------------------------------------------------------------------
$goCmd = Get-Command go -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($goCmd) {
    $out = Get-ToolOutput $goCmd.Source @('version')
    if ($out -and ($out -match ' go(\d+\.\d+(\.\d+)?)')) {
        $v = $Matches[1]
        if (($v.Split('.')).Count -eq 2) { $v = "$v.0" }
        Test-Version 'host go' 'go' $v
    } else { Add-Result 'host go' 'go' '-' 'NONE' 'could not read Go version' '' }
} else { Add-Result 'host go' 'go' '-' 'NONE' 'go not found' '' }

# ---- .NET -------------------------------------------------------------------------------------
$dotnetCmd = Get-Command dotnet -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($dotnetCmd) {
    $foundDotnet = $false
    foreach ($line in @(Get-ToolLines $dotnetCmd.Source @('--list-runtimes'))) {
        if ("$line" -notmatch '^(Microsoft\.NETCore\.App|Microsoft\.AspNetCore\.App)\s+(\S+)') { continue }
        $fw = $Matches[1]; $v = $Matches[2]
        $foundDotnet = $true
        if (-not (Test-ValidVersion $v)) {
            Add-Result "host $fw" 'dotnet' $v 'CHECK' 'version not understood (preview build?). Verify against the .NET release notes.' ''
        } elseif (Test-FirstSeen "dotnet:${fw}:$v") {
            Test-Version "host $fw" 'dotnet' $v
        }
    }
    if (-not $foundDotnet) { Add-Result 'host dotnet' 'dotnet' '-' 'NONE' 'dotnet found but no shared runtime installed (SDK only?)' '' }
} else { Add-Result 'host dotnet' 'dotnet' '-' 'NONE' 'dotnet not found' '' }

# ---- Python Brotli packages (Node2Shell, CVE-2026-111497) -------------------------------------
# Python is run from the filesystem root with -E so that a hostile file in the current directory (an "importlib" folder)
# or in PYTHONPATH can never be imported.
function Get-PythonPackageVersion([string]$python, [string]$package) {
    $root = '/'
    if ($env:OS -eq 'Windows_NT') { $root = $env:SystemRoot }
    Push-Location -LiteralPath $root
    try {
        $out = & $python -E -c 'import sys; from importlib.metadata import version; print(version(sys.argv[1]))' $package 2>$null | Select-Object -First 1
    } catch { return $null } finally { Pop-Location }
    if ($out -and ("$out" -match '^\d+(\.\d+){1,3}$')) { return "$out" }
    return $null
}

$pyCandidates = New-Object System.Collections.ArrayList
foreach ($n in 'python3', 'python') {
    foreach ($c in @(Get-Command $n -All -CommandType Application -ErrorAction SilentlyContinue)) { [void]$pyCandidates.Add($c.Source) }
}
foreach ($extra in $Python) {
    if (Test-Path -LiteralPath $extra -PathType Leaf) { [void]$pyCandidates.Add((Get-CanonPath (Resolve-Path -LiteralPath $extra).ProviderPath)) }
    else { Add-Result "python $extra" 'python' '-' 'NONE' 'not an executable file' '' }
}
$foundPython = $false
foreach ($py in $pyCandidates) {
    if (-not (Test-FirstSeen "python:$(Get-CanonPath $py)")) { continue }
    $foundPython = $true
    foreach ($pkg in 'brotli', 'brotlicffi') {
        $v = Get-PythonPackageVersion $py $pkg
        if ($v) { Test-Version "python $py package $pkg" $pkg $v }
    }
}
if (-not $foundPython) { Add-Result 'host python' 'python' '-' 'NONE' 'no python found (Python Brotli packages not checked)' '' }

# ---- summary ----------------------------------------------------------------------------------
$nOk = @($Results | Where-Object { $_.state -eq 'OK' }).Count
$nBad = @($Results | Where-Object { $_.state -eq 'VULNERABLE' -or $_.state -eq 'RESTART' }).Count
$nCheck = @($Results | Where-Object { $_.state -eq 'CHECK' }).Count
$exitCode = 0
if ($nCheck -gt 0) { $exitCode = 2 }
if ($nBad -gt 0) { $exitCode = 1 }

if ($Json) {
    $doc = [ordered]@{
        tool = 'patchcheck'; version = $ToolVersion; data_updated = $DataUpdated
        results = @($Results)
        summary = [ordered]@{ ok = $nOk; vulnerable = $nBad; check = $nCheck }
        exit_code = $exitCode
    }
    Write-Output ($doc | ConvertTo-Json -Depth 5 -Compress)
    exit $exitCode
}

Write-Host "patchcheck $ToolVersion (advisory data: $DataUpdated)"
foreach ($r in $Results) {
    if ($Quiet -and ($r.state -eq 'OK' -or $r.state -eq 'NONE')) { continue }
    $color = 'Yellow'
    if ($r.state -eq 'OK') { $color = 'Green' }
    if ($r.state -eq 'VULNERABLE' -or $r.state -eq 'RESTART') { $color = 'Red' }
    $idtxt = ''
    if ($r.advisory) { $idtxt = " [$($r.advisory)]" }
    Write-Host ('{0,-13}' -f "[$($r.state)]") -ForegroundColor $color -NoNewline
    Write-Host " $($r.label) $($r.version) - $($r.detail)$idtxt"
}
Write-Host ''
switch ($exitCode) {
    0 { Write-Host 'Result: everything found is patched.' }
    1 { Write-Host 'Result: ACTION NEEDED. Upgrade, then restart IIS app pools / services / Node processes so the new code loads.' }
    2 { Write-Host 'Result: nothing known-vulnerable, but some versions could not be confirmed. See [CHECK] lines.' }
}
exit $exitCode
