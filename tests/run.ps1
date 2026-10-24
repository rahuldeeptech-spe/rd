# Hermetic tests for patchcheck.ps1 (Windows PowerShell 5.1 and PowerShell 7+, Windows or Linux/macOS).
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Script = Join-Path $Root 'patchcheck.ps1'
$IsWin = ($env:OS -eq 'Windows_NT')
$Pwsh = (Get-Process -Id $PID).Path
$Work = Join-Path ([IO.Path]::GetTempPath()) ("patchcheck-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Work | Out-Null
$script:Pass = 0
$script:Fail = 0
$script:Counter = 0

function New-Bin([hashtable]$tools) {
    $script:Counter++
    $dir = Join-Path $Work "bin$($script:Counter)"
    New-Item -ItemType Directory -Path $dir | Out-Null
    foreach ($name in $tools.Keys) {
        if ($IsWin) {
            Set-Content -LiteralPath (Join-Path $dir "$name.cmd") -Value "@echo $($tools[$name])" -Encoding ASCII
        } else {
            $p = Join-Path $dir $name
            Set-Content -LiteralPath $p -Value "#!/bin/sh`necho `"$($tools[$name])`"`n" -NoNewline
            chmod +x $p
        }
    }
    return $dir
}

function Invoke-Patchcheck([string]$bin, [string[]]$extra) {
    $oldPath = $env:PATH
    $env:PATCHCHECK_SEARCH_DIRS = $bin
    if ($IsWin) { $env:PATH = "$bin;$env:SystemRoot\System32" } else { $env:PATH = $bin }
    try {
        # Windows PowerShell 5.1 turns native stderr into a terminating error under 'Stop'; the exit code is what we assert on.
        $ErrorActionPreference = 'Continue'
        $out = & $Pwsh -NoProfile -NonInteractive -File $Script @extra 2>&1 | ForEach-Object { "$_" } | Out-String
        return [pscustomobject]@{ Code = $LASTEXITCODE; Out = $out }
    } finally {
        $ErrorActionPreference = 'Stop'
        $env:PATH = $oldPath
        Remove-Item Env:\PATCHCHECK_SEARCH_DIRS -ErrorAction SilentlyContinue
    }
}

function Test-Case([string]$name, [hashtable]$tools, [int]$wantExit, [string]$pattern, [string[]]$extra = @()) {
    $bin = New-Bin $tools
    $r = Invoke-Patchcheck $bin $extra
    if ($r.Code -eq $wantExit -and $r.Out -match $pattern) { $script:Pass++; Write-Host "ok   $name" }
    else { $script:Fail++; Write-Host "FAIL $name (exit $($r.Code), wanted $wantExit, pattern '$pattern')"; Write-Host $r.Out }
}

$go = 'go version go1.26.10 windows/amd64'
Test-Case 'all patched'              @{ php = 'PHP 8.3.36 (cli)'; node = 'v24.22.1'; go = $go } 0 'everything found is patched'
Test-Case 'php one patch behind'     @{ php = 'PHP 8.3.35 (cli)'; node = 'v24.22.1'; go = $go } 1 'VULNERABLE\].*php 8\.3\.35.*>= 8\.3\.36'
if (-not $IsWin) { Test-Case 'label drops .exe' @{ 'php.exe' = 'PHP 8.3.35 (cli)' } 1 'host php 8\.3\.35' }
Test-Case 'boundary: exactly fixed'  @{ php = 'PHP 8.5.12 (cli)' } 0 'OK\].*php 8\.5\.12'
Test-Case 'php 8.1 backport only'    @{ php = 'PHP 8.1.30 (cli)' } 1 'VULNERABLE\].*php 8\.1\.30.*no upstream fix'
Test-Case 'php newer than data'      @{ php = 'PHP 8.6.0 (cli)' } 2 'CHECK\].*php 8\.6\.0'
Test-Case 'node 20 is EOL'           @{ node = 'v20.11.0' } 1 'VULNERABLE\].*node 20\.11\.0'
Test-Case 'node 22 one behind'       @{ node = 'v22.23.3' } 1 '>= 22\.23\.4'
Test-Case 'go 1.25 unconfirmed'      @{ go = 'go version go1.25.13 linux/amd64' } 2 'CHECK\].*go 1\.25\.13'
Test-Case 'go1.26 (no patch)=1.26.0' @{ go = 'go version go1.26 linux/amd64' } 1 'VULNERABLE\].*go 1\.26\.0'
Test-Case 'vulnerable beats check'   @{ php = 'PHP 8.3.1 (cli)'; go = 'go version go1.25.1 linux/amd64' } 1 'VULNERABLE'
Test-Case 'dotnet 8.0.31 one behind' @{ dotnet = 'Microsoft.NETCore.App 8.0.31 [C:\x]' } 1 'VULNERABLE\].*Microsoft\.NETCore\.App 8\.0\.31.*>= 8\.0\.32'
Test-Case 'dotnet 10.0.13 patched'   @{ dotnet = 'Microsoft.NETCore.App 10.0.13 [C:\x]' } 0 'OK\].*Microsoft\.NETCore\.App 10\.0\.13'
Test-Case 'dotnet ASP.NET is checked' @{ dotnet = 'Microsoft.AspNetCore.App 9.0.20 [C:\x]' } 1 'VULNERABLE\].*Microsoft\.AspNetCore\.App 9\.0\.20'
Test-Case 'dotnet preview -> check'  @{ dotnet = 'Microsoft.NETCore.App 10.0.0-rc.2.25502.107 [C:\x]' } 2 'CHECK\].*preview'
Test-Case 'dotnet 11 newer -> check' @{ dotnet = 'Microsoft.NETCore.App 11.0.0 [C:\x]' } 2 'CHECK\].*11\.0\.0'
Test-Case 'nothing installed'        @{} 0 'no PHP binary found'
Test-Case 'quiet hides OK'           @{ php = 'PHP 8.3.36 (cli)'; node = 'v20.1.0' } 1 'node 20\.1\.0' @('-Quiet')
Test-Case '--version'                @{} 0 '^patchcheck \d' @('-Version')

# ---- non-Windows only: needs sh stubs and symlinks (the Windows job covers everything above) ----
if (-not $IsWin) {
    function New-PyStub([string]$dir, [string]$name) {
        $p = Join-Path $dir $name
        Set-Content -LiteralPath $p -Value "#!/bin/sh`nfor last; do :; done`ncase `"`$last`" in`n  brotli) if [ -n `"`${STUB_BROTLI:-}`" ]; then echo `"`$STUB_BROTLI`"; exit 0; fi ;;`n  brotlicffi) if [ -n `"`${STUB_BROTLICFFI:-}`" ]; then echo `"`$STUB_BROTLICFFI`"; exit 0; fi ;;`nesac`nexit 1`n" -NoNewline
        chmod +x $p
    }
    function Test-Py([string]$name, [hashtable]$envVars, [int]$wantExit, [string]$pattern, [string[]]$extra = @(), [string]$bin = '') {
        if (-not $bin) { $bin = New-Bin @{}; New-PyStub $bin 'python3' }
        foreach ($k in $envVars.Keys) { Set-Item -Path "Env:$k" -Value $envVars[$k] }
        try { $r = Invoke-Patchcheck $bin $extra } finally { foreach ($k in $envVars.Keys) { Remove-Item "Env:$k" -ErrorAction SilentlyContinue } }
        if ($r.Code -eq $wantExit -and $r.Out -match $pattern) { $script:Pass++; Write-Host "ok   $name" }
        else { $script:Fail++; Write-Host "FAIL $name (exit $($r.Code), wanted $wantExit, pattern '$pattern')"; Write-Host $r.Out }
    }
    Test-Py 'pip brotli 1.2.1 (patched)'      @{ STUB_BROTLI = '1.2.1' }   0 'OK\].*package brotli 1\.2\.1'
    Test-Py 'pip brotli 1.2.0 (one behind)'   @{ STUB_BROTLI = '1.2.0' }   1 'VULNERABLE\].*package brotli 1\.2\.0.*>= 1\.2\.1'
    Test-Py 'pip brotli 1.1.0 (no 1.1.x fix)' @{ STUB_BROTLI = '1.1.0' }   1 'VULNERABLE\].*package brotli 1\.1\.0.*no upstream fix'
    Test-Py 'pip brotli newer than the data'  @{ STUB_BROTLI = '1.3.0' }   2 'CHECK\].*package brotli 1\.3\.0'
    Test-Py 'brotlicffi 1.2.0.0 (four parts)' @{ STUB_BROTLICFFI = '1.2.0.0' } 1 'VULNERABLE\].*package brotlicffi 1\.2\.0\.0.*>= 1\.2\.1\.0'
    Test-Py 'brotlicffi 1.2.1.0 (patched)'    @{ STUB_BROTLICFFI = '1.2.1.0' } 0 'OK\].*package brotlicffi 1\.2\.1\.0'
    Test-Py 'python without the packages'     @{}                          0 'everything found is patched'
    $none = New-Bin @{}
    Test-Py 'no python at all'                @{}                          0 'no python found' @() $none
    $venv = New-Bin @{}; New-PyStub $venv 'python'
    Test-Py '-Python adds a virtualenv python' @{ STUB_BROTLI = '1.2.1' }   0 'package brotli 1\.2\.1' @('-Python', (Join-Path $venv 'python'))
    Test-Py '-Python nonexistent is reported' @{}                          0 'not an executable file' @('-Python', '/nope/python')

    # the same php reachable through a symlinked directory must be reported once (the /bin -> /usr/bin case)
    $real = New-Bin @{ php = 'PHP 8.3.36 (cli)' }
    New-Item -ItemType SymbolicLink -Path (Join-Path $real 'readlink') -Target (Get-Command readlink -CommandType Application | Select-Object -First 1).Source | Out-Null   # real systems have it on PATH
    $link = Join-Path $Work 'linkdir'; New-Item -ItemType SymbolicLink -Path $link -Target $real | Out-Null
    $oldPath = $env:PATH; $env:PATH = "$real" + [IO.Path]::PathSeparator + "$link"; $env:PATCHCHECK_SEARCH_DIRS = $real
    try { $dup = & $Pwsh -NoProfile -NonInteractive -File $Script -Json 2>&1 | Out-String } finally { $env:PATH = $oldPath; Remove-Item Env:\PATCHCHECK_SEARCH_DIRS -ErrorAction SilentlyContinue }
    $count = ([regex]::Matches($dup, '"label":"host php[^"]*"')).Count
    if ($count -eq 1) { $script:Pass++; Write-Host 'ok   a symlinked directory does not report php twice' } else { $script:Fail++; Write-Host "FAIL a symlinked directory reported php $count times"; Write-Host $dup }

    # a REAL virtualenv (no stub, no network): its python is a link to the base interpreter and must still be checked
    $basePy = Get-Command python3 -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($basePy) {
        $rv = Join-Path $Work 'realvenv'
        & $basePy.Source -m venv --without-pip $rv 2>$null
        if ($LASTEXITCODE -eq 0) {
            $site = & (Join-Path $rv 'bin/python') -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])'
            $dist = Join-Path $site 'Brotli.dist-info'; New-Item -ItemType Directory -Path $dist -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dist 'METADATA') -Value "Metadata-Version: 2.1`nName: Brotli`nVersion: 1.2.0`n" -NoNewline
            $pybin2 = New-Bin @{}; New-Item -ItemType SymbolicLink -Path (Join-Path $pybin2 'python3') -Target $basePy.Source | Out-Null
            New-Item -ItemType SymbolicLink -Path (Join-Path $pybin2 'readlink') -Target (Get-Command readlink -CommandType Application | Select-Object -First 1).Source | Out-Null   # real systems have it on PATH
            Test-Py 'real venv with Brotli 1.2.0 is checked and flagged' @{} 1 'VULNERABLE\].*realvenv/bin/python package brotli 1\.2\.0' @('-Python', (Join-Path $rv 'bin/python')) $pybin2
        }
    }

    # a hostile directory must never get code executed: the REAL python, run from a folder holding a fake importlib
    $realPy = Get-Command python3 -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($realPy) {
        $evil = Join-Path $Work 'evil'; New-Item -ItemType Directory -Path (Join-Path $evil 'importlib') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $evil 'importlib/__init__.py') -Value "import os`nopen(os.environ['EVIL_MARKER'], 'w').close()`n"
        $marker = Join-Path $Work 'evil.marker'; Remove-Item $marker -ErrorAction SilentlyContinue
        $pybin = New-Bin @{}; New-Item -ItemType SymbolicLink -Path (Join-Path $pybin 'python3') -Target $realPy.Source | Out-Null
        $env:EVIL_MARKER = $marker; Push-Location $evil
        try { [void](Invoke-Patchcheck $pybin @()) } finally { Pop-Location; Remove-Item Env:\EVIL_MARKER -ErrorAction SilentlyContinue }
        if (-not (Test-Path $marker)) { $script:Pass++; Write-Host 'ok   hostile cwd: a fake importlib in the current directory is never imported' }
        else { $script:Fail++; Write-Host 'FAIL hostile cwd: the fake importlib was executed' }
    }
}

# JSON must parse and carry the right numbers
$bin = New-Bin @{ php = 'PHP 8.3.1 (cli)'; node = 'v22.23.4' }
$r = Invoke-Patchcheck $bin @('-Json')
try {
    $d = $r.Out | ConvertFrom-Json
    if ($d.exit_code -eq 1 -and $d.summary.vulnerable -eq 1 -and $r.Code -eq 1) { $script:Pass++; Write-Host 'ok   json valid and correct' }
    else { throw 'wrong values' }
} catch { $script:Fail++; Write-Host "FAIL json valid and correct: $_"; Write-Host $r.Out }

# usage error: missing data file
$r = Invoke-Patchcheck (New-Bin @{}) @('-DataPath', (Join-Path $Work 'nope.tsv'))
if ($r.Code -eq 64 -and $r.Out -match 'not readable') { $script:Pass++; Write-Host 'ok   missing data file' } else { $script:Fail++; Write-Host "FAIL missing data file (exit $($r.Code))"; Write-Host $r.Out }

Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
Write-Host ''
Write-Host "passed: $($script:Pass)  failed: $($script:Fail)"
if ($script:Fail -gt 0) { exit 1 }
exit 0
