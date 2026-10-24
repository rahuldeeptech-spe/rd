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
        $out = & $Pwsh -NoProfile -NonInteractive -File $Script @extra 2>&1 | Out-String
        return [pscustomobject]@{ Code = $LASTEXITCODE; Out = $out }
    } finally {
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
Test-Case 'nothing installed'        @{} 0 'no PHP binary found'
Test-Case 'quiet hides OK'           @{ php = 'PHP 8.3.36 (cli)'; node = 'v20.1.0' } 1 'node 20\.1\.0' @('-Quiet')
Test-Case '--version'                @{} 0 '^patchcheck \d' @('-Version')

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
