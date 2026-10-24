# check-php2shell.ps1 - read-only checker for PHP2Shell (CVE-2026-109618 / CVE-2026-109619),
# the Oct 21 2026 Node.js security release, and Go CVE-2026-111943.
# Windows PowerShell 5.1+ or PowerShell 7+. Changes nothing on the system.
#
# Usage: powershell -ExecutionPolicy Bypass -File .\check-php2shell.ps1
# Exit code: 0 = everything found is patched, 1 = vulnerable/EOL/unknown found.

$PhpFixed  = @{ '8.5' = '8.5.12'; '8.4' = '8.4.27'; '8.3' = '8.3.36'; '8.2' = '8.2.35' }
$NodeFixed = @{ '26' = '26.12.1'; '24' = '24.22.1'; '22' = '22.23.4' }
$GoFixed   = @{ '1.26' = '1.26.10'; '1.27' = '1.27.3' }   # no fix confirmed for 1.25 and older

$script:Rc = 0

function Get-Branch([string]$v, [int]$parts) { ($v.Split('.')[0..($parts - 1)]) -join '.' }

function Test-Fixed([string]$label, [string]$v, $fixedMap, [int]$parts, [string]$eolHint) {
    $branch = Get-Branch $v $parts
    if ($fixedMap.ContainsKey($branch)) {
        $fixed = $fixedMap[$branch]
        if ([version]$v -ge [version]$fixed) {
            Write-Host "[OK]             $label $v (>= $fixed)"
        } else {
            Write-Host "[VULNERABLE]     $label $v - update to >= $fixed"
            $script:Rc = 1
        }
    } else {
        Write-Host "[CHECK/EOL]      $label $v - no confirmed upstream fix for this branch. $eolHint"
        $script:Rc = 1
    }
}

Write-Host '== Host =='

$php = Get-Command php -ErrorAction SilentlyContinue
if ($php) {
    $v = (& php -r 'echo PHP_VERSION;') -replace '[^0-9.].*', ''
    Test-Fixed 'host PHP' $v $PhpFixed 2 'Upgrade to a supported branch. Windows builds from windows.php.net have no distro backports.'
} else {
    Write-Host '[--]             php not found (IIS/FastCGI may use a different install: check php-cgi.exe)'
}

$node = Get-Command node -ErrorAction SilentlyContinue
if ($node) {
    $v = (& node -v) -replace '^v', ''
    Test-Fixed 'host Node' $v $NodeFixed 1 'End-of-life branch; move to 22, 24 or 26.'
} else {
    Write-Host '[--]             node not found'
}

$go = Get-Command go -ErrorAction SilentlyContinue
if ($go) {
    if ((& go version) -match 'go(\d+\.\d+(\.\d+)?)') {
        Test-Fixed 'host Go' $Matches[1] $GoFixed 2 'Move to Go 1.26.10+ or 1.27.3+ and rebuild binaries.'
    }
}

Write-Host ''
if ($script:Rc -eq 0) {
    Write-Host 'Result: everything checked is patched.'
} else {
    Write-Host 'Result: action needed. After upgrading, restart IIS / php-cgi / Node processes.'
}
exit $script:Rc
