param([string]$BuildRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$git = (Get-Command git.exe -ErrorAction Stop).Source
$policy = Join-Path $PSScriptRoot '.gitattributes'
if (!(Test-Path -LiteralPath $policy -PathType Leaf)) {
    throw 'Missing tools shell-export policy'
}
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$out = Join-Path $BuildRoot ('shell-exports-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $out -Force
$shells = @(Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -File -Filter '*.sh')
$attributes = @(Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -File -Filter '.gitattributes')
if (!$shells.Count) { throw 'Empty shell-export inventory' }
$inputs = @($PSCommandPath, $git) + @($shells.FullName) + @($attributes.FullName)
$before = @($inputs | Sort-Object -Unique | ForEach-Object { Get-FileHash -LiteralPath $_ })
$before | Select-Object Path,Hash | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $out 'inputs-before.json') -Encoding ASCII
$checks = New-Object System.Collections.Generic.List[object]
function Check([string]$Name, [bool]$Passed) {
    $checks.Add([pscustomobject]@{Name=$Name;Passed=$Passed})
    if (!$Passed) { throw "Shell-export regression: $Name" }
}
function Git([string]$Root, [string]$Mode, [string[]]$Arguments) {
    $old = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $git -c "core.autocrlf=$Mode" -c core.safecrlf=false `
            -c core.attributesFile= -C $Root @Arguments 2>&1)
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $old }
    [ordered]@{Root=$Root;Mode=$Mode;Arguments=$Arguments;ExitCode=$code;
        Output=($lines | ForEach-Object {"$_"})} | ConvertTo-Json -Depth 4 -Compress |
        Add-Content -LiteralPath (Join-Path $out 'commands.jsonl') -Encoding ASCII
    if ($code) { throw "Shell-export Git failure: $Arguments`n$lines" }
    $lines | ForEach-Object {"$_"}
}
function Assert-Lf([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if (!$bytes.Length -or $bytes -contains 13 -or $bytes -notcontains 10) {
        throw "Shell export must be nonempty LF text without CR: $Path"
    }
}
foreach ($file in $shells) {
    $valid = $true
    try { Assert-Lf $file.FullName } catch { $valid = $false }
    Check ('source-lf/' + $file.FullName.Substring($repo.Length + 1)) $valid
}
foreach ($mode in @('true', 'input', 'false', 'removed-policy')) {
    $root = Join-Path $out $mode
    $null = New-Item -ItemType Directory -Path $root
    $autocrlf = if ($mode -eq 'removed-policy') { 'true' } else { $mode }
    $null = Git $root $autocrlf @('init', '--quiet')
    foreach ($file in @($shells) + @($attributes)) {
        if ($mode -eq 'removed-policy' -and $file.FullName -eq $policy) { continue }
        $relative = $file.FullName.Substring($repo.Length + 1)
        $destination = Join-Path $root $relative
        $null = New-Item -ItemType Directory -Path (Split-Path $destination) -Force
        [IO.File]::Copy($file.FullName, $destination)
    }
    $null = Git $root $autocrlf @('add', '--', 'tools')
    $tree = (Git $root $autocrlf @('write-tree')).Trim()
    $zip = Join-Path $root 'source.zip'
    $null = Git $root $autocrlf @('archive', '--format=zip', "--output=$zip", $tree)
    $export = Join-Path $root 'export'
    Expand-Archive -LiteralPath $zip -DestinationPath $export
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($file in $shells) {
        $relative = $file.FullName.Substring($repo.Length + 1)
        $path = Join-Path $export $relative
        try { Assert-Lf $path } catch { $bad.Add($relative) }
    }
    if ($mode -eq 'removed-policy') {
        Check 'removed-policy/real-archive-rejected' ($bad.Count -gt 0)
    } else {
        Check ("$mode/all-shells-exported-lf") ($bad.Count -eq 0)
        $sample = Join-Path $export ($shells[0].FullName.Substring($repo.Length + 1))
        $corrupt = Join-Path $root 'crlf-control.sh'
        $text = [IO.File]::ReadAllText($sample).Replace("`n", "`r`n")
        [IO.File]::WriteAllText($corrupt, $text, (New-Object Text.UTF8Encoding($false)))
        $rejected = $false
        try { Assert-Lf $corrupt } catch { $rejected = $true }
        Check ("$mode/injected-crlf-rejected") $rejected
    }
}
foreach ($input in $before) {
    Check ('input-stable/' + $input.Path) (
        (Get-FileHash -LiteralPath $input.Path).Hash -ceq $input.Hash)
}
$result = [ordered]@{Status='PASS';ShellFiles=$shells.Count;ArchiveModes=3;
    Checks=$checks.Count;Cases=$checks.ToArray();
    Scope='Real Git tree archives under autocrlf true/input/false; no ARM or QEMU execution'}
$result | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $out 'results.json') -Encoding ASCII
Write-Host "PASS shell exports: $($shells.Count) scripts, $($checks.Count) checks; $out"
