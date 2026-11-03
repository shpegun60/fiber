param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$HostGcc,
    [string]$Python = 'python',
    [string]$BuildRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Assert-ClassicMpuControlReceipt {
    param($Receipt)

    function Reject([string]$Reason) { throw "Classic MPU CONTROL receipt rejected: $Reason" }
    function Fields($Value, [string[]]$Names, [string]$At) {
        if ($Value -isnot [System.Management.Automation.PSCustomObject]) { Reject "$At object type" }
        $actual = @($Value.PSObject.Properties.Name)
        if ($actual.Count -ne $Names.Count) { Reject "$At fields" }
        foreach ($name in $actual) { if ($Names -cnotcontains $name) { Reject "$At fields" } }
    }
    function Integer($Value, [long]$Expected, [string]$At) {
        if (($Value -isnot [int] -and $Value -isnot [long]) -or $Value -ne $Expected) { Reject "$At integer" }
    }
    function Boolean($Value, [bool]$Expected, [string]$At) {
        if ($Value -isnot [bool] -or $Value -ne $Expected) { Reject "$At boolean" }
    }
    function Text($Value, [string]$At) {
        if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) { Reject "$At text" }
    }
    function ArrayValue($Value, [string]$At) {
        if ($Value -isnot [array] -or $Value.Rank -ne 1) { Reject "$At array" }
    }
    function Kind($Value, [string]$At) {
        if ($Value -isnot [System.Management.Automation.PSCustomObject]) { Reject "$At object type" }
        if (@($Value.PSObject.Properties.Name) -cnotcontains 'Kind') { Reject "$At Kind missing" }
        Text $Value.Kind "$At Kind"
    }
    function Inventory($Value, $Expected, [string]$At) {
        Fields $Value @($Expected.Keys) $At
        foreach ($name in $Expected.Keys) { Integer $Value.$name $Expected[$name] "$At.$name" }
    }
    function Take($Pending, [string]$Key, [string]$At) {
        if (@($Pending.Keys) -cnotcontains $Key) { Reject "$At duplicate/unknown: $Key" }
        $Pending.Remove($Key)
    }

    Fields $Receipt @('Verdict', 'CompleteSuite', 'CPUExecuted', 'Scope', 'InputDrift', 'Cases',
        'Controls', 'Errors', 'PythonImage', 'ArtifactsVerifiedBeforePass', 'Commands', 'Python',
        'Tools', 'Counts', 'ControlCounts') 'receipt'
    if ($Receipt.Verdict -isnot [string] -or $Receipt.Verdict -cne 'PASS') { Reject 'Verdict' }
    Boolean $Receipt.CompleteSuite $true 'CompleteSuite'
    Boolean $Receipt.CPUExecuted $false 'CPUExecuted'
    Boolean $Receipt.ArtifactsVerifiedBeforePass $true 'ArtifactsVerifiedBeforePass'
    foreach ($name in @('InputDrift', 'Errors')) {
        ArrayValue $Receipt.$name $name
        if ($Receipt.$name.Count -ne 0) { Reject "$name nonempty" }
    }
    foreach ($name in @('Scope', 'PythonImage', 'Python')) { Text $Receipt.$name $name }
    if (($Receipt.Commands -isnot [int] -and $Receipt.Commands -isnot [long]) -or $Receipt.Commands -le 0) {
        Reject 'Commands integer'
    }
    Fields $Receipt.Tools @('objdump', 'readelf', 'nm', 'ar', 'cc1', 'lto1', 'as', 'ld', 'lto-wrapper', 'plugin') 'Tools'
    foreach ($name in $Receipt.Tools.PSObject.Properties.Name) { Text $Receipt.Tools.$name "Tools.$name" }
    Inventory $Receipt.Counts ([ordered]@{HostRuns=35; HostChecks=238680; ArmCodegen=63; MatchingLinks=56; Controls=214}) 'Counts'
    Inventory $Receipt.ControlCounts ([ordered]@{
        'COMPILED-GUARD-MUTATION'=61; 'COMPILED-RAW-FAMILIES'=63; 'ACTUAL-RUNTIME-V1-V2-COHORT'=56
        'COMPILED-PRE-MRS-ANNOTATION-REMOVAL'=14; 'COMPILED-OLD-CM0-READBACK'=4
        'COMPILED-VFP-POISON-before-mrs'=8; 'COMPILED-VFP-POISON-transitive-helper'=8
    }) 'ControlCounts'

    # These are receipt identities, not copied implementations of port guards.
    $profiles = @('CM0-v0', 'CM0-v1', 'CM3', 'CM4-r8', 'CM4-r16', 'CM7-r8', 'CM7-r16')
    $opts = @('O0', 'Og', 'O2', 'Os', 'O3')
    $cases = @{}
    $controls = @{}
    foreach ($profile in $profiles) {
        foreach ($opt in $opts) { $cases["HOST-GUARDS|$profile|$opt"] = $true }
        foreach ($mode in @('O0|False|False', 'Og|False|False', 'O2|False|False', 'Os|False|False',
                'O3|False|False', 'O2|True|False', 'Os|True|False', 'O2|True|True', 'Os|True|True')) {
            $cases["ARM-CODEGEN|$profile|$mode"] = $true
            $parts = $mode.Split('|')
            $label = $profile + '-' + $parts[0] + '-' + $(if ($parts[1] -ceq 'True') { 'LTO' } else { 'normal' })
            if ($parts[2] -ceq 'True') { $label += '-unsectioned' }
            $controls["COMPILED-RAW-FAMILIES|$label"] = $true
        }
        foreach ($lto in @($false, $true)) {
            foreach ($generation in @('v1', 'v2')) {
                foreach ($package in @('direct', 'archive')) {
                    $identity = "$profile|$lto|$generation|$package"
                    $cases["COHORT-MATCHING-LINK|$identity"] = $true
                    $controls["ACTUAL-RUNTIME-V1-V2-COHORT|$identity"] = $true
                }
            }
            $controls["COMPILED-PRE-MRS-ANNOTATION-REMOVAL|$profile|$lto"] = $true
            if ($profile.StartsWith('CM0-')) { $controls["COMPILED-OLD-CM0-READBACK|$profile|$lto"] = $true }
            if ($profile.StartsWith('CM4-') -or $profile.StartsWith('CM7-')) {
                foreach ($where in @('before-mrs', 'transitive-helper')) { $controls["COMPILED-VFP-POISON-$where|$profile|$lto"] = $true }
            }
        }
        $guards = @('fiber_port_boot.c/fiber_port_context_fast_check/control/0',
            'fiber_port_boot.c/fiber_port_context_validate_restore/control/0',
            'fiber_port.c/fiber_port_pendsv_validate_save_current/control/0',
            'fiber_port.c/fiber_port_scheduler_pick_next_from_pendsv/control/0',
            'fiber_port.c/fiber_port_mpu_switch_to_context/control/0')
        if ($profile.StartsWith('CM0-')) {
            $guards += @('fiber_port_boot.c/fiber_port_context_initial_image_check/control/0',
                'fiber_port_boot.c/fiber_port_context_validate_initial_restore/control/0',
                'fiber_port_boot.c/fiber_port_context_validate_running_frame/control/0')
        } elseif ($profile -ceq 'CM3') {
            $guards += @('fiber_port_boot.c/fiber_port_context_init/control/0',
                'fiber_port_boot.c/fiber_port_context_validate_running_frame/control/0',
                'fiber_port.c/fiber_port_runtime_select_first/control/0',
                'fiber_port.c/fiber_port_runtime_start_first/control/0')
        } else {
            $guards += @('fiber_port_boot.c/fiber_port_context_init/control/0',
                'fiber_port_boot.c/fiber_port_context_validate_initial_restore/control/0',
                'fiber_port_boot.c/fiber_port_context_validate_restore/control/1',
                'fiber_port_boot.c/fiber_port_context_validate_running_svc/control/0')
        }
        foreach ($guard in $guards) { $controls["COMPILED-GUARD-MUTATION|$profile|$guard"] = $true }
    }

    ArrayValue $Receipt.Cases 'Cases'
    foreach ($row in $Receipt.Cases) {
        Kind $row 'Cases row'
        $caseFields = switch -CaseSensitive ($row.Kind) {
            'HOST-GUARDS' { @('Kind', 'Profile', 'Optimization', 'Checks', 'Guards') }
            'ARM-CODEGEN' { @('Kind', 'Profile', 'Optimization', 'NativeLTO', 'Unsectioned', 'PreMRSClosure', 'ExternalTerminal') }
            'COHORT-MATCHING-LINK' { @('Kind', 'Profile', 'NativeLTO', 'Packaging', 'ProviderGeneration') }
            default { Reject 'Cases Kind' }
        }
        Fields $row $caseFields 'Cases row'
        foreach ($name in @('Profile', 'Optimization', 'Packaging', 'ProviderGeneration')) {
            if ($caseFields -ccontains $name) { Text $row.$name "Cases $name" }
        }
        if ($profiles -cnotcontains $row.Profile) { Reject 'Cases Profile' }
        switch -CaseSensitive ($row.Kind) {
            'HOST-GUARDS' {
                Take $cases "HOST-GUARDS|$($row.Profile)|$($row.Optimization)" 'Cases'
                $guardCount = if ($row.Profile.StartsWith('CM0-')) { 13 } elseif ($row.Profile -ceq 'CM3') { 14 } else { 16 }
                Integer $row.Guards $guardCount 'Cases Guards'
                Integer $row.Checks (459 * $guardCount) 'Cases Checks'
            }
            'ARM-CODEGEN' {
                if ($row.NativeLTO -isnot [bool] -or $row.Unsectioned -isnot [bool]) { Reject 'Cases mode boolean' }
                Take $cases "ARM-CODEGEN|$($row.Profile)|$($row.Optimization)|$($row.NativeLTO)|$($row.Unsectioned)" 'Cases'
                ArrayValue $row.PreMRSClosure 'Cases PreMRSClosure'
                if ($row.PreMRSClosure.Count -eq 0) { Reject 'Cases PreMRSClosure empty' }
                $closureNames = @()
                foreach ($name in $row.PreMRSClosure) {
                    Text $name 'Cases PreMRSClosure member'
                    if ($closureNames -ccontains $name) { Reject 'Cases PreMRSClosure duplicate' }
                    $closureNames += $name
                }
                foreach ($root in @('fiber_port_pendsv_validate_save_current', 'fiber_port_context_validate_save_current')) {
                    if ($row.PreMRSClosure -cnotcontains $root) { Reject 'Cases PreMRSClosure roots' }
                }
                ArrayValue $row.ExternalTerminal 'Cases ExternalTerminal'
                foreach ($name in $row.ExternalTerminal) { Text $name 'Cases ExternalTerminal member' }
                if ($row.ExternalTerminal.Count -gt 1 -or ($row.ExternalTerminal.Count -eq 1 -and $row.ExternalTerminal[0] -cne 'fiber_panic')) { Reject 'Cases ExternalTerminal members' }
            }
            'COHORT-MATCHING-LINK' {
                if ($row.NativeLTO -isnot [bool]) { Reject 'Cases mode boolean' }
                Take $cases "COHORT-MATCHING-LINK|$($row.Profile)|$($row.NativeLTO)|$($row.ProviderGeneration)|$($row.Packaging)" 'Cases'
            }
        }
    }
    if ($cases.Count -ne 0) { Reject 'Cases incomplete' }

    ArrayValue $Receipt.Controls 'Controls'
    foreach ($row in $Receipt.Controls) {
        Kind $row 'Controls row'
        $fields = switch -CaseSensitive ($row.Kind) {
            'COMPILED-GUARD-MUTATION' { @('Kind', 'Profile', 'Guard', 'Diagnostic') }
            'COMPILED-RAW-FAMILIES' { @('Kind', 'Case', 'Observed') }
            'ACTUAL-RUNTIME-V1-V2-COHORT' { @('Kind', 'Profile', 'NativeLTO', 'Packaging', 'ProviderGeneration', 'ExpectedMissing', 'ProviderSHA256') }
            'COMPILED-OLD-CM0-READBACK' { @('Kind', 'Profile', 'NativeLTO', 'ExpectedBadReadbacks') }
            { $_ -cin @('COMPILED-PRE-MRS-ANNOTATION-REMOVAL', 'COMPILED-VFP-POISON-before-mrs', 'COMPILED-VFP-POISON-transitive-helper') } { @('Kind', 'Profile', 'NativeLTO') }
            default { Reject 'Controls Kind' }
        }
        Fields $row $fields 'Controls row'
        foreach ($name in @('Profile', 'Guard', 'Case', 'Packaging', 'ProviderGeneration')) {
            if ($fields -ccontains $name) { Text $row.$name "Controls $name" }
        }
        $key = ''
        if ($fields -ccontains 'NativeLTO') {
            if ($row.NativeLTO -isnot [bool]) { Reject 'Controls mode boolean' }
            $key = "$($row.Kind)|$($row.Profile)|$($row.NativeLTO)"
        }
        switch -CaseSensitive ($row.Kind) {
            'COMPILED-GUARD-MUTATION' {
                $key = "$($row.Kind)|$($row.Profile)|$($row.Guard)"
                Text $row.Diagnostic 'Controls Diagnostic'
                if ($row.Diagnostic -cnotmatch ('^CONTROL-MISMATCH ' + [regex]::Escape($row.Guard) + ' value=[0-9A-F]{8} expected=([01]) actual=([01])$') -or $Matches[1] -ceq $Matches[2]) { Reject 'Controls Diagnostic witness' }
            }
            'COMPILED-RAW-FAMILIES' {
                $key = "$($row.Kind)|$($row.Case)"
                ArrayValue $row.Observed 'Controls Observed'
                if ($row.Observed.Count -ne 6) { Reject 'Controls Observed inventory' }
                $observed = @{}
                foreach ($family in @('coverage', 'instrument', 'pg', 'ssp', 'tracepc', 'ubsan')) { $observed[$family] = $true }
                foreach ($family in $row.Observed) { Text $family 'Controls Observed member'; Take $observed $family 'Controls Observed' }
            }
            'ACTUAL-RUNTIME-V1-V2-COHORT' {
                $key = "$($row.Kind)|$($row.Profile)|$($row.NativeLTO)|$($row.ProviderGeneration)|$($row.Packaging)"
                Text $row.ExpectedMissing 'Controls ExpectedMissing'
                if ($row.ExpectedMissing -cnotmatch '^fiber_port_context_cohort_[A-Za-z0-9_]+$') { Reject 'Controls ExpectedMissing value' }
                if ($row.ProviderSHA256 -isnot [string] -or $row.ProviderSHA256 -cnotmatch '^[0-9A-F]{64}$') { Reject 'Controls ProviderSHA256' }
            }
            'COMPILED-OLD-CM0-READBACK' { Integer $row.ExpectedBadReadbacks 2 'Controls ExpectedBadReadbacks' }
            'COMPILED-PRE-MRS-ANNOTATION-REMOVAL' { }
            'COMPILED-VFP-POISON-before-mrs' { }
            'COMPILED-VFP-POISON-transitive-helper' { }
            default { Reject 'Controls Kind' }
        }
        Take $controls $key 'Controls'
    }
    if ($controls.Count -ne 0) { Reject 'Controls incomplete' }
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (!$ArmGcc -or !$CmsisCore) { throw 'Specify -ArmGcc and -CmsisCore explicitly' }
if (!$HostGcc) { $HostGcc = (Get-Command gcc.exe -ErrorAction Stop).Source }
foreach ($path in @($ArmGcc, $HostGcc, (Join-Path $CmsisCore 'core_cm0plus.h'),
        (Join-Path $CmsisCore 'core_cm3.h'), (Join-Path $CmsisCore 'core_cm4.h'),
        (Join-Path $CmsisCore 'core_cm7.h'))) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required input missing: $path" }
}
if (!$BuildRoot) { $BuildRoot = Join-Path $env:TEMP ('fiber-classic-mpu-control-' + [guid]::NewGuid().ToString('N')) }
$runner = Join-Path $PSScriptRoot 'fixtures/classic_mpu_control/run.py'
$old = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    & $Python -B $runner --repo $repo --gcc $ArmGcc --cmsis $CmsisCore --host-gcc $HostGcc --build $BuildRoot
    $code = $LASTEXITCODE
} finally { $ErrorActionPreference = $old }
if ($code -ne 0) { throw "Classic MPU CONTROL regression failed ($code): $BuildRoot" }
$receipt = Get-Content -LiteralPath (Join-Path $BuildRoot 'results.json') -Raw | ConvertFrom-Json
Assert-ClassicMpuControlReceipt $receipt
& (Join-Path $PSScriptRoot 'fixtures/classic_mpu_control/test_closing.ps1') `
    -ReceiptPath (Join-Path $BuildRoot 'results.json') -BuildRoot ($BuildRoot + '-closing')
Write-Host "PASS classic MPU CONTROL: $BuildRoot"
