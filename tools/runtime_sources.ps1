# Proof-only common source inventory. Dot-source this file; no Git is required.
# Both public functions validate the complete manifest. Roles are explicit and
# preserve caller order. Empty role arrays are valid for port-only consumers.
# Get-RuntimeSourceInputs adds the manifest and both actual reader files; callers
# must still capture their own scripts, fixtures, headers and dependency closure.

function Read-RuntimeSourceObject {
    param([System.Xml.XmlElement]$Node, [string[]]$Keys, [string]$Label)

    if ($Node.GetAttribute('type') -cne 'object') {
        throw "runtime_sources: schema: $Label must be an object"
    }
    $fields = New-Object 'System.Collections.Generic.Dictionary[string,System.Xml.XmlElement]' ([StringComparer]::Ordinal)
    foreach ($child in $Node.ChildNodes) {
        if ($child -isnot [System.Xml.XmlElement]) {
            throw "runtime_sources: schema: unknown field in $Label"
        }
        # Escaped JSON names use the JSON/XML mapping's item attribute.
        $name = $child.LocalName
        if ($child.NamespaceURI -ceq 'item' -and $name -ceq 'item') {
            $name = $child.GetAttribute('item')
        }
        if ($Keys -cnotcontains $name) {
            throw "runtime_sources: schema: unknown field in $Label"
        }
        if ($fields.ContainsKey($name)) {
            throw "runtime_sources: schema: duplicate JSON key in $Label"
        }
        $fields.Add($name, $child)
    }
    if ($fields.Count -ne $Keys.Count) {
        throw "runtime_sources: schema: $Label requires exactly $($Keys -join ', ')"
    }
    return ,$fields
}

function Resolve-RuntimeSourceFile {
    param([string]$Root, [string]$Relative)

    $path = $Root
    foreach ($part in $Relative.Split('/')) {
        $path = Join-Path $path $part
        if (!(Test-Path -LiteralPath $path)) {
            throw "runtime_sources: input: missing $Relative"
        }
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "runtime_sources: path: reparse/symlink input is unsupported: $Relative"
        }
    }
    if ($item.PSIsContainer) {
        throw "runtime_sources: input: not a regular file: $Relative"
    }
    return $item.FullName
}

function Read-RuntimeSourceInventory {
    param([Parameter(Mandatory=$true)][string]$RepositoryRoot)

    $root = Get-Item -LiteralPath $RepositoryRoot -Force -ErrorAction Stop
    if (!$root.PSIsContainer) {
        throw 'runtime_sources: input: repository root is not a directory'
    }
    $manifest = Resolve-RuntimeSourceFile $root.FullName 'tools/runtime_sources.json'
    $reader = $null
    try {
        # The structured JSON/XML reader preserves duplicate keys, unlike
        # ConvertFrom-Json on Windows PowerShell. Reject them before selection.
        Add-Type -AssemblyName System.Runtime.Serialization -ErrorAction Stop
        $bytes = [IO.File]::ReadAllBytes($manifest)
        $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $text = $utf8.GetString($bytes)
        if ($text.Length -ne 0 -and $text[0] -eq [char]0xFEFF) {
            throw 'manifest must be canonical UTF-8 JSON without a BOM'
        }
        if ($text.IndexOf([char]0) -ge 0) {
            throw 'manifest must be UTF-8 JSON, not auto-detected UTF-16/32'
        }
        # The JSON/XML reader can silently ignore another JSON root. Validate
        # whole-document consumption separately; never use its collapsed keys.
        $null = ConvertFrom-Json -InputObject $text -ErrorAction Stop
        $bytes = $utf8.GetBytes($text)
        $reader = [System.Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader(
            $bytes, [System.Xml.XmlDictionaryReaderQuotas]::Max)
        $document = New-Object System.Xml.XmlDocument
        $document.Load($reader)
        # JSON __type metadata can become an XML attribute instead of a child.
        # Admit only the reader's type/name mapping, never hidden JSON members.
        foreach ($node in $document.SelectNodes('//*')) {
            $mappedName = $node.NamespaceURI -ceq 'item' -and $node.LocalName -ceq 'item'
            foreach ($attribute in $node.Attributes) {
                if ($attribute.NamespaceURI -ceq '' -and $attribute.LocalName -ceq 'type') {
                    continue
                }
                if ($mappedName -and $attribute.NamespaceURI -ceq '' -and
                        $attribute.LocalName -ceq 'item') {
                    continue
                }
                if ($mappedName -and
                        $attribute.NamespaceURI -ceq 'http://www.w3.org/2000/xmlns/' -and
                        $attribute.Value -ceq 'item') {
                    continue
                }
                throw "unsupported JSON/XML attribute: $($attribute.Name)"
            }
        }
    }
    catch {
        throw "runtime_sources: schema: cannot load manifest: $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }
    $top = Read-RuntimeSourceObject $document.DocumentElement @(
        'schema_version', 'providers', 'compatibility') 'root'
    if ($top['schema_version'].GetAttribute('type') -cne 'number' -or
            $top['schema_version'].InnerText -cne '1') {
        throw 'runtime_sources: schema: schema_version must be integer 1'
    }
    $providerRoles = @('engine', 'state', 'panic', 'optional_configuration')
    $compatibilityRoles = @('legacy_compat', 'facade_bridge')
    $providers = Read-RuntimeSourceObject $top['providers'] $providerRoles 'providers'
    $compatibility = Read-RuntimeSourceObject $top['compatibility'] $compatibilityRoles 'compatibility'
    $paths = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($role in ($providerRoles + $compatibilityRoles)) {
        if ($providerRoles -ccontains $role) {
            $entries = @($providers[$role])
        }
        else {
            $array = $compatibility[$role]
            if ($array.GetAttribute('type') -cne 'array') {
                throw "runtime_sources: provider: $role must be an array"
            }
            $entries = @($array.ChildNodes)
        }
        $resolved = New-Object System.Collections.Generic.List[string]
        foreach ($entry in $entries) {
            if ($entry -isnot [System.Xml.XmlElement] -or
                    $entry.GetAttribute('type') -cne 'string' -or
                    $entry.InnerText -cnotmatch '\A(?:context|fiber)/[A-Za-z0-9_-]+\.c\z') {
                throw "runtime_sources: path: $role requires a canonical context/*.c or fiber/*.c path"
            }
            $relative = $entry.InnerText
            if (!$seen.Add($relative)) {
                throw "runtime_sources: provider: duplicate source provider: $relative"
            }
            $resolved.Add((Resolve-RuntimeSourceFile $root.FullName $relative))
        }
        $paths.Add($role, $resolved.ToArray())
    }
    return [pscustomobject]@{Manifest=$manifest; Paths=$paths}
}

function Select-RuntimeSourcePaths {
    param([object]$Inventory, [AllowEmptyCollection()][object]$Roles)

    if ($Roles -is [string]) { $Roles = @($Roles) }
    elseif ($Roles -isnot [array]) {
        throw 'runtime_sources: role: roles must be a role name or an array of role names'
    }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($role in $Roles) {
        if ($role -isnot [string] -or !$Inventory.Paths.ContainsKey($role)) {
            throw "runtime_sources: role: unknown role: $role"
        }
        if (!$seen.Add($role)) {
            throw "runtime_sources: role: duplicate requested role: $role"
        }
        foreach ($path in $Inventory.Paths[$role]) { $path }
    }
}

function Get-RuntimeSourcePaths {
    param(
        [Parameter(Mandatory=$true)][string]$RepositoryRoot,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object]$Roles
    )

    $inventory = Read-RuntimeSourceInventory -RepositoryRoot $RepositoryRoot
    Select-RuntimeSourcePaths -Inventory $inventory -Roles $Roles
}

function Get-RuntimeSourceInputs {
    param(
        [Parameter(Mandatory=$true)][string]$RepositoryRoot,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object]$Roles
    )

    $inventory = Read-RuntimeSourceInventory -RepositoryRoot $RepositoryRoot
    $selected = @(Select-RuntimeSourcePaths -Inventory $inventory -Roles $Roles)
    $definition = $MyInvocation.MyCommand.ScriptBlock.File
    if ([string]::IsNullOrEmpty($definition)) {
        throw 'runtime_sources: input: reader must be loaded from its actual file'
    }
    $directory = Split-Path -Parent $definition
    $inventory.Manifest
    Resolve-RuntimeSourceFile $directory 'runtime_sources.ps1'
    Resolve-RuntimeSourceFile $directory 'runtime_sources.py'
    $selected
}
