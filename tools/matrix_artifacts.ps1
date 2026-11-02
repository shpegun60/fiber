# Shared by the matrix and its filesystem-only regression gate.
function New-FiberMatrixBuildDirectory {
    param([string]$RequestedPath)

    $automatic = [string]::IsNullOrWhiteSpace($RequestedPath)
    $path = if ($automatic) {
        Join-Path ([IO.Path]::GetTempPath()) (
            'fiber-compile-matrix-' + [Guid]::NewGuid().ToString('N'))
    } else {
        $RequestedPath
    }
    $path = [IO.Path]::GetFullPath($path)
    if ($path.IndexOfAny([char[]]'*?[]') -ge 0) {
        throw 'Matrix build directory must not contain wildcard characters'
    }
    if (Test-Path -LiteralPath $path) {
        throw "Matrix build directory already exists; refusing stale outputs: $path"
    }
    $created = New-Item -ItemType Directory -Path $path -ErrorAction Stop
    [pscustomobject]@{Path=$created.FullName; Automatic=$automatic}
}

function Remove-FiberAutomaticMatrixBuildDirectory {
    param([object]$Directory)

    if ($null -eq $Directory -or $Directory.Automatic -ne $true) {
        throw 'Refusing to remove an application-owned matrix output directory'
    }
    $path = [IO.Path]::GetFullPath([string]$Directory.Path)
    $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
    $parent = ([string][IO.Path]::GetDirectoryName($path)).TrimEnd('\','/')
    $leaf = [IO.Path]::GetFileName($path)
    if (![string]::Equals($parent, $temp, [StringComparison]::OrdinalIgnoreCase) -or
            $leaf -cnotmatch '^fiber-compile-matrix-[0-9a-f]{32}$') {
        throw "Refusing matrix cleanup outside its exact automatic temporary directory: $path"
    }
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (!$item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Refusing matrix cleanup of a file or reparse point: $path"
    }
    $pending = New-Object System.Collections.Generic.Stack[string]
    $pending.Push($item.FullName)
    while ($pending.Count -ne 0) {
        foreach ($child in Get-ChildItem -LiteralPath $pending.Pop() -Force -ErrorAction Stop) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing matrix cleanup with a descendant reparse point: $($child.FullName)"
            }
            if ($child.PSIsContainer) { $pending.Push($child.FullName) }
        }
    }
    Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
}
