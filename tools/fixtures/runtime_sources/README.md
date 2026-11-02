# Runtime Source Inventory

`tools/runtime_sources.json` records source paths and roles, not ABI symbols or
safety oracles. Canonical providers are singular; compatibility roles are
explicit arrays. All paths are distinct, repository-relative top-level
`context/*.c` or `fiber/*.c` files. Readers reject reparse/symlink descendants.
This prevents duplicate source selection, not duplicate C definitions; actual
archive/ELF ownership proofs must continue to check definitions independently.
The manifest is strict UTF-8 JSON without a BOM. Duplicate decoded keys,
comments, trailing JSON, nonfinite numbers and non-integer version spellings
are rejected by both readers; UTF-16/32 input is not auto-detected.
The PowerShell JSON/XML representation also has a closed attribute grammar:
`__type` metadata cannot hide an extra JSON member as an XML attribute. Shared
cases cover all three object levels, member order, escapes and duplicates.

PowerShell callers dot-source `tools/runtime_sources.ps1`, then call
`Get-RuntimeSourcePaths -RepositoryRoot $repo -Roles engine,state,panic,legacy_compat`.
Python callers use `get_runtime_source_paths(repo, roles)` with the same names.
One role string is also accepted. Empty role arrays select no sources. Both
readers preserve requested order and validate the entire manifest, including
providers outside the selected roles. Optional configuration is never implicit.

`Get-RuntimeSourceInputs` / `get_runtime_source_inputs` additionally return the
manifest and both actual reader files. These paths are for before/after hashing;
they are not a complete compiler dependency closure. Callers must also capture
their own scripts, fixture inputs and transitive header/compiler dependencies.

Run `tools/test_runtime_sources.ps1`. The shared `cases.json` corpus is applied
to generated no-Git exports and consumed by both actual readers. Current and
inverted layouts contain inventory-only C files, not dummy runtime providers or
executable implementations. The synthetic inverted layout proves selection
mechanics, not that production ownership has moved. Byte-drift controls modify
only generated exports; live repository and installed tools remain unchanged.
Each language's path and receipt APIs are exercised independently, including
negative cases. A missing counterpart reader prevents receipt generation but
does not invalidate otherwise valid path selection by the remaining reader.

Each run retains commands, both reader outputs, case exports, input hashes and
artifact hashes, including failures. This proof performs no C compilation,
runtime execution, ABI equivalence comparison, or board access.
