# CM3 Os-LTO Machine Replay Components

These pure components prepare the final immutable-reader replay for the current
CM3 `-Os` + LTO direct cell. They do not qualify that cell independently.

## Authority

The caller must authenticate every helper before executing it, admit the actual
current Os capture, and bind each original/generated input to its declared role
and SHA256. The original target, optimization and ABI options must be established
from the captured compiler/worker records. ELF bytes alone do not prove `-Os`.

The final composer must consume ABI, isolation, common-attribute and selected-port
outputs in one immutable reader scope. Separate pure tests or earlier component
receipts cannot substitute for that replay. Output sealing and physical input
closure happen outside the reader, including failure and summary-failure paths.

## Common Effects

`common_effects.py` owns the Os result and checks actual original ET_REL bytes.
It uses only explicitly supplied neutral attribute primitives and catalogs, not
the old O2 top-level inspector. It covers the fourteen protected common functions,
Thread-section identity, cold carrier activity, constructor/counter ownership,
original REL fields, three annotation mutants, and protected/raw stress carriers.

An unresolved setter/cold-inline attribution returns `PENDING`. A structurally
valid pending record is not a clean result. A future composer must not promote it
to protected-effects PASS without an independent attribution proof. The unchanged
clean predicate must reject each actual intended mutant/raw carrier.

## Port Census

`port_census.py` owns the Os instruction/REL census. Its low-level policy helpers
are caller-authenticated. It does not invoke or relabel the frozen O2 `_scan`,
`inspect_lowered`, `inspect_final` or `inspect_stress` results.

Public lowered/final inspectors require a validated provider surface; `None`
must not disable that requirement. Only the internal one-function stress scan
has no selected-provider surface. The census retains complete executable bytes,
function extents, padding and referenced mapped literal pools. It rejects missing
or extra disassembly rows, forbidden dependencies/forms and malformed, overlapping
or unowned transfer REL sites. Original addend and applied destination semantics
remain separate obligations, not implied by this census.

Final vector evidence requires an allocated file-backed `.isr_vector`, a unique
readable PT_LOAD owner, matching section/load offsets and raw bytes, strong
Reset/SVC/PendSV symbol values in slots 1/11/14, and the matching ELF entry. This
does not prove active hardware vector routing or the complete transfer protocols.

## Scope

Pure tests use synthetic bytes and do not execute a compiler, a real ELF parser,
or a CPU. Actual aggregate and saved-worker outputs still require a final replay.
No component grants whole-cell, archive, global-freeze, hosted-CI or hardware
credit. No runtime C, context layout, SVC or PendSV implementation is changed.
