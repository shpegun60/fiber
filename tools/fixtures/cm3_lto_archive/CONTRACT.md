# Native CM3 O2-LTO Archive Capture

## Fixed Scope

This contract defines capture feasibility only for native
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default`, O2-LTO,
using a static archive rather than the qualified direct-object link order.
It makes no implementation, execution or measured PASS claim.
Authenticate the fixed ordinary O2 seed receipt and artifact manifest with
independent caller-supplied hashes, and admit its exact source/configuration,
inventory, compiler, flags and dependencies before creating output or executing
selected helpers. Preserve the seed's scope and original bytes unchanged.

## Exact Inputs And Archive

Recompile the same nine seed translation units with the captured toolchain.
The eight C units use the unchanged O2 recipe plus genuine
`-flto -fno-fat-lto-objects`; startup remains the unchanged native assembly input
compiled with its admitted O2 flags. No old direct-link machine or fat fallback
may replace these fresh slim IR inputs.

Create one indexed archive with exactly these six members, in seed index order:

| Seed index | Source |
|---|---|
| 0 | `context/context_core.c` |
| 1 | `context/context_runtime_state.c` |
| 2 | `context/context_panic.c` |
| 3 | `fiber/port/ARM_CM3/fiber_port.c` |
| 4 | `fiber/port/ARM_CM3/fiber_port_boot.c` |
| 5 | `fiber/port/ARM_CM3/fiber_port_exception.c` |

Bind every member name, order and complete extracted bytes to its freshly
compiled object and hash. Binary member authority is the raw archive payload,
the compiled object and a generated private file from `ar x`, compared without
rewriting any bytes. Do not use `ar p` stdout as binary authority or normalize
LF/CRLF to obtain equality; retain command streams as recorded evidence.
Retain the raw member listing and archive symbol
index, not just a six-member counter. Use authenticated archive/index tools from
the same captured toolchain; retain exact commands, tool/plugin bytes and raw
inspection streams. Record plugin/worker resolution fields actually obtained;
their independent semantic validation may remain partial, not silently PASS.
No ambient archive tool or silent index repair is authority. Freeze the archive
before and after each link.

The explicit objects before the archive are, in order, seed index 8
`tools/fixtures/classic_final_image/startup.S`, index 7
`tools/fixtures/classic_final_image/application.c`, and index 6
`fiber/port/fiber_port_context_cohort_expectation.c`. Thus the authorized order
is exactly `(8, 7, 6)`, then the archive. Link only those three explicit
objects followed by the archive, using the unchanged authenticated linker
script. Do not duplicate archived members as direct objects, use whole-archive,
forced undefined symbols (`-u`/`--undefined`), extra anchors, rescue stubs,
or new linker-script retention rules to manufacture extraction.

## Consumer And Extraction Boundaries

Keep the expectation outside the archive and before it, using the unchanged
script's private/storage expectation KEEP rules. KEEP does not itself prove
extraction of a member hidden inside an archive. Retain raw maps, resolution
records and symbol inspections for later provider/expectation analysis. Parsed
expectation-relocation or extraction fields may remain partial; capture does
not claim their independent qualification. Do not assume that packaging six
members means all six were extracted.

The fallback definition of `fiber_panic` is weak, but the existing public
declaration and consumer references remain strong. Record the actual archive
index and observed fallback selection/resolution evidence; do not assume its
pre-LTO weak binding survives LTO or add a strong override to force selection.
The unchanged startup references SVC/PendSV as undefined symbols and has no weak
Default_Handler aliases for them. Evidence is for this exact consumer only,
not startup weak-alias precedence, override semantics or a new archive-negative
proof. Existing matrix weak fixtures are separate evidence, not credit here.
No startup or production source change belongs to this slice.

## Actual Links And Closing Evidence

Produce fresh ordinary and emit-relocs twins from the same explicit objects,
archive and script in separate private directories. Preserve the existing
target/O2/LTO/link flags, including one partition and actual machine retention
via `-flto-partition=one -save-temps=obj -Wl,-plugin-opt=-save-temps`.
Only emit-relocs and necessary output/map/private-directory names differ.
Require a fresh actual saved LTRANS machine per link; WPA IR is not machine
authority. Retain entire link-temp directories, maps, `.res`, argument/response
files, verbose tool traces, machine/final inspections and archive extraction
evidence. Preserve actual raw bindings/layouts rather than imposing direct-link
root sizes, symbol classes, provider counts or resolution-row totals.

Compare the two actual load images with the authenticated unchanged comparator.
Close seed/source/helper/input/tool/archive/member/object bytes and membership,
command records and generated evidence through sealing. Report physical-identity
bindings actually checked; partial fields are not an all-file identity proof.
Use immutable helper buffers, the hardened contained process runner and the
existing sanitized environment policy. Pin consumed evidence before use.

The archive subclass must implement the intended-receipt sealing guard rather
than inherit the utility's disk-learned receipt seal unchanged. Serialize the
intended report once with the writer's exact platform newline representation,
verify the written bytes, and bind the manifest's receipt hash directly to those
intended bytes. Do not learn that expected hash from a later disk read. Recheck
complete output membership/hashes after manifest writing and at late closing;
persist FAIL on drift with a consistent failure receipt/manifest.

Capture PASS proves only this consumer's build/extraction capture and twin load
equivalence. Root preservation, canonical protocols, reference parity, full
API/ABI, source/IR semantics, general archive/weak-alias behavior, runtime,
CPU/hardware and global qualification remain false or unproved. Required-cell
credit remains literal integer zero. Future qualification must independently
replay the new machines' full origin/REL/mapping evidence and canonical bodies;
direct-link receipts or matching metadata cannot substitute for that replay.
