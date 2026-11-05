# CM3 Final Mechanism Join

## Fixed Scope

This opt-in gate composes independently qualified native and pinned-reference
CM3 direct final images. It admits only
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default`, at exactly
O0/Og/O2/Os/O3. The target is Cortex-M3/ARMv7-M, ordinary AAPCS, soft ABI,
no FPU or FP stacking, VTOR1, no MPU, classic security, four declared priority
bits and raw BASEPRI threshold 16. PSPLIM, MVE, PAC/BTI, fixed-R9/PIC and
alternate errata policies are outside this cohort.

Each admitted pair contains six complete transfer roots and three fixed
mechanisms. A five-mode sweep is five separate pairs, not an expansion to
other defines, CPUs, optimization combinations or link routes. No compiler,
linker, objdump, emulator, Git command or target is executed by this join.
The producer recipes, generated images and execution evidence remain separate
from this read-only composition gate.

## Authentication Before Parsing

Both producer `results.json` hashes and both `artifacts.json` hashes must be
supplied from separately qualified evidence. All four complete byte buffers
must authenticate before importing pyelftools, ELF readers or replay helpers
that can load parser code. Matching a receipt without authenticating its full
artifact manifest is insufficient. Deriving new expected hashes from an
untrusted directory is not admission.

The authenticated manifests must cover the receipts, sources, owning objects,
disassembly, attributes, maps, final images, captured parser and input records.
Exact artifact membership and all declared hashes are required, not merely
validation of whichever files happen to be supplied. Duplicate JSON keys,
missing/foreign artifacts, input drift and conflicting bindings reject.

Native and reference must bind the same captured inventory fingerprint,
manifest, exact cohort and selected mode. The reference pin is
`a50edad08b29052631aa469d4df6e6ec7ff68878`. Source-group and target keys,
complete artifact facts, flags and mode are independently admitted; source
fingerprints, architecture attributes or matching filenames alone are not CPU
proof. Og/O2/Os/O3 identity cannot be inferred from equal instruction bytes.

## Inputs And Owners

Native retains exactly nine TUs, in the producer's fixed order:

1. `context/context_core.c`.
2. `context/context_runtime_state.c`.
3. `context/context_panic.c`.
4. `fiber/port/ARM_CM3/fiber_port.c`.
5. `fiber/port/ARM_CM3/fiber_port_boot.c`.
6. `fiber/port/ARM_CM3/fiber_port_exception.c`.
7. `fiber/port/fiber_port_context_cohort_expectation.c`.
8. `tools/fixtures/classic_final_image/application.c`.
9. `tools/fixtures/classic_final_image/startup.S`.

The transfer-owning prelink is native source index 3, `03-fiber_port.o`.
Native common-state, scheduler/validation and weak default panic providers
retain their separate original object identities and definition bindings.

Reference retains exactly four TUs:

1. Pinned `portable/GCC/ARM_CM3/port.c`.
2. `tools/fixtures/cm3_final_image/reference/providers.c`.
3. `tools/fixtures/cm3_final_image/reference/consumer.c`.
4. `tools/fixtures/cm3_final_image/reference/startup.S`.

Reference source index 0, `00-port.o`, owns all three reference transfer roots.
There is no `portasm.c`, CM0 C SVC dispatcher or composite reference-owner
adapter. Only `prvPortStartFirstTask` is, and must be, local; reference SVC and
PendSV are strong globals. The strong scheduler boundary and four-byte BSS
`pxCurrentTCB` slot share the separate provider object. A null opaque TCB
pointer and typed fail-stop functions do not provide a runtime kernel.

The exact same native and reference owning objects must feed both
`cm3_freeze_parity/check.py:check_pair` and their respective final readers.
Objects from another mode, a merged group, a separately reconstructed body or
an unrelated successful receipt are not substitutes. Provider sets, original
REL authority and ordinary/emitted final links must name these same objects.

Complete source/dependency, generated-config, linker-script, inventory,
compiler/interpreter, resolved-worker, DLL and parser input bindings are
required. Discovery dependencies must agree with actual compile dependencies.
Exact ordered compile commands bind target/mode flags, source, dependency file
and object; exact link commands bind all provider objects, script, map,
ordinary/emit-relocs choice and output. No extra optimization, target, ABI or
LTO override is admitted.

Unchanged reference source and consumed upstream headers must bind pinned Git
blobs. Only exact bytes or a whole-file LF-to-CRLF conversion is permitted,
retaining both raw blob and worktree hashes. Mixed-newline or semantic
normalization is not accepted. Generated `FreeRTOSConfig.h` instead binds the
captured recipe and producer configuration-transform bytes, together with the
captured repository fixture's base-config bytes; neither generated nor base
configuration is presented as an upstream Git blob. Enabled inline assertions,
handler-installation check 1, the two thresholds 16 and header facts
`(1,4,4,4,8,0,0,16,16,4)` remain explicit.

## Exact Mechanisms

The following assignments are normative and match the fixed checker's
`_MECHANISMS`; order and ID membership are not caller-selected.

| Mechanism | Native root | Reference root | Difference IDs |
| --- | --- | --- | --- |
| first-start | `fiber_port_start_first_context` | `prvPortStartFirstTask` | `FAP-COMMON-START`, `FAP-COMMON-PROVENANCE`, `FAP-CM3-LOCAL-LITERAL-POOLS` |
| first-restore | `SVC_Handler` | `vPortSVCHandler` | `FAP-COMMON-PROVENANCE`, `FAP-COMMON-MASK-RESTORE`, `FAP-CM3-EXC-RETURN`, `FAP-CM3-LOCAL-LITERAL-POOLS` |
| PendSV | `PendSV_Handler` | `xPortPendSVHandler` | `FAP-COMMON-SCHEDULER`, `FAP-COMMON-PROVENANCE`, `FAP-CM3-EXC-RETURN`, `FAP-CM3-LOCAL-LITERAL-POOLS` |

Every one of these six unique IDs must have its exact heading and nonempty
rationale in the admitted inventory's captured `FREERTOS_ASM_PARITY.md` ledger
(the retained E8 input is `inputs/FREERTOS_ASM_PARITY.md`). Current root-document
edits or this directory's `POLICY_DIFFERENCES.md` cannot replace a missing or
different captured rationale. The policy document specializes the existing
IDs; it does not introduce an additional mechanism or equivalence waiver.

All six source-derived canonical protocols must consume complete bodies,
including failure branches, barriers, literal descriptors and mode-bound NOPs.
The final readers independently bind complete root raw bytes, mappings,
unapplied REL addends, applied destinations and exact definition origins.
Original addends are taken from the owning prelinks, never reverse-inferred
from the already relocated final bytes. Provider/map checks bind full original
input-section extents and symbol offsets/sizes, not mutable final symbol names
alone. Ordinary instructions are not filtered or replaced by matching token or
body hashes. Canonical-token and raw-byte hashes remain distinct evidence.

The reference reader also preserves its fixed separate padding/pool mappings,
in-function O0 NOPs and permitted outside-function alignment bytes. Original
provider files and input-section records remain bound without extending a
root proof to unrelated C bodies. Unknown layouts, aliases, veneers, interior
call targets or unsupported relocation forms reject.

Native and reference each require their own ordinary/emit-relocs twin
comparison, preserving entry/vector bytes, allocated layout and PT_LOAD bytes.
These are two within-implementation comparisons. Native and reference images
are not required to have identical bytes, layouts, control flow or addresses.

## Policy And Closure

The native software frame has nine words: r4-r11 plus the saved, validated
EXC_RETURN in LR. Reference CM3 saves/restores only r4-r11; reference SVC
constructs Thread/PSP return through the exact `orr lr,lr,#13`. Neither side is
rewritten into the other's frame. Initial register values, dynamic EXC_RETURN
values, control-plane state, masks, provenance and scheduler behavior are not
declared equivalent. No FP setup/transfer contract or CM0 staged-dispatch
contract is imported into this join.

The parser must come from an authenticated captured package, with cross-build
package identity and recorded imported-module origins/hashes checked. Ambient
cached parsers are not authority. Local executable helper graphs must execute
the authenticated source buffers, including nested legacy loaders, rather
than hash A, execute a transient B and accept restored A at closure.
Originals, captures, generated inputs, parser/helper sources and exact input
and output memberships must close after replay. Failed closure must retain a
non-promoting failure, not a stale PASS.

Fresh external output must not overlap the repository, producer directories
or frozen input memberships. Distinct physical file roles and provider
identities reject same-path, reparse/symlink and hard-link self-comparison.
One intentional prelink/provider overlap per implementation is not a license
for aliases between finals, maps, disassemblies or implementations.

The CLI calls `prepare_output(args)` before creating the output directory. It
authenticates all four caller-supplied receipt/manifest hashes, requires each
manifest to bind its receipt, then authenticates each manifest-bound
`inputs.json`. Output-denial roots are derived from those same authenticated
receipt/input buffers, with a closing read/hash check before admission returns.
Wrong hashes or overlap with declared inputs reject without creating output;
the caller or outer driver retains stderr for these admission failures. Later
replay or closure failures must seal a non-promoting FAIL in the created output.

The three-argument `output_directory(path, native, reference)` helper is only a
synthetic declaration-based denial check. It does not authenticate producer
records and is not CLI admission or evidence of the pre-output hash contract.

## Invocation

Use a fresh unoptimized interpreter and independently qualified hashes:

```text
python -B tools/fixtures/cm3_final_join/join.py \
  --native-build <qualified-native-build> \
  --native-receipt-sha256 <qualified-native-results-sha256> \
  --native-artifacts-sha256 <qualified-native-artifacts-sha256> \
  --reference-build <qualified-reference-build> \
  --reference-receipt-sha256 <qualified-reference-results-sha256> \
  --reference-artifacts-sha256 <qualified-reference-artifacts-sha256> \
  --profile CM3 --mode O2 --output-dir <fresh-external-directory>
```

Repeat independently for the five exact modes with distinct fresh outputs.
The line continuations above are schematic, not PowerShell continuation syntax.
Admission/contract/closure controls and real ELF mutation receipts are separate
evidence classes, not additional modes or required global cells. Measured
results, source hashes and retained failed attempts belong in the qualification
record; this contract does not predict a successful execution.

## Nonclaims

Success is bounded six-root/three-mechanism composition with explicit
differences. It is not instruction, semantic, frame-value or policy equivalence;
general C/callee/kernel semantics; successful exception, MMIO or handler
execution/routing; dynamic stack/EXC_RETURN safety; complete objects; other
cohorts; FP/MPU/security; archive extraction; final LTO; CPU/board execution; or
global software freeze. Required global counters remain typed integer zero;
required-cell satisfaction and global/CPU/equivalence promotion flags remain
false. Local receipts are not hosted exact-commit CI qualification.

The gate changes no production runtime C/assembly, public/port ABI, feature
admission, default matrix, firmware or board state.
