# Native CM3 LTO Fresh-Link Controls

## Fixed Scope

This separate gate covers native CM3 O2-lto direct linkage for
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default`: Cortex-M3,
ARMv7-M Thumb, ordinary AAPCS, soft ABI, no FPU/MPU/TrustZone, VTOR1,
four declared priority bits and raw BASEPRI threshold 16.

The positive control supplies one strong application `fiber_panic` as genuine
slim IR alongside the admitted eight native C IR inputs and unchanged startup
object: ten TUs, nine IR objects and one native assembly object. Two fresh LTO
links form ordinary and emit-relocs twins. Two separate negative controls add
a competing strong SVC or PendSV definition to the original baseline.

This document specifies acceptance obligations, not an implementation, test or
qualification PASS. Existing default-panic images cannot establish these fresh
link outcomes. No production runtime, attributes, frozen reader or matrix changes
are authorized by this contract.

## Admission And Command Closure

Authenticate caller-bound source-capture receipt and artifact buffers before
helper imports, output creation or tool execution. Require the fixed successful
native capture, exact eight slim-IR identities plus startup, source/configuration
bindings, target recipe and captured tools. Verify complete input/artifact
membership, hashes and physical identities; reject conflicting bindings,
reparse escapes and unintended aliases. Fresh output must not overlap admitted
inputs, original source/tool trees, repository or earlier evidence directories.

For every new compile/link command, retain exact ordered argv, sanitized
environment, working directory, prelaunch record, stdout/stderr, exit outcome,
resolved compiler/plugin/workers and relevant DLL hashes. Use the maintained
contained process runner, including abnormal-exit/timeout descendant cleanup.
Only host compiler/linker and inspection tools execute; no resulting program,
emulator, target or board executes.

Compile each added C provider with the admitted CM3 flags plus O2, `-flto` and
`-fno-fat-lto-objects`. Capture its literal source, declarations, configuration,
actual dependencies and output hash. Verify genuine slim IR without executable
fat fallback. Preserve the eight baseline IR inputs and startup byte-for-byte;
freeze all link inputs before and after every link and again at closure.

Both successful links use exactly the same ordered ten objects and captured
script, retaining the baseline providers' relative order. The additional IR's
position is fixed and recorded, not selected by a caller. Use the qualified
target/link recipe, including `-flto-partition=one`, `-save-temps=obj`, `-v`,
`-Wl,-plugin-opt=-save-temps`, no undefined symbols and no build ID. Apart from
private output/map/temp names, only the emit twin adds `--emit-relocs`.
No archives, ordinary-object panic substitute, IR bypass, replayed assembly or
reconstructed machine object is allowed.

## Strong Application Panic

The added provider includes the existing context-owned declaration and defines
exactly typed `void fiber_panic(char code)` with the admitted noreturn/sensitive
attributes and no weak definition. Its fixture body is fail-stop, not a usable
application or exercised runtime handler. Keep the bundled weak fallback IR
present; deleting it does not test override resolution.

Each genuine twin must succeed independently and retain the complete actual
plugin resolution file, wrapper/WPA/LTRANS arguments, response files, saved
assembly, one real post-LTO machine partition, map and final ELF. A WPA IR
`*.ltrans0.o` is not the native `*.ltrans0.ltrans.o` authority. Require ELF32
little-endian ARM machine/final metadata and the fixed soft CM3 attributes.

Bind `.res` entries to their exact input-object identities. The fallback's
`fiber_panic` definition must be preempted by IR (`PREEMPTED_IR`), and the
application IR must supply the unique prevailing definition. Retain the literal
prevailing status and all relevant reference records; missing, ambiguous or
contradictory resolution rejects. Final GLOBAL binding alone is not override
proof: the earlier default-only image already globalized its weak definition.

Independently bind the resulting unique strong GLOBAL Thumb `fiber_panic`
definition from the actual generated machine section/offset/positive extent
through a unique full map placement to its final definition. Require executable
storage/load, exact placement and no positive-size alias or overlapping function.
Preserve raw symbol metadata and each twin's original machine identity.

Enumerate original named machine call/tail relocations to `fiber_panic`, retain
their actual kinds, sites, bytes and decoded addends, and validate all resulting
final branch targets against that same map-bound definition. Require nonempty
coverage; a symbol-table name, map printout or decoded destination alone is not
sufficient. Validate applicable residual REL records in the emit twin without
requiring them in the ordinary twin. Do not force all call sites through a
BL-only decoder when an actual tail transfer uses a different supported form.

The resolution-to-IR and machine-to-final checks are distinct authorities.
Neither reconstructs a per-TU machine owner or proves the semantics of IR
lowering. The extra IR may change whole-program layout, sizes and symbol
bindings; do not compare them to old default-only addresses or silently promote
old root/protocol records. Existing two-provider readers remain unchanged.

Compare genuine twins' PT_LOAD geometry/bytes, entry and allocated/vector
sections with the frozen structured comparator, retaining its evidence.
This equality does not substitute for either link's resolution/origin checks.

## Intended Duplicate-Handler Failures

Use two isolated controls: one new slim-IR TU defines strong `SVC_Handler`,
and another independently defines strong `PendSV_Handler`. Each is linked
separately with the original eight IR inputs and startup; neither replaces the
production handler or includes the positive panic override. Each case therefore
has ten TUs, nine IR objects and one startup object. Compilation of the added
provider must succeed before its link can count as a negative control.

Each link must fail with a recognized multiple-definition/duplicate-definition
diagnostic naming exactly its intended handler as the collision. Bind the
competing provider identities and keep the original handler provider present.
A nonzero exit alone, echoed argv/path text, missing symbol/tool, syntax error,
unrelated linker error, crash, timeout or containment failure is not control PASS.
A successful duplicate-handler link is control FAIL. Do not accept a stale final
ELF or preexisting diagnostics as the failed command's output.

The minimal complete batch has two successful twin links and two intended failed
links. Preserve every attempted command and its actual exit status. An expected
link-command FAIL becomes control PASS only after its exact collision evidence
and closure validate; never relabel the command itself as successful. Failed
attempts/reruns remain separate and cannot repair earlier receipts in place.

## Closing Evidence And Nonclaims

Retain all newly used source/configuration/tool inputs, exact provider order,
IR/startup hashes, complete private temporary trees, raw plugin resolutions,
machine/final files, maps, inspection outputs and structured validation evidence.
Close input hashes, physical bindings and directory memberships after commands,
before sealing and after sealing. Bind generated proof files before their first
seal; a late change cannot be legitimized by simply resealing modified bytes.
Persist FAIL and a consistent receipt/artifact manifest on closure/seal failure.

Report positive and negative counts separately, along with actual command exits.
No partial success grants batch PASS. Required-cell/global credit remains typed
integer zero; global freeze and full ABI, source/IR semantics, complete-object,
canonical root/protocol, native/reference parity, policy/kernel, archive,
other-mode/cohort, CPU/board and hardware claims remain false or unproved.
Identity-mismatch and reverse-ABI link controls are outside this slice.
