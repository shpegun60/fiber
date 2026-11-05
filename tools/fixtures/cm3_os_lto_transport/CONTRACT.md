# CM3 Os-LTO Transport Capture

## Scope

This is a capture-feasibility contract, not a measured result or a root/parity
qualification. Each invocation selects exactly one side, native or pinned
FreeRTOS reference, for the fixed CM3 p4/BASEPRI16 soft-float direct-link cohort.
The two sides require separate ordinary O2 seed receipts and artifact-manifest
SHA256 values. One side's receipt is never authority for the other side.

Successful capture means fresh genuine Os-LTO inputs, two actual final links,
one retained machine partition per link, closed provenance, and identical
loader-visible twins within that side. It does not mean native/reference
instruction equality, scheduler equivalence, or a qualified seven-mode grid.

## Seed And Source Admission

Authenticate the caller-bound receipt and artifact-manifest buffers, then all
consumed seed inputs, source/configuration bytes, inventory, tools and helpers.
Require the exact ordinary O2 target, source group, compiler flags and provider
order. Preserve the seed records as O2 evidence; do not relabel old objects or
old machine code as Os output. Admit fresh output outside source/input trees
before creating it. Helper execution uses authenticated immutable source
buffers, including nested local loads; fixed helper pins are not mutable paths.

The native group has exactly nine ordered translation units:

1. `context/context_core.c`
2. `context/context_runtime_state.c`
3. `context/context_panic.c`
4. `fiber/port/ARM_CM3/fiber_port.c`
5. `fiber/port/ARM_CM3/fiber_port_boot.c`
6. `fiber/port/ARM_CM3/fiber_port_exception.c`
7. `fiber/port/fiber_port_context_cohort_expectation.c`
8. `classic_final_image/application.c`
9. `classic_final_image/startup.S`

The reference group has exactly four ordered translation units: the pinned
FreeRTOS `portable/GCC/ARM_CM3/port.c`, followed by
`cm3_final_image/reference/{providers.c,consumer.c,startup.S}`. The fixture paths
above are relative to `tools/fixtures` where not already repo-relative. Preserve
the pinned source/configuration and typed failstop integration, not invented
kernel implementations or scheduler semantics.

## Exact Optimization Transform

Every admitted compile argv, including startup, contains exactly one `-O2`.
Replace that token in place with `-Os`; retain all other seed flags, defines,
includes, target/ABI facts and ordering. Reject counteracting optimization/LTO
options. Add `-flto -fno-fat-lto-objects` to the eight native or three reference
C compilations. Startup remains a native assembly object, also built with `-Os`.
Actual compile dependencies must equal the authenticated seed dependency set,
with only the recorded relocation of captured toolchain headers.

Link the newly compiled inputs in the admitted provider order and exact script
recipe. The optimization transform is also mandatory at link time. Retain
`-flto -flto-partition=one -save-temps=obj -v` and the explicit plugin retention
option `-Wl,-plugin-opt=-save-temps`. Do not substitute an old O2 machine object,
fat-object fallback, reconstructed assembly, or a replayed assembler output.

## Actual Twins And Machine Evidence

Each side produces ordinary and `--emit-relocs` images in separate fresh private
directories. Differences are limited to the emit-relocs option and necessary
output/map/private-directory names. These are two links per side, four links
when both independent sides are captured, not four qualified root proofs.

Retain the complete actual link directories: maps, `.res`, verbose streams,
wrapper/WPA/LTRANS arguments and response files, saved assembly and other temps.
Require exactly one actual `image.elf.ltrans0.ltrans.o` machine partition per
link. The similarly named `.ltrans0.o` WPA IR is not machine authority.
Account for every ELF section-header row. Require ELF32 little-endian ARM
ET_REL slim inputs and real machine code, no executable fat fallback or GIMPLE
masquerading as the retained machine, and actual final executables.

Capture raw root/callee/current-slot symbol facts without imposing ordinary/O2
binding, extent, address or weak/global assumptions on Os output. Do not
normalize raw section-symbol names. Retained resolution rows and argument files
are capture evidence, not a source-IR semantic proof or an already qualified
Os resolution grammar; old O2 symbol/row counts are not acceptance constants.

Use the authenticated unchanged twin comparator for PT_LOAD geometry/bytes,
entry and allocated/vector sections. Bind its returned evidence before sealing.
Equality is within each side only, not between native/reference or O2/Os.

## Closure And Failure

Reuse the hardened contained process runner, explicit sanitized environment,
prelaunch/failure command records, and observed compiler/plugin/worker/DLL byte
bindings. Freeze source/tool/input and object hashes before and after links.
Pin consumed/generated evidence before interpretation. Close exact artifact
membership, hashes and applicable physical identities, including helper/parser
sources and comparison evidence, through final and late manifest checks.
Drift, missing evidence or a failed command cannot promote partial capture;
retain a consistent FAIL receipt and manifest when output was safely admitted.

## Qualification Still Required

Independently validate each real Os machine-to-final transport: complete root
bytes, mapping/pools, original REL/addends, decoded targets, slot and map origins.
Then compare those same actual machine bodies through the canonical protocol
decoder/checker, with actual-byte and coherent-preservation negative controls.
Finally compose the six real bodies through the paired mechanism checker and
captured difference ledger. Unsupported Os forms must reject; do not relax
frozen ordinary/O2 checks or fabricate another side to obtain acceptance.

Capture PASS leaves root/protocol/parity/full-ABI/source-IR/whole-object/policy,
CPU/hardware, archive, global-freeze and required-cell qualification false.
Required-cell credit remains literal integer zero. No runtime changes or CPU
execution are part of this capture; seven-mode aggregation is a later gate.
