# Pinned Reference CM3 LTO Transport Feasibility

## Fixed Scope

This opt-in probe captures a genuine pinned FreeRTOS reference CM3 O2-lto
direct build for
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default` only. The target is
Cortex-M3/ARMv7-M, Thumb, ordinary AAPCS, soft ABI, no FPU/MPU/TrustZone, four
declared priority bits and raw BASEPRI threshold 16. It adds no runtime backend.

This is capture/build feasibility, not root preservation, canonical protocol,
source-to-machine semantics, ABI qualification or a native/reference join.
The native transport probe and its native-only admission remain unchanged.
This contract itself asserts no successful implementation or measured run.

## Independent Reference Seed

The caller supplies independently qualified SHA-256 values for the ordinary
reference CM3 O2 producer's `results.json` and `artifacts.json`. Authenticate
both complete buffers and manifest-bound inputs before parser/helper imports,
output creation or tool execution. Reject duplicate JSON keys, malformed or
partial evidence, conflicting identities, missing artifacts and hash drift.

Require the exact reference profile, cohort, ordinary O2 recipe, successful
producer closure and pin `a50edad08b29052631aa469d4df6e6ec7ff68878`.
Revalidate the retained pin/clean-status and Git blob bindings, source inventory,
original/captured identities, compiler baseline, dependencies and generated
configuration. A native seed or a matching CPU attribute is not an alternative.
Pinned bytes admit exact equality or the single permitted whole-file LF-to-CRLF
expansion only; mixed or altered bytes reject. Bind the base configuration to
`tools/fixtures/freertos_asm_parity/FreeRTOSConfig.h` and reconstruct its adapter.

Use authenticated captured bytes, never an unbound current checkout or an
ordinary object substituted for new IR. Historical originals are provenance,
not permission to replace captured inputs or qualify a later source tree.
Authenticate actual tools against admitted hashes and close all used inputs.

The fixed CLI accepts only `--reference-build`, `--reference-receipt-sha256`,
`--reference-artifacts-sha256` and `--output-dir`. No caller-selected profile,
mode, source list, plugin options or symbol allowlist is introduced.

## Four Translation Units

Preserve this source/provider order from the admitted reference recipe:

1. `freertos/portable/GCC/ARM_CM3/port.c`.
2. `tools/fixtures/cm3_final_image/reference/providers.c`.
3. `tools/fixtures/cm3_final_image/reference/consumer.c`.
4. `tools/fixtures/cm3_final_image/reference/startup.S`.

Compile the three C TUs with their exact O2 target/configuration/include flags
plus `-flto -fno-fat-lto-objects`. Each C object must contain slim IR without a
nonempty executable fallback. Compile startup with its admitted assembly recipe
unchanged; it is the sole non-IR source object. No native nine-TU recipe,
`portasm.c`, CMSIS forced header or native startup define is substituted.
Discovery and actual compilation dependencies must agree, including the exact
ARM_CM3 `portmacro.h`, generated config and captured base config providers.

Keep pinned upstream source and fixture attributes unchanged. Retain threshold
16, priority bits 4, enabled assertions and handler-installation checks. The
typed consumer retains stack-initializer/scheduler addresses and configuration
facts; taking their addresses does not prove their semantics or execute them.
Keep the original reference linker script, vectors, retained tables and padding.

## Fail-Stop Integration

`pxCurrentTCB` remains the fixture's NULL-initialized volatile handle.
`vTaskSwitchContext` and `xTaskIncrementTick` retain their typed unavailable-
kernel boundaries and enter `reference_fail_stop`, which records a code and
loops on `udf`. Reset/fault integration remains forbidden/fail-stop; it does not
start a scheduler, fabricate a valid TCB/stack or supply successful kernel work.
Keep base `configASSERT` behavior and the upstream weak timer provider intact.
No assertion disabling, new retention attributes, source repair, fake returning
provider or alias may be added to make LTO or a future reader accept the build.

## Two Genuine Links

Freeze the same ordered three IR objects and startup object before and after
each link. Use distinct fresh ordinary and emit-relocs directories, with the
same admitted reference script and ordered flags/providers. Both links invoke
LTO from IR; only output/map/temp paths and `-Wl,--emit-relocs` differ.
The fixed LTO link options include:

```text
-O2 -flto -flto-partition=one -save-temps=obj -v
-Wl,-plugin-opt=-save-temps
```

Preserve the seed's target, no-standard-library, garbage-collection,
no-undefined, fatal-warning, no-build-id and stack-permission options. Reject
counterflags, plugin bypass, foreign workers, fat fallback and archive input.
Driver `-save-temps=obj` alone is insufficient: explicit plugin retention is
mandatory. Missing actual machine output is a feasibility failure; do not
reassemble saved assembly, replay LTRANS or relink an old machine as replacement.

Require one actual LTRANS machine partition per link, structurally ELF32
little-endian ARM ET_REL, distinct from WPA IR. Capture all section headers
fail-closed and distinguish true `*.ltrans0.ltrans.o` from `*.ltrans0.o` IR.
Filename, a first glob match or a map path alone is not machine authority.
Retain all real temporaries, resolutions, partition lists, assembly, wrapper/
WPA/LTRANS arguments and response-file bytes, including flattened Windows names.
Query and bind compiler/plugin/worker paths and actual verbose invocations;
predicted commands are not execution evidence. Full argument bytes are captured,
not certified as a complete semantic IR-to-machine execution graph.

## Observed Machine Facts And Twins

Record actual machine/final symbol, section, mapping, relocation and map facts
with artifact identities. Preserve raw names, bindings, types, values and sizes.
Upstream first-start is static+naked; SVC/PendSV are global+naked. Provider
attributes differ. Capture any localization, globalization, cloning, merging,
inlining or changed reference forms without pretending source bindings survive.
Report missing/ambiguous facts; do not repair them with ordinary-owner aliases.

Keep source/IR providers separate from generated machine providers. One LTRANS
partition is not per-TU origin proof. Linker KEEP cannot restore definitions
eliminated before emission. Retain original unapplied machine REL bytes/addends
for a later adapter; this probe does not validate their applied root semantics.

Compare both final load images through authenticated frozen parser/helper bytes:
PT_LOAD geometry/bytes, allocated/vector bytes and entry must agree. Record
`TwinLoadImageCompared=True` and `TwinLoadImages.Identical=True` only after the
comparison succeeds. Bind saved comparison evidence before the first seal and
repeat its exact path/hash/value checks afterward; a changed or deleted file
cannot be legitimized by resealing altered output.

## Closure And Nonclaims

Before mkdir, deny either-direction overlap between output and the repository,
seed, original/captured inputs, inventory, reference checkout and tool/config
roots. Derive denials from authenticated buffers; check resolved ancestors and
reject physical aliases and reparse escapes before creating any directory.
Use the hardened contained process runner and sanitized process environment.
Record commands before launch, failures/timeouts and complete child cleanup.
Capture interpreter, actual workers/plugin/linker, DLLs, specs and executed
helper/parser bytes; nested imports execute those same authenticated buffers.
Close seed/source/tool/dependency/object/temp memberships and hashes after both
links and at sealing, including exact output membership. Late faults persist
FAIL rather than promoting success. Preserve failed attempts without relabeling.

Required-cell and global credit remain exact typed integer zero. Root/protocol,
full ABI, source-to-machine semantic/per-TU origin, policy, kernel/CPU/hardware,
native/reference join, archive, other modes/cohorts and global qualification
remain false. Structural twin equality does not change those boundaries.
No ordinary reader, production source, public ABI or default matrix is changed.
