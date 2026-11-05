# Native CM3 LTO Private-Cohort Controls

## Bounded Architectural Claim

This opt-in link experiment varies only the selected CM3 scheduler BASEPRI
threshold between decimal 16 and 32 at declared priority bits 4. Both satisfy
the existing nonzero, eight-bit and implemented-priority-bit checks. Other
target, layout, feature, public storage and ABI identities remain unchanged.
This document specifies obligations, not an implementation or measured PASS.

The intended result is exact private-policy cohort rejection under genuine
O2-lto direct linkage. It does not test storage-revision or reverse-ABI-version
mismatch, establish a new inventory cohort, or prove interrupt masking at runtime.
The existing `cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default`
receipt remains historical authority; the 32 variant is a bounded test fixture.

## Exact Source Split

Use the authenticated native CM3 LTO capture's nine-source order:

| Index | Provider | Treatment |
| --- | --- | --- |
| 0 | `context/context_core.c` | Reuse unchanged IR |
| 1 | `context/context_runtime_state.c` | Reuse unchanged IR |
| 2 | `context/context_panic.c` | Reuse unchanged fallback IR |
| 3 | `fiber/port/ARM_CM3/fiber_port.c` | Runtime identity owner; compile 32 variant |
| 4 | `fiber/port/ARM_CM3/fiber_port_boot.c` | Private-key consumer; compile 32 variant |
| 5 | `fiber/port/ARM_CM3/fiber_port_exception.c` | Private-key consumer; compile 32 variant |
| 6 | `fiber/port/fiber_port_context_cohort_expectation.c` | Build expectation; compile 32 variant |
| 7 | `tools/fixtures/classic_final_image/application.c` | Reuse unchanged public consumer IR |
| 8 | `tools/fixtures/classic_final_image/startup.S` | Reuse unchanged native object |

Retained actual dependencies for indices 0, 1, 2 and 7 contain none of
`fiber_port_private.h`, `fiber_portmacro.h` or `fiber_port_context_cohort.h`.
The application uses public complete types and the storage expectation, not
the private scheduler policy. Its retained resolution records reference
`fiber_port_storage_cohort_arm_cm3_v1_r0`, unchanged by this threshold variation.
Reuse is specific to these actual source/dependency/object bytes, not a general
claim that every Context consumer is independent of every selected-port option.

Recompile only indices 3 through 6 from the same captured C/header bytes.
Replace the single canonical `-DFIBER_SCHEDULER_BASEPRI=16` with
`-DFIBER_SCHEDULER_BASEPRI=32` in each original compile argv; do not append a
second definition or supply a conflicting `FIBER_PORT_SCHEDULER_BASEPRI`.
Preserve all other flags, generated CMSIS facts, includes, layout headers and
dependencies. Require successful compilation and real slim IR with no native
fallback. Neutral reused IR retains its original recorded flags, including 16;
do not relabel those objects as freshly compiled with 32.

Each complete link still has nine TUs: eight C IR objects plus native startup.
There is no additional panic override or handler fixture. Runtime defines the
sole private key and unchanged storage key. Boot and exception retain volatile
private-key reads; the expectation retains its key pointer. Preserve the exact
linker script and KEEP of `.fiber_port_context_cohort_expectation` so GC/LTO
cannot turn a missing guard into a successful link.

## Exact Keys And Eight Swaps

Let C16 be the complete original private key. C32 differs only in its eight
encoded BASEPRI bits: `_u00010000` becomes `_u00100000`. Derive and retain both
complete symbol names from the admitted source/IR authority; acceptance of a
missing-symbol diagnostic must compare the full exact key, not this substring.
Port ID, private layout ID, P4 field and every other key field must agree.

Produce fresh matching-16 and matching-32 ordinary/emit-relocs pairs with fixed
provider order, script and semantic link flags. Retain the old matching-16
receipt separately, not as a substitute for this batch's fresh positive links.
Both pairs must link successfully before the eight negatives can qualify.

For each negative, replace exactly one selected object in an otherwise matching
set. Reuse neutral objects unchanged; do not introduce duplicate providers.

| Matching Base | Single Swapped Object | Expected Undefined Identity |
| --- | --- | --- |
| 16 | Runtime from 32 | C16 |
| 16 | Boot from 32 | C32 |
| 16 | Exception from 32 | C32 |
| 16 | Expectation from 32 | C32 |
| 32 | Runtime from 16 | C32 |
| 32 | Boot from 16 | C16 |
| 32 | Exception from 16 | C16 |
| 32 | Expectation from 16 | C16 |

Runtime swaps replace the only definition, leaving the base's other consumers
unresolved. Other swaps introduce one foreign consumer while the base runtime
still defines only its own key. That asymmetry is intentional. The complete
batch has four successful positive links and eight intended failed links.

## Link And Diagnostic Boundary

Preserve CM3 soft target flags, O2, genuine LTO, single-partition retention,
direct provider order, GC/no-undefined/fatal-warning policy and no-build-ID
recipe. Positive twins retain `-v` and actual verbose tool traces. Negative
links use one fixed ordinary-link recipe and remove only `-v` from that recipe.
Record this verbosity-only argv difference explicitly; do not remove semantic
CPU/optimization/LTO/GC options or claim a per-negative verbose worker trace.
Removing driver verbosity keeps echoed commands and worker details outside the
strict intended-undefined-identity diagnostic grammar.

Every negative requires a completed nonzero link exit, no timeout/containment
fault, absent final ELF and actual undefined-reference diagnostics for exactly
the table's missing complete key. Repeated references to that same key are
allowed; other undefined identities, compile errors, missing tools, unrelated
link errors or mere echoed names are not control PASS. Preserve command FAIL
separately from expected-control PASS. No successful mixed link may promote.

Retain the positive IR symbol/resolution evidence identifying the sole private
definition and selected consumers, plus actual machines, finals, maps and raw
plugin files. Positive resolution input sets have eight IR providers, not the
nine-provider override grammar. Compare twins within each matching policy only;
16 and 32 are not asserted to have equal final bytes or scheduler protocols.
Frozen fixed-b16 audit/protocol predicates remain unchanged and grant no b32
root, canonical-protocol or full-ABI qualification in this experiment.

## Capture Closure And Nonclaims

Bind the source capture, tools/helpers, exact compile/link argv, actual raw
dependencies, IR/startup hashes, environment and command JSON/stdout/stderr.
Use the maintained contained host runner and safe fresh external output.
Freeze consumed inputs and generated evidence before consumption, retain all
private temporary artifacts and close hashes, memberships and physical
identities before and after sealing. Persist failures and consistent manifests;
counts or receipt status alone are not intended-failure evidence.

No source/layout edit or new storage identity is needed for this control. The
unchanged storage revision and reverse-v1 anchor are not tested mismatch axes.
Full ABI, source/IR semantics, whole-object correctness, other modes/cohorts,
archives, kernel/priority behavior and CPU/board/hardware proof remain false or
unproved. Required-cell/global credit stays typed integer zero; global freeze
stays false. No production or frozen reader/checker changes follow.
