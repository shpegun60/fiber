# C55S Staged Construction And Attachment Gate

`tools/test_m55_secure_attachment.ps1` needs explicit existing `-ArmGcc` and
WSL `-QemuRoot`; it never installs tools. Optional `-CmsisCore`,
`-FreeRtosRoot`, `-WslDistro`, and `-BuildRoot` select existing inputs.
`-DevelopmentModes` / `-DevelopmentCases` produce explicitly incomplete
receipts, not complete-suite qualification.

## Executed Inputs

The runner compiles unmodified selected C55S NS boot/attachment sources, the
actual common context-configuration guard/state, the actual pinned FreeRTOS
M55 TrustZone non-MPU/non-FP/non-MVE `port.c`, and the actual C55S Secure
identity/context gateway and bounded private pool. The fixture supplies only
platform address hooks, terminal reporting, one staged NS cohort provider,
and an instruction-level constructor caller that seeds r9. No production
runtime/provider/start/switch implementation is supplied or claimed.

The independent numeric image oracle checks all 19 words, SP geometry,
zero handle, PSPLIM, EXC_RETURN `0xffffffbc`, every GPR including live r9,
hardware frame, both context guards, complete untouched stack bytes, canary,
all boot metadata and independently computed field-wise hash. It also
executes the real pinned initializer and checks all 19 reference words and
its untouched stack. The pin enables `portPRELOAD_REGISTERS=1`: its patterned
GPR contents and odd function PC intentionally differ from Fiber's zero-fill,
captured r9 and even stacked PC. The task-return target is the sole reference
configuration override; the actual initializer is not extracted or rewritten.

The real positive boots two ELFs on QEMU TCG `mps3-an547`, enters NS Thread,
then crosses the real eight SG query veneers from production attachment.
Private Unix-socket RSP breakpoints prove all eight actual Secure body
entries in order, Thread IPSR, and exact NS return addresses derived from
the linked NS calls. All eight breakpoints remain armed, so repeats fail.
Attachment only changes the sealed request/hash; every frame/stack byte and
CPU-state field must remain unchanged.

## Labelled Failure Doubles And Controls

Failure cases deliberately replace the eight query imports with **same-state
NS test doubles**, not claimed Secure implementations. Each query has an
invalid-value case and all six CPU-state disturbances. PRIMASK, BASEPRI,
FAULTMASK, CONTROL and PSPLIM disturbances execute real register writes.
The terminal IPSR disturbance executes real NS SVC then a fixture-only
Handler-MSP continuation without exception return; this is not a scheduler
handler. Each must reach the exact panic, exact query count and unchanged
context/stack snapshot, with the disturbed register independently read back.
No fake MRS result is used. CONTROL switches to a matching PSP so execution
can reach the terminal assertion; it is not a Handler-SPSEL RAZ model.

The 119 ordinary cases include both positives, ten query-value failures,
48 query/CPU disturbances, 17 metadata failures, 18 invalid frame words
(r9 has no historical metadata oracle), 12 attachment/lifecycle failures,
and 12 invalid constructor cases. The positive checks r9 exactly; it is not
treated as an immutable value by later frame validation.

Eight compiled actual-source mutations per mode must build/link successfully
then reach exact independent assertions: wrong captured r9, removal of each
of the six CPU comparisons, and disabled reference register preloading.
Generic faults/panics/other assertions cannot satisfy these controls. Three
additional O2 compiled reporter controls must be rejected specifically for
unrelated fault, missing completion report and timeout.

Default modes are O0/O2/Os, O2/Os LTO, and O2/Os hostile instrumentation:
892 launches, including 56 compiled source mutants and three reporter
controls. Hostile flags are not cancelled on the command line; actual boot
and attachment objects must retain the exact normal undefined-symbol sets,
and final ELFs must have no undefined/instrumentation support or counters.
Every mode also requires exact failed links for missing optional lifecycle
object, stale lifecycle ABI anchor and missing staged context cohort.

Only the existing maintained RSP transport and existing QEMU inspection
script are reused. Inputs are SHA256-inventoried before/after; all native
commands, generated-code dumps, link diagnostics, QEMU logs/manifests and
receipts are retained with an artifact hash inventory. Input drift fails the
run. This is emulated staged-constructor/attachment evidence, not complete
Secure Thread execution, allocation/switching, arbitrary compiler or board
qualification.
