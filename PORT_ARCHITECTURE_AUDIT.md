# Port Architecture And FreeRTOS Audit

## Historical Snapshot And Verdict

Reviewed on 2026-11-01:

```text
Fiber:    5c34785088e3496540a8dcbec1351fac241e11ca
FreeRTOS: a50edad08b29052631aa469d4df6e6ec7ff68878
Compiler: STM32CubeIDE GNU Arm GCC 14.3.1
Scope:    all present port families, common boundaries, and validation tools
```

The common/selected-port separation is suitable for the intended static-lifetime,
single-core STM32 profiles. It does not need a new CPU-specific branch in common
for each MPU, FP, MVE, or SecureContext cohort. The current software checkpoint
nevertheless has concrete execution and protection defects at that reviewed SHA. It is not ready for
software freeze or for a claim that every implemented port runs correctly.

Every finding below is OPEN at the reviewed SHA. That is the historical audit
baseline, not the status of the subsequent repair tree. The remediation record
at the end of this document identifies the implemented corrections and their
maintained regressions. Neither record qualifies hardware.

## Scope And Evidence

Six independent review lanes covered:

| Lane | Sources |
| --- | --- |
| Privileged classic | ARM_CM0, ARM_CM3, ARM_CM4, ARM_CM7/r0p1 |
| Classic MPU | ARM_CM0_MPU, ARM_CM3_MPU, ARM_CM4_MPU |
| NTZ and FP/MVE | ARM_CM23_NTZ, ARM_CM33_NTZ, ARM_CM33F_NTZ, ARM_CM55_NTZ, ARM_CM55F_NTZ, ARM_CM55_MVEF_NTZ; transitional_v8m containment |
| M33 protected/security | ARM_CM33_MPU, ARM_CM33 Non-secure/Secure, ARM_CM33_TFM, optional configuration lifecycle |
| M55 protected/security | ARM_CM55_MPU, ARM_CM55F_MPU, ARM_CM55_MVEF_MPU, staged ARM_CM55 Non-secure/Secure |
| Architecture | public API/types, eight forward operations, reverse ABI, lifecycle, selection, optional extensions, cohort guards, later Context extraction |

The parent independently ran the complete existing `tools/compile_matrix.ps1`
against this tree: PASS, including actual pinned FreeRTOS/Fiber generated-code
comparison at `-O2` and `-Os`, current ABI/cohort/archive/CMSE/vector checks,
and existing normal/LTO and negative fixtures.

Additional evidence includes source/control-flow inspection, actual GCC stdout
assembly probes, compiler dependency output for the Secure reference, and Arm/ST
architecture documentation. The parent independently reproduced the optimized
CM0 address-zero trap from the actual boot source. An independent reviewer also
linked both mixed-build cases in A15/A16 using real sources and archives, with
GC and with/without LTO. No board or emulator was run. Source deductions below
are not reported as measured target execution.

The existing assembly signatures prove selected ordered operations. They do not
execute the C guards around those operations, prove every branch, or establish
equivalence of the whole implementation. Several signatures currently accept or
even require incorrect added validation. A matrix PASS therefore coexists with
the execution defects in this report.

Relevant architecture sources:

- [ST AN4838, MPU overview](https://www.st.com/content/st_com/en/technical-documents/an4838-introduction-to-memory-protection-unit-management-on-stm32-mcus-stmicroelectronics_asset/chunk-001-topic-an4838-overview.html): Armv8-M region-overlap restrictions.
- [Arm Cortex-M33 Generic User Guide](https://documentation-service.arm.com/static/5f16e93d20b7cf4bc524af1d): CONTROL.SPSEL in Handler mode, exception frame geometry, and MPU multiple matches.
- [Armv8-M Exception Model User Guide](https://community.arm.com/cfs-file/__key/communityserver-discussions-components-files/471/armv8_2D00_m_5F00_exception_5F00_model_5F00_user_5F00_guide_5F00_107706_5F00_0100_5F00_01_5F00_en.pdf): FPCA/EXC_RETURN and lazy preservation transitions.

Line numbers below refer to the reviewed SHA. Reference paths are relative to
`_reference/FreeRTOS-Kernel`.

## P1 Execution And Protection Findings

### A01: Nested PRIMASK Makes M55 FP MPU Startup Fail

Locations: `ARM_CM55F_MPU/non_secure/fiber_port_svc.c:145,200,219` and
`ARM_CM55_MVEF_MPU/non_secure/fiber_port_svc.c:145,200,219`.

`configure_first_start_exceptions()` disables interrupts, then reaches a priority
probe that saves PRIMASK and requires its prior value to be zero. That value is
necessarily one inside the outer critical section. Valid startup panics `'p'`.

Preserve nesting in the probe or perform it before the outer critical section.
Regression: execute successful `runtime_prepare_start()` with normal initial
masks, and exercise the probe under both initial PRIMASK values. Reference:
`portable/GCC/ARM_CM55_NTZ/non_secure/port.c:2166` priority setup.

### A02: Armv8-M MPU Current Aperture Overlaps Privileged SRAM

Locations: `ARM_CM33_MPU/non_secure/fiber_port_boot.c:250`,
`ARM_CM55_MPU/non_secure/fiber_port_boot.c:247`,
`ARM_CM55F_MPU/non_secure/fiber_port_boot.c:306`, and
`ARM_CM55_MVEF_MPU/non_secure/fiber_port_boot.c:307`.

The linker checks require the current-slot aperture to lie inside privileged
SRAM. The port enables both enclosing region 3 and aperture region 5. Accessing
the slot consequently matches two regions. Armv8-M faults on such overlaps;
the Armv7-M highest-region-priority policy cannot implement this overlay.

Keep the RO/XN aperture disjoint from the privileged-RW mapping, preferably at
its boundary, and update linker manifests and startup-zeroing requirements.
Regression: decode every enabled region and reject pairwise overlaps for all
8/16-region cohorts; test current-slot reads and publication with MPU enabled.
The pinned CM33/CM55 reference global maps do not contain this Fiber overlay.

### A03: Handler Checks Require Thread CONTROL State

Representative locations:

```text
ARM_CM33_NTZ/non_secure/fiber_port.c:351
ARM_CM33F_NTZ/non_secure/fiber_port.c:428
ARM_CM55_NTZ/non_secure/fiber_port.c:351
ARM_CM55F_NTZ/non_secure/fiber_port.c:120
ARM_CM55_MVEF_NTZ/non_secure/fiber_port.c:121
ARM_CM33/non_secure/fiber_port_secure_context.c:219,253,293
ARM_CM33_TFM/non_secure/fiber_port.c:356
ARM_CM33_MPU/non_secure/fiber_port.c:554
ARM_CM55_MPU/non_secure/fiber_port.c:554
ARM_CM55F_MPU/non_secure/fiber_port_pendsv.c:232
ARM_CM55_MVEF_MPU/non_secure/fiber_port_pendsv.c:235
```

At the audited revision, these entry guards require SPSEL=1, through CONTROL
values 2 or 3. Exception entry clears SPSEL in the targeted bank, so an ordinary
PendSV/SVC entry fails those guards. This does not apply to post-write restore
checks: privileged Armv8-M Handler code can write SPSEL and must read back the
written value even though Handler execution continues using MSP. SG is not
exception entry and does not normalize the other CONTROL bank. FP variants also
confuse interrupted FP state with the Handler's live FPCA state.

Use EXC_RETURN for interrupted stack/frame identity. Distinguish live Handler
CONTROL, the synthetic first-start template, and a saved CONTROL value. Correct
all C and assembly consumers together; preserve valid Thread-only API checks.
Regression: first yield, same-context selection, alternating contexts, and basic/
extended exception entry followed by verified Thread/PSP return. Reference:
CM33/CM55 `portasm.c` saves actual Handler state and uses exception-return state.

### A04: MPU Restore Rejects Its Own Yield Continuation

Locations: `ARM_CM33_MPU/non_secure/fiber_port.c:500`,
`ARM_CM55_MPU/non_secure/fiber_port.c:500`,
`ARM_CM55F_MPU/non_secure/fiber_port_pendsv.c:150`, and
`ARM_CM55_MVEF_MPU/non_secure/fiber_port_pendsv.c:153`.

SVC 71 pends PendSV. Tail-chaining preserves the Thread continuation at
`fiber_port_svc_yield_return_site` inside syscall flash. Restore accepts ordinary
application flash and explicitly rejects syscall flash, so resuming this valid
context panics `'c'`.

Accept the exact owned yield continuation while retaining restrictions against
arbitrary syscall addresses. Regression: public yield with scheduler-returning-
current and A-to-B-to-A selection. Reference: protected FreeRTOS restore accepts
the hardware frame containing the legitimate yield continuation.

### A05: Scalar MPU Preflight Compares Live PSP To Historical PSP

Locations: `ARM_CM33_MPU/non_secure/fiber_port.c:301` and
`ARM_CM55_MPU/non_secure/fiber_port.c:301`.

`image->psp` still contains the previous save/initialization address. A later
yield from a different call depth has another valid live PSP. Requiring equality
panics before the handler records the new address.

Validate live PSP against sealed bounds and frame extent. Regression: nested
non-tail-called yields at several depths. Reference: `portasm.c:298` samples
live PSP before storing the new protected image.

### A06: M55 FP MPU SVC Uses The Wrong Extended Core-Frame Offset

Locations: `ARM_CM55F_MPU/non_secure/fiber_port_svc.c:358` and
`ARM_CM55_MVEF_MPU/non_secure/fiber_port_svc.c:358`.

`running_svc_core_frame()` adds 72 bytes for an extended hardware frame, then
decodes PC/xPSR there. The core registers are at the frame base; low FP state
follows them. PC/xPSR checks consequently consume FP extension words.

Keep the core base at raw PSP and include FP bytes only in total-extent checks.
Regression: extended SVC with different core, FPSCR, and reserved/VPR sentinels.
Reference: `ARM_CM55_NTZ/non_secure/portasm.c:531` decodes PC at frame+24.

### A07: Runtime M55 FP MPU SVC Rejects Pending Lazy Preservation

Locations: `ARM_CM55F_MPU/non_secure/fiber_port_svc.c:631` and
`ARM_CM55_MVEF_MPU/non_secure/fiber_port_svc.c:631`; readiness implementation
in each `fiber_port_boot.c:31`.

With lazy FP enabled, FP use followed by SVC can legitimately enter with LSPACT=1.
Runtime SVC calls startup `fpu_require_ready()`, which demands LSPACT=0, and
panics `'E'` before normal preservation can complete.

Use the runtime configured-policy check at this stage. Keep first-start readiness
strict. Regression: FP/MVE activity immediately followed by public yield in eager
and lazy modes. Reference: the conditional FP transfers in protected FreeRTOS
PendSV permit normal lazy preservation.

### A08: Runtime M55 FP MPU SVC Reads The Inactive Basic Union View

Locations: `ARM_CM55F_MPU/non_secure/fiber_port_svc.c:369` and
`ARM_CM55_MVEF_MPU/non_secure/fiber_port_svc.c:369`.

After an extended save/restore, basic-view `cursor_limit` aliases saved S4 and
basic-view PSPLIM aliases saved S1. Runtime SVC treats these as invariant metadata.
Ordinary FP values then cause `'P'` or `'L'` panic.

Validate live PSPLIM and the active protected representation/cursor. Regression:
extended save, restore, and another SVC with nonzero S1/S4. The overlapping
54-word FreeRTOS representation itself is intentional and should remain.

### A09: VTOR-Less CM0 Address-Zero Read Becomes An Undefined Instruction

Location: `ARM_CM0/fiber_portmacro.h:277`, reached by boot MSP planning with
default `FIBER_REWIND_MSP=1`.

`vectors[0]` dereferences a compiler-visible constant null pointer. Actual GCC
14.3 output from the boot source at optimized settings includes `ldr [0]`
followed by `.inst 0xdeff`. A valid vector table mapped at zero does not make
the C null dereference defined.

Use an explicit assembly word read or an explicit no-rewind policy. Regression:
actual optimized no-VTOR boot code, including M0+ without VTOR, must not contain
the generated unconditional trap on the valid path. Reference:
`ARM_CM0/portasm.c:222` intentionally preserves MSP.

### A10: CM0 MPU Compares r9 Across Unrelated Compiler Frames

Location: `ARM_CM0_MPU/fiber_port_boot.c:636`.

Initial restore validation compares the seeded r9 with a later live r9. Ordinary
AAPCS permits each C function to use r9 and restore its caller's value on return.
The reviewed optimized constructor actually used r9 for a context-derived
temporary. This equality can reject a valid first context with `'x'`.

Remove the cross-frame equality for the general-register ABI. A platform/static-
base policy needs an explicit consistently reserved-register contract. Regression:
real constructor/validator call chains without `-ffixed-r9`, including register
pressure. FreeRTOS seeds registers without requiring later live-r9 equality.

### A11: CM0 MPU Accepts An Unprivileged-Writable Active Vector Table

Location: `ARM_CM0_MPU/fiber_port.c:129`.

Vector validation compares initial handler addresses but does not prove table
protection. A VTOR table within a context's writable stack can initially pass.
The unprivileged context can then change an SVC vector and obtain attacker-chosen
privileged Handler execution in executable application flash.

Require active-table placement in protected memory before dereferencing vectors.
Regression: reject VTOR inside an otherwise valid user stack even when handler
slots initially match. The pinned CM0 reference also lacks this stronger placement
check; matching the reference does not establish MPU isolation here.

## P2 Validation And Build-Protection Findings

### A12: M55 FP MPU Preflight Reads xPSR Before Establishing Frame Bounds

Locations: `ARM_CM55F_MPU/non_secure/fiber_port_pendsv.c:253` and
`ARM_CM55_MVEF_MPU/non_secure/fiber_port_pendsv.c:256`.

`core_frame[7]` is read before overflow/stack-range checks. An invalid live PSP
can fault during validation instead of reaching the intended controlled panic.
Prove minimum core-frame extent first, then read xPSR and validate full extent.
Regression: instrument memory accesses for out-of-range/inaccessible frames.

### A13: Classic-Port Canary Lies Outside The Address-Validated Range

Representative location: `ARM_CM7/r0p1/fiber_port_boot.c:405,569`; the same
construction pattern exists in ARM_CM0, ARM_CM3, and ARM_CM4.

RAM hooks validate normalized usable stack bounds. The canary is written below
those bounds, at aligned raw begin. An invalid raw prefix can be hidden by
red-zone normalization and still receive a write. For example, approved RAM can
start at 0x20000000 while raw begin is 0x1FFFFFF0 and normalized base is valid.

Validate the raw allocation or the exact canary cell before access, and include
that cell in enabled switch-time map validation. Regression: reject a raw prefix
outside RAM before any canary write/read. FreeRTOS has no equivalent Fiber canary.

### A14: Weak MSP-Fallback Declaration Weakens Application Overrides

Representative location: `ARM_CM7/r0p1/fiber_port_boot.h:32`; also present in
the classic CM0/CM3/CM4 declarations.

An ordinary application definition after the weak declaration inherits weak
linkage, as confirmed by GCC output. The bundled zero-return definition can win
by link order. Keep the declaration strong and only the default definition weak.
Regression: actual override resolution in reversed object orders and archives.

### A15: Split CM33 SecureContext Handlers Lack Their Own Identity Guard

Location: `ARM_CM33/non_secure/fiber_port_svc.c:8,387`.

The constant bundle anchor forces archive extraction but does not retain the
reverse ABI version or exact context cohort. A handler compiled with another
BASEPRI threshold can accompany fresh runtime/boot/expectation objects without
requiring its original cohort. Its hard-coded mask then disagrees with the bridge.

Add a retained one-shot component guard for both identities, following the
CM55F/MVEF MPU PendSV components. Regression: stale-handler threshold and reverse-
version negative archive links, including section GC and LTO. Extraction and
compatibility must remain separate proofs.

Actual links accepted a handler compiled for BASEPRI 0x20 with runtime, boot,
attachment, and expectation compiled for 0x10, at `-O2` and `-O2 -flto`.
Disassembly retained the handler's 32 and the bridge's expected 16. These ELFs
had no undefined symbols and retained strong handlers and correct vector slots.
Deliberately stale expectations failed on the intended missing cohort symbol.

### A16: Public Allocating Objects Are Not Bound To Storage Cohorts

Locations: `fiber/fiber_core.c:20`,
`fiber/port/fiber_port_context_cohort_expectation.c:11`, and
`ARM_CM33_MPU/non_secure/fiber_port_types.h:94`.

The expectation object proves the cohort expected by its own compile settings,
not the settings used by each object allocating `FiberContext`. A stale consumer
compiled with eight MPU regions allocates 216 bytes; a fresh sixteen-region
initializer expects 280. Neither its `fiber_init` reference nor current type-only
headers bind the stale object to its storage identity. SRAM plausibility cannot
prove the caller's actual allocation extent.

This is a gap in the stronger stale-build protection, not a same-manifest layout
failure. Correctly configured clean builds remain the required integration
contract, as in FreeRTOS static task allocation. Add a type-only storage identity
relocation or another explicit caller-storage contract before claiming detection
of stale application objects. Regression: stale C/C++ allocating consumers versus
fresh matching port/expectation, including GC/LTO.

Actual links of an eight-region consumer with a sixteen-region runtime/archive
and expectation succeeded at `-O2` and `-O2 -flto`. The final images retained
216-byte context objects and an initializer with a four-byte store at offset
276. Matching controls succeeded; stale expectation controls failed on the
intended missing cohort. The images were inspected, not executed.

### A17: Secure Pool Sensitive-Code Evidence Does Not Cover Its Full Call Graph

Location: `ARM_CM33/secure/fiber_secure_context_pool.c:161` and reachable helpers.

The pool does not carry the canonical sensitive bundle. Adversarial GCC flags can
generate profiling and stack-check calls in the handler-reachable pool code.
Selected-port builds already require counterflags against these transformations;
this finding does not assert failure under correctly applied counterflags.

`V2_RUNTIME_PORT_BOUNDARY_CONTRACT.md:274-288` and `README.md:810` require
counter-options for every selected-port translation unit, including Secure
companion code. The contract also says counterflags supplement, rather than
replace, canonical annotations. The probe without these mandatory counterflags
is therefore annotation/test-coverage evidence, not a supported-build failure.

Make Secure-companion requirements explicit and cover gateway plus pool with the
same generated-code checks. Add annotations where the contract promises source-
level protection. Regression: an adversarial complete Secure-image build with
the required counterflags, followed by forbidden-dependency/call-graph checks.

### A18: Two M55 MPU Archive Modes Named Os Actually Use O2

Locations: `tools/compile_matrix.ps1:6289,6316,6665,6692`.

Both FP and MVE-FP MPU runtime integration functions name a mode `softfp-os`,
but their shared compile argument array always contains `-O2`. Documentation
claims softfp `-Os` archive/final-ELF coverage that these functions do not execute.
Separate actual `-Os` generated-assembly parity does run and passed.

Give modes an explicit optimization field and use it for compilation/linking.
Regression: assert effective flags and retain mode-specific final artifacts.

### A19: Reference Hash Pin Omits Consumed Secure Headers

Location: `tools/freertos_asm_parity.ps1:365` hash table and `:233` verification loop.

HEAD equality plus the listed hashes does not pin every consumed portable header.
For example, GCC `-MM` for the actual CM33 Secure allocator confirms dependencies
on `secure_context.h`, `secure_heap.h`, and `secure_port_macros.h`, none of which
is in that hash table. CM33 companion `portmacro`/`portasm` headers are also absent.
An edited reference can therefore retain the expected HEAD and pass this identity
check. The actual reference checkout was clean during this audit.

Pin consumed reference dependencies or reject tracked reference modifications
before compiling. Regression: modified consumed header at the pinned HEAD must
fail before parity comparison.

### A20: NTZ Extended Save Reads The Wrong xPSR Word

Locations: `ARM_CM33F_NTZ/non_secure/fiber_port.c:740`,
`ARM_CM55F_NTZ/non_secure/fiber_port.c:204`, and
`ARM_CM55_MVEF_NTZ/non_secure/fiber_port.c:205`.

Extended save bounds checks obtain STACKALIGN from PSP+100 instead of core
xPSR at PSP+28. Bit 9 of the reserved/VPR extension word can cause spurious
padding and reject a valid exactly fitting frame. Restore uses the correct core
geometry. Matrix assertions at `:12918,14059,16428` currently require the wrong
`#100` load, so the test must change with the implementation.

Regression: independently vary xPSR.STACKALIGN and extension-word bit 9 at the
exact stack boundary, including scalar FP and MVE-FP.

### A21: NTZ Map-On Save Validation Rejects Legitimate Lazy FP

Locations: `ARM_CM33F_NTZ/non_secure/fiber_port_boot.c:360`,
`ARM_CM55F_NTZ/non_secure/fiber_port_boot.c:499`, and
`ARM_CM55_MVEF_NTZ/non_secure/fiber_port_boot.c:500`.

With both lazy FP and switch-time address-map validation enabled, the CPU-state
checker invokes startup readiness while LSPACT=1 is still legitimate. It panics
before the first VSTM can complete lazy preservation. Use the configured-policy
check for this stage and keep first-start checks distinct.

Regression: combined lazy/map-on save preflight with LSPACT=1, followed by the
normal FP save and a post-materialization state check.

## Documentation Hygiene

`STM32_PORT_FREEZE_INVENTORY.md:56` says eighteen complete runtime profiles,
but its table has nineteen: seventeen ordinary `fiber_port.c` source groups
plus two complete split M55 MPU groups. Its staged C55S description at line 82
should not call that profile a prospective nineteenth runtime. This is a count
correction, not a support promotion.

## Additional Link-Probe Evidence

The A15/A16 replay scripts, exact command transcript, ELF/archive/map/disassembly
artifacts, verification results, and SHA-256 manifest were preserved outside the
repository at:

```text
C:\Users\admin\AppData\Local\Temp\fiber-mixed-review-bcff04c7588545b3af694dca9cf593cf
```

`run.ps1` constructs the links and `verify.ps1` checks their outputs. Eight
positive/mixed links had zero diagnostics and no undefined symbols; four
deliberately incompatible expectation links failed on their missing cohort.
These temporary artifacts are supplementary local evidence, not durable CI
fixtures. Promote the reproductions into maintained tests with the fixes.

## Architecture Assessment

The following boundaries should be retained:

- Five portable public operations, with scheduler-selected first and next context.
- Eight mandatory CPU-neutral forward operations and versioned reverse ABI.
- Common ownership of scheduler state/current publication; port ownership of
  context layout, CPU state, exceptions, and protected execution mechanics.
- Distinct exact MPU/FP/MVE/security cohorts and per-profile parity ledgers.
- Separate optional context-feature and lifecycle modules; no unsupported no-ops.
- Explicitly staged C55S work and isolated temporary transitional_v8m.

The fact that later M55 profiles were added without changing `fiber_core.c` or
expanding the forward ABI is practical evidence for this boundary's scalability.
Port duplication is intentional. Repeated validation defects call for shared
behavioral test cases, not an immediate consolidation of port implementations.

The planned Context/Fiber/C++ separation remains later work. TF-M mutex/service
adaptation belongs above the pure Context layer during that extraction. Dynamic
destruction/reclamation, ISR scheduling, SMP, and arbitrary host backends require
their documented later contracts; current opaque storage alone does not provide
them. Application secure-storage/crypto portability belongs to a service layer.

## Original Required Next Work

1. Correct the P1 execution and protection findings with narrow port-focused
   commits, addressing copied instances together with their tests.
2. Add executable architectural-state regressions for startup nesting, Handler
   CONTROL/EXC_RETURN, MPU disjointness, yield/resume, changing stack depth,
   basic/extended frame decoding, union views, and lazy FP transitions.
3. Close the P2 guard and evidence gaps. Update assertions which encode an
   incorrect assumption instead of merely preserving their current PASS.
4. Repeat actual pinned FreeRTOS assembly/ELF/cohort checks after corrections.
   Keep target/emulator execution evidence distinct from codegen and link tests.
5. Resume C55S one-shot initialization/allocation work after this correction
   checkpoint. Finish the inventory, then run the separately planned all-
   optimization/final-LTO and CI freeze gate before Context extraction.

The present audit does not require a rewrite of the common ABI. It requires
repairing port validation semantics and extending the evidence beyond matching
the context-transfer instruction backbone.

## 2026-11-01 Remediation Record

The repair working tree is based on the Fiber SHA recorded above. Six lanes
covered architecture, public-library consumption, library ownership, classic
ports, scalar/security v8-M, and FP/MVE MPU implementations. Implementers also
reviewed another lane's changes. The architect and consumer found no remaining
blocker in the intended static-lifetime, single-core boundary. This is not a
claim that unrelated future profiles or lifecycle extensions are complete.

All A01-A21 source/build corrections below are implemented. Their maintained
tests are invoked by `tools/compile_matrix.ps1`; commands, prerequisites, and
evidence limits are documented in `tools/PORT_AUDIT_TESTS.md`. Software test
results do not substitute for MPU/FP exception execution on target hardware.

| ID | Implemented correction | Maintained regression |
| --- | --- | --- |
| A01 | Priority probing preserves either incoming PRIMASK, including nested startup masking. | FP/MVE state runner executes extracted real startup/probe functions with hardware stubs. |
| A02 | CM33 MPU and three M55 MPU maps put the RO/XN current slot outside privileged RW; linker checks reject overlap and startup must zero the slot separately. | Scalar/FP region decoding, pairwise disjointness, access-policy/publication state cases, linker negatives, and real ARM integrations. |
| A03 | Entry checks distinguish targeted-bank SPSEL clearing from post-MSR stored state; scalar MPU normalizes saved SPSEL, while FP MPU preserves its Handler snapshot and checks all written CONTROL low bits after restore writes. | Scalar/NTZ and FP/MVE state cases, generated ARM sequences, and the separate executed QEMU transition suite. |
| A04 | Restore accepts only the port's exact yield-return site inside syscall text, not arbitrary syscall addresses. | Scalar/FP MPU yield/resume positives and foreign-continuation negatives. |
| A05 | Scalar MPU validates current live PSP bounds, not equality with a historical protected PSP. | Different valid stack-depth positives and out-of-range negatives. |
| A06 | FP MPU runtime SVC decodes the core frame at raw PSP; the FP extension follows the basic frame. | Basic/extended source-derived SVC cases and paired FreeRTOS transfer instructions. |
| A07 | Runtime FP SVC uses configured-policy checks; first-start readiness remains separate. | Runtime lazy-preservation positives and malformed-policy negatives. |
| A08 | Runtime FP SVC reads the active cursor/live PSPLIM rather than inactive basic-union special words. | Extended-image cases deliberately poison the inactive basic view. |
| A09 | CM0 reads the zero-based vector table explicitly through assembly rather than a C null dereference. | Actual optimized/LTO ARM boot code executed with a mapped address-zero table. |
| A10 | CM0 MPU no longer compares r9 across unrelated compiler frames; synthetic seed validation remains. | ARM tests without fixed-r9, including real construction and restore guards. |
| A11 | CM0 MPU proves the entire active 48-word vector table immutable before reading slots. | VTOR/no-VTOR full-table positives and writable/short-table negatives. |
| A12 | FP MPU establishes minimum core-frame bounds before reading xPSR. | Truncated and boundary frames fail before the modeled read; generated ARM components are also audited. |
| A13 | Classic full boot checks validate raw allocation/canary storage before access. | Instrumented memory/hook ordering in real ARM code, including rejected raw storage. |
| A14 | MSP fallback declarations are strong; only library default definitions remain weak. | Strong application overrides with reversed object/archive orders and LTO. |
| A15 | Split CM33 handler extraction calls a one-shot component guard retaining reverse ABI and exact cohort identity. | Real archive links reject stale BASEPRI/cohort, reverse version, and pre-fix handler objects with/without LTO. |
| A16 | Public allocating translation units retain a type-only storage expectation; mandatory runtime defines its exact identity. | No-CMSIS C/C++ public compiles; matching/stale consumer object/archive links, 8/16-region and historical-revision negatives, GC/LTO. |
| A17 | Secure gateway/pool reachable functions use the canonical sensitive attributes. | Complete Secure-companion adversarial builds with required counterflags, final LTO call-graph/dependency audits, contaminated controls. |
| A18 | Softfp Os archive modes carry explicit Os optimization rather than relying on mode-name inference. | Effective compiler optimization probes and existing archive integrations. |
| A19 | Reference pin validates all tracked content and rejects extra or modified files, including consumed headers outside the old hash list. | Clean reference positive and tracked/header/index-flag/untracked/ignored drift negatives; live checkout remains untouched. |
| A20 | NTZ extended pre-save reads core xPSR at PSP+28, independently of extension/VPR bits. | Boundary cases independently vary STACKALIGN and extension bit 9; wrong #100 signatures were removed. |
| A21 | NTZ map-on CPU-state checks use runtime configured FP policy, allowing legitimate pending lazy preservation. | Combined lazy/map-on source-derived cases and generated transfer-order checks. |

### Integration And Identity Changes

CM33 MPU, CM55 MPU, CM55F MPU, and CM55 MVEF MPU now use context generation 2:
`0x00020008u` for eight regions and `0x00020010u` for sixteen. Their public
storage revision is also 2. Clean-rebuild runtime, boot, exception, application,
and expectation objects; unchanged byte counts do not imply compatible saved
semantics.

The public facade automatically retains caller-storage expectations. A direct
concrete-type allocator must explicitly include the storage-expectation header;
bare type inspection intentionally has no runtime dependency. Pre-guard objects
cannot be retroactively protected and must be rebuilt. The linker must retain
all contributions to `.fiber_port_context_cohort_expectation`, not assume the
section always contains exactly one pointer. See `tools/CONSUMER_COHORT_TEST.md`.

CM0 MPU no-VTOR aliases outside the declared immutable maps fail closed. An
embedding platform must supply the documented immutable-alias integration proof;
these tests do not silently grant a writable vector-table alias.

### Evidence Limits And Remaining Roadmap

Classic Unicorn tests execute real Thumb boot/guard code, not architectural MPU
or lazy-FP exception behavior. The scalar and FP state tests compile extracted
production functions with explicit hardware stubs. They exercise guard logic,
but do not execute FP register transfer, lazy materialization, or exception
return. Assembly parity compares the actual pinned FreeRTOS/Fiber operations
and their documented differences; it is not whole-program equivalence.

Five portable public operations, eight forward ABI operations, and reverse ABI
ownership remain unchanged. No per-context user call, CPU branch in common,
unsupported optional stub, or scheduler-policy dependency was added. The staged
C55S profile is still staged. Hardware qualification, the separately scheduled
global O0/Og/O3/final-LTO expansion, and an actual CI run remain outstanding.
Resume the remaining port inventory only after the complete repaired matrix
passes; perform Context/Fiber/C++ extraction after the recorded freeze gates.

### Repair Checkpoint Qualification

The complete repaired `tools/compile_matrix.ps1` passed on 2026-11-01 with
STM32CubeIDE GNU Arm GCC 14.3.1 and the unchanged pinned FreeRTOS reference.
This includes the actual paired O2/Os comparison, all five audit regressions,
all existing port-specific integrations, common/reverse ABI isolation, exact
cohorts, archive/ELF/vector/CMSE negatives, GC/LTO, selection, and settings cases.
Classic coverage executes 842 guard checks across 84 real ARM ELFs; consumer
coverage includes 156 no-CMSIS public compiles, ten invalid manifests, and 256
GC/LTO link scenarios. Scalar/security host cases and the sixteen FP/MVE MPU
host builds remain source-derived state tests, not architectural execution.

The H7 Debug and Release generated builds were force-rebuilt and their final
ELFs audited separately: strong handlers, correct slots 11/14, exact private
and public storage identities, and eight-byte read-only expectations. ASCII,
PowerShell parsing, and `git diff --check` pass. The reference checkout remains
clean. Neither a hardware run nor a hosted CI run was performed.

This is a working-tree qualification based on `5c34785`, not a claim about a
new remote SHA. The complete source snapshot, file hashes, full matrix log,
and H7 ELF receipts are preserved outside the repository at:

```text
C:\Users\admin\AppData\Local\Temp\fiber-audit-qualified-521a6e5ca8894b1782176a13a5fb0bcd
```

Later roadmap slices must record their own qualification instead of inheriting
this PASS after changing runtime code.

### CONTROL Follow-Up Before C55S

The first repair incorrectly generalized exception-entry SPSEL to a permanent
Handler-mode RAZ rule. Armv8-M privileged MSR can change it; MRS reads the written
bank. MPU post-write readbacks must therefore compare the written value, not
the entry value. The existing CM33 Secure initializer is not defective here.
See [Armv8-M ARM](https://community.arm.com/cfs-file/__key/communityserver-discussions-components-files/471/DDI0553B_5F00_y_5F00_armv8m_5F00_arm.pdf), MRS/MSR pages 755-763 and ExceptionTaken page 1931.

The archived qualification above is historical software evidence, not evidence
for this follow-up. Four MPU implementations now check complete post-write
CONTROL; the entry guards remain unchanged.

The refreshed complete matrix passed on 2026-11-01. Its log is
`%TEMP%/fiber-control-final-matrix-3dc5514eada243d6b96fc517924f70f5.log`, with
artifacts in `%TEMP%/fiber-compile-matrix-c53819aa103146638ea32deaa424734c`.
It includes the actual FreeRTOS O2/Os comparison, 403 scalar/security host
checks, 24 FP/MVE host builds with 293-294 checks each, actual ARM component
checks, and all existing integration/selection/settings gates. Host cases
remain source-derived tests, not execution of the exception machinery.

Separately, the maintained QEMU runner passed all six cases: M33 and M55
stored-CONTROL versus physical-MSP transitions, the M3 contrast, two exact
obsolete-RAZ negative failures, and M33 banked SG/Secure-PendSV behavior.
The parent replay retained evidence at
`%TEMP%/fiber-control-parent/arm-control-31d8aa4ec41c45488a294aea12c5d9fb`.
QEMU 8.2.2 package `1:8.2.2+ds-0ubuntu1.18`, compiler identity, fixtures,
commands, ELF/map/disassembly and hashes are recorded there. No packages were
installed into WSL, no board was programmed, and this is not execution of the
Fiber runtime or complete TrustZone qualification.

The matrix now accepts `-ControlQemuRoot` to run that maintained architecture
gate with existing isolated tools. The complete run above preceded this optional
dispatch addition; the six-case runner was executed separately. A future matrix
qualification must distinguish an explicitly executed QEMU gate from `NOT_RUN`.
This closes the correction gate before C55S lifecycle work; global optimization,
final-LTO, CI, and hardware qualification remain separately outstanding.

The corrected source snapshot and hashes, matrix log, and parent QEMU evidence
are preserved at
`%TEMP%/fiber-control-qualified-665e3942f7594b3585a1088992d612b1`.
Its `qualified-source.zip` SHA256 is
`A37353142C2547F4B229065939F2863BDC510585F7DDCD65CEF586AB6E8A4BC9`.
This is an uncommitted working-tree checkpoint based on `5c34785`, not a remote
release or proof for later source changes.

### Secure Pool Copy Review

Two additional follow-ups were identified while reviewing the CM33 companion
before adapting the C55S private lifecycle. They are not hidden behind the
earlier matrix PASS:

- **A22, static storage aliasing:** CM33 seal helpers access a declared byte
  array through uint32 pointers. Alignment does not make that typed access
  valid under strict aliasing. The reference allocator obtains untyped heap
  storage, so copying its cast into a declared static byte array changes the C
  object-model assumptions. Use character representation access without
  changing seal bytes, record geometry, or usable stack size. No observed
  miscompilation is claimed. See the
  [GCC strict-aliasing rules](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html#index-fstrict-aliasing).
- **A23, caller-origin contract:** IPSR 11/14 proves an exception number, not
  Non-secure caller provenance. Stateful NSC entries that require NS origin
  must inspect `cmse_nonsecure_caller()` inside the actual entry function.
  A helper cannot substitute its own caller state. This does not by itself
  authenticate a particular NS instruction site or an entire TrustZone policy;
  owned-SVC validation remains the NS runtime's separate responsibility. Secure
  firmware is trusted, so no exploit of an untrusted Secure caller is claimed.
  See [Arm CMSE caller-state requirements](https://arm-software.github.io/acle/cmse/cmse.html#security-state-of-the-caller).

CM33 repairs and their dedicated evidence are tracked separately from the new
M55 private pool. Neither follow-up widens common or portable ABI. C55S remains
staged until CPU initialization, stateful gateways, attachment, and SVC/PendSV
are implemented and qualified.

### A24: Privileged Armv8-M First-Start Readback

Cross-review found a remaining application of the obsolete Handler SPSEL rule
outside the four protected implementations covered by the first correction.
Seven privileged first-SVC paths wrote CONTROL 2 but compared the readback with
0: CM33 SecureContext, CM33 NTZ/TF-M/scalar-FP NTZ, and M55 scalar/FP/MVE NTZ.
The M23 path already checked 2. Entry guards after writing 0 were correct and
remain unchanged; the Armv7-M contrast must not be converted to the v8-M rule.

These seven post-write checks now require 2. The scalar/NTZ/security runner
requires the exact source and generated O2/Os sequences and rejects a mutated
comparison against 0. The independent CONTROL QEMU transition suite supplies
the architectural execution evidence, not execution of the complete Fiber SVC
path. Existing compile/parity receipts did not detect this semantic defect and
must not be presented as proof that the old readback was correct. A fresh full
matrix is required for the combined A22-A24/C55S private-pool checkpoint.

### A22-A24 And C55S Slice-4 Qualification

The complete matrix passed on 2026-11-01 with the explicit isolated QEMU prefix,
GNU Arm GCC 14.3.1 and the clean pinned FreeRTOS reference. This run includes
all prior compile/link/ELF/archive/cohort/settings gates, actual FreeRTOS O2/Os
comparisons, and the newly integrated C55S private-pool comparison. The earlier
partial run was deliberately interrupted after A24 was confirmed; it is not a
qualification receipt.

```text
Full log:
  %TEMP%/fiber-c55s-a24-matrix-98e0fac2a64d4f699b0ae669dfca2a62.log
Complete artifacts:
  %TEMP%/fiber-compile-matrix-0bdb3e68121a4c3687a393e55f62b6db
Qualification snapshot root:
  %TEMP%/fiber-c55s-a24-qualification-1411e2bfc94d46f88f7dafd19f9f8fe7
```

The new executable proof cohorts are independent:

- CONTROL: six actual QEMU cases, including the Armv7-M contrast and exact
  obsolete-readback negatives. These establish architecture transitions, not
  execution of every production Fiber handler.
- CM33 gateway/pool: five production two-image QEMU modes and four exact
  caller-guard-removal mutants; actual CMSE entries and native seal accesses.
- C55S private pool: 2872 Unicorn ARM calls with 848 expected UDF traps and no
  invalid accesses, plus 48 calls killing eight guard-removal mutants. Twelve
  executable scalar-model ELFs use the explicitly qualified loop counterflag;
  twelve separate untouched M55 ELFs supply default code-generation evidence.
- Default C55S M55 execution: sixteen QEMU AN547 cases across O2/Os and both
  LTO modes, including emitted low-overhead loops without the counterflag.
  Four independent classifier controls reject unrelated faults, missing
  reports and timeouts. Negative PASS requires the exact production UDF PC,
  UNDEFINSTR status, expected frame origin and case-specific exit marker.

The 361 recorded code inputs remained unchanged during the qualification
interval; source/evidence manifests and the full log are retained at the
snapshot root. This is an uncommitted working-tree checkpoint based on
`5c34785`, not a remote release or hosted-CI result. No board was programmed.
It neither closes staged C55S CPU lifecycle nor adds a twentieth complete
runtime. Global O0/Og/O3 and final-LTO parity expansion remain later gates.

The preserved snapshot contains 412 source/document files. Its
`qualified-source.zip` SHA256 is
`2D18106E8EE4180B35B0B3FFC5E89FB80A554AF41066E3EE70C2D9240F58C5BC`.
This digest record was appended after the snapshot; subsequent source slices
require their own evidence rather than inheriting this PASS.

### A25: Reference-Copied Armv8-M Shareability Encoding

The four implemented v8-M MPU dictionaries and the staged CM33F MPU dictionary
copied INNER_SHAREABLE as `1u << 3u` from pinned FreeRTOS. Arm RBAR.SH defines
1 as reserved and 3 as Inner-shareable; local CMSIS agrees. The dictionary now
uses 3, and encoder validation consequently rejects the reserved raw value.
This is an intentional reference divergence, `FAP-ARMV8M-RBAR-SH`, not a
reason to alter the pinned checkout or relax architectural checks.

All currently constructed standard global/context mappings use Non-shareable
0. Their descriptor bytes, frame geometry, callable ABI and storage identity
therefore remain unchanged. Optional heterogeneous-region configuration is not
implemented by this correction. Numeric SH/AP/XN cross-product regressions must
test both accepted output and rejected output preservation, with a stale INNER
1 mutant rejected independently of copied symbolic definitions.

The A22-A24/C55S snapshot above predates A25 and the staged CM33F type/manifest
slice. It remains historical evidence; a fresh combined matrix is required.

### A25 And C3FP Type Qualification

The fresh full matrix passed on 2026-11-01 with the explicit isolated QEMU
prefix, GCC 14.3.1 and the unchanged pinned reference. All 424 captured source
and document inputs remained unchanged during the run. This includes actual
FreeRTOS O2/Os comparison, the existing ABI/ELF/cohort/archive/GC/LTO gates,
32 rejected stale-INNER mutants, and the staged C3FP type proof: 16 public
C/C++ objects without CMSIS, 16 real-CMSIS objects, 24 actual M33 reference
objects and 51 intended negative manifests.

```text
Snapshot and receipts:
  %TEMP%/fiber-a25-cm33f-qualification-617bed93992d4655826a36fa53a211ad
Full log within that root:
  full-matrix-replay.log
Complete artifacts:
  %TEMP%/fiber-compile-matrix-5bafce4a84684adab805657680aace16
qualified-source.zip SHA256:
  210DCF83AD8B5BA20DA9F11085D3DE29765C2249B54C0EF3F2E60359EA11FB68
```

This is uncommitted working-tree evidence based on `5c34785`, not a new remote
SHA or hosted-CI/hardware run. The type proof is not a C3FP constructor, handler
or runtime qualification. The snapshot receipt explicitly records known A26
below; this is not the no-known-software-gap freeze. This record was added after
the preserved snapshot and does not extend its PASS to subsequent changes.

### A26: Secure Exception-Priority Precondition

CM33 Secure initialization copied the reference's AIRCR read/modify/write:
preserve fault-routing bits and set PRIS. If the platform previously set
BFHFNMINS, that produces an architecturally UNPREDICTABLE combination. Readback
after the write is too late. See the
[Armv8-M ARM](https://community.arm.com/cfs-file/__key/communityserver-discussions-components-files/471/DDI0553B_5F00_y_5F00_armv8m_5F00_arm.pdf), AIRCR PRIS/BFHFNMINS, page 1459.

The selected Secure gateway now requires BFHFNMINS=0 before storing its
INITIALIZING marker or changing CPU/pool state. Rejection returns 0 without
changing the platform's fault routing. The successful PRIS/PSPLIM/PSP/pool/
CONTROL/READY sequence, masks, public ABI and context layout are unchanged.
The preceding matrix did not contain this new guard. Its independent focused
qualification is recorded below; a new combined run must include it.

### A26 Focused Qualification

The maintained CM33 guard runner and an independent parent replay both passed:
14 two-image cases / 28 ELFs, with five production modes (O0/O2/Os/O2-LTO/
Os-LTO), the four original caller-guard mutants and five new BFHFNMINS mutants.
Production performs two genuine NS-SVC/SG rejections with cold gate, CPU state
and poisoned pool unchanged, followed by the valid initialization control.

The runner decodes the actual generated store operands and uses a private Unix
RSP socket. Each BFHFNMINS mutant stops at the exact keyed AIRCR STR with the
forbidden value pending; the paused emulator is killed before executing it.
Unknown store code generation, an unrelated fault, missing reports or timeouts
cannot satisfy this proof. No new package or fixed TCP port is required.

```text
Parent replay:
  %TEMP%/fiber-a26-parent-89375930f93648b68c3f0824b5c54a02
  cm33-secure-guards-8df01e33d83941338e66faaccc4d2b29
Actual FreeRTOS O2/Os generated-code replay:
  %TEMP%/fiber-a26-parity-e75e17fa46fc421388f3d3f883c8bb0f
```

This is execution of the gateway/fixture on QEMU M33, not STM32 hardware or
whole-runtime isolation qualification. The C3FP constructor/linker slice and
the complete combined matrix still require fresh qualification.

### A27: Sensitive Forced-Inline Call Graph

The staged C3FP constructor's strict hostile-flags build found compiler-generated
instrumentation dependencies despite the enclosing constructor's sensitive
attributes. Forced-inline register and alignment helpers need their own compiler
protections: caller attributes do not automatically protect the inlined source.

The canonical `FIBER_API_ATTR_INLINE_SENSITIVE` bundle disables instrumentation,
stack protector, sanitizer, profiling and coverage, without imposing noinline or
noipa on helpers that must remain inline. The four shared geometry helpers and
the C3FP r9 reader use it with general-registers-only. The enclosing operation
still owns the normal sensitive function boundary. No frame/layout or scheduler
ABI change is intended. C3FP strict hostile builds now pass without counterflags
that hide the original failure. Other local port helpers require their own
call-graph coverage; this focused result is not a global hostile-build claim.

### A28: Optimized Python Cannot Qualify Assertions

The constructor proof initially used assertions for its optimization/version
preflight. Python `-O` removed those checks and later assertions, including ARM
calls embedded in them. That could falsely accept broken classifier cases.
Classic audit had the same preflight pattern and assertion-based checks.

Both runners now reject optimized execution with explicit conditionals before
normal execution, reference extraction or classifier import. Package versions
also use explicit failures. Maintained subprocess negatives require the exact
intended diagnostic, not merely a nonzero status. Existing M55 pool guards remain
independent. The new constructor focused replay passes 4176 actual ARM calls,
1216 expected panics, 34 linker negatives and ten Python guard negatives across
eight configurations; classic passes 842 checks across 84 ARM ELFs and seven
preflight controls. Full current-tree qualification is still separate.

### A26-C3FP Combined Checkpoint

The complete matrix passed with the explicit isolated QEMU prefix on
2026-11-01. Its 438 source/document inputs remained unchanged during the run.
It includes the A26 gateway rejection/mutants, staged C3FP constructor/reference
proof, existing nineteen-runtime O2/Os reference parity and all current
ABI/cohort/archive/ELF/GC/LTO/settings gates. Generated H7 Debug and Release
builds also pass; their `.text` bytes remain identical to the preceding H7
receipt, with strong handlers, slots 11/14 and both cohort expectations intact.

```text
Snapshot, full-matrix.log, source manifests and qualification.json:
  %TEMP%/fiber-a26-c3fp-combined-ae7a54e6bbc7435f912dd17f0594964b
Complete matrix artifacts:
  %TEMP%/fiber-compile-matrix-2ff2e1fabd9147cc9e29e1e8415de933
qualified-source.zip SHA256:
  7424F351FD08A577DCD04C7A56872D82710F2DAB626A5A3A5A653A74213EFB5F
Generated H7 rebuild/ELF receipt:
  %TEMP%/fiber-inline-h7-5e927bcc666e496c8214544a4aa5c7bd
```

This checkpoint explicitly records three independently reproduced follow-ups:
C3FP optimized-code import can bypass a process-flags-only guard; substring
diagnostic controls can accept traceback counterfeits; and four existing v8-M
MPU r9 readers still leak hostile instrumentation. Additional local inline
helper coverage is incomplete. The ordinary non-optimized runner did execute
the recorded checks, but this is not a no-known-gap freeze. Follow-up changes
require separate evidence; no runtime count, hardware or hosted-CI claim is
added by this working-tree snapshot based on `5c34785`.

### A27-A28 Focused Follow-Up

The four existing v8-M MPU dictionaries now protect all seven local inline
r9/BASEPRI/vector helpers. The shared EXC_RETURN predicate and the staged C3FP
dictionary receive the same canonical protections. No global force-inline
default, frame, cohort identity or public/runtime ABI is changed.

The constructor attribute gate passed 24 applicable configurations, exact
normal/hostile dependency checks, unchanged normal instructions/relocations,
40 actual consumer compiles and 48 compiled hostile mutants. A separate helper
gate passed 32 configurations / 96 positive ARM C/C++ objects, 256 compiled
annotation-removal mutants and 40 host executions, each checking 131104
predicate inputs. Four classifier counterexamples are rejected. Ordinary and
hostile helper bytes agree; no writable counters or FP/MVE code is emitted.

The final Python guards use both process flags and `__debug__`. Optimized
compiled imports in an ordinary interpreter are rejected before assertions.
Negative diagnostics require the sole exact line, and actual RuntimeError
tracebacks are maintained counterexamples. Classic passes eight preflight
controls and 842 checks on 84 ARM ELFs. An independent parent C3FP replay passes
4176 ARM calls, 1216 expected panic paths, 34 linker negatives and 32 Python
guard controls on stable input hashes.

```text
MPU constructor attribute receipt:
  %TEMP%/fiber-mpu-constructor-attributes-qualification/
  mpu-constructor-attributes-fc1117fb118b413689036a27fa9b92ad
Parent helper replay:
  %TEMP%/fiber-inline-helpers-parent/
  fiber-inline-cpu-helpers-466e8f07fd1c406c8ea4305829e8562b
Parent constructor replay:
  %TEMP%/fiber-c3fp-final-guards-parent/
  cm33f-mpu-constructor-84c163ac489846668dd0556202b4c36f
Classic exact-diagnostic receipt:
  %TEMP%/fiber-owner-classic-exact-diagnostic/
  fiber-classic-audit-dbd64811662d480da384c51a8c2bea80
```

Other port dictionaries, CMSIS helpers and non-inline runtime callees remain
outside this focused hostile-build closure. This is not a global call-graph,
exception-execution or hardware claim. These later sources and the new C55S
initializer require their own combined matrix receipt, not the preceding
438-file snapshot's inherited PASS.

### C55S CMSE Code Generation Boundary

GCC 14 emits `VSTR FPCXTNS`, `VLDR FPCXTNS` and `VSCCLRM` security
housekeeping for Armv8.1-M Non-secure-callable entries even with a soft-float
ABI and general-register-only function attributes. The exact production
sequence is also present in the actual pinned FreeRTOS Secure initializer.
Only the qualified instruction/operand forms in NSC entries are permitted;
ordinary FP/MVE arithmetic and private-helper FP/MVE code remain prohibited.
Neither a blanket no-`V*` assertion nor an unrestricted `V*` exception is valid.

Arm DDI0553B.y sections C2.4.364 and C2.4.484 define FPCXT_NS accesses without
FP/MVE as inactive: payload access and CP10 checks are suppressed, while address
writeback and stack checks still apply. They are not whole-instruction NOPs.
Section C2.4.470 defines the corresponding Secure-state VSCCLRM no-FP/MVE
behavior. No new physical-FPU requirement follows from these instructions alone.
See the [Arm architecture manual](https://community.arm.com/cfs-file/__key/communityserver-discussions-components-files/471/DDI0553B_5F00_y_5F00_armv8m_5F00_arm.pdf)
and the [GCC soft-ABI CMSE regression cases](https://gcc.gnu.org/pipermail/gcc-patches/2024-October/666067.html).

The used QEMU 8.2.2 M55 machine has physical FP capability regardless of fixture
CMSIS macros. Its [FP-system-register decoder](https://github.com/qemu/qemu/blob/v8.2.2/target/arm/tcg/translate-m-nocp.c)
also does not establish the architectural physical-no-FP FPCXT_NS path. The
two-image M55 tests therefore qualify their actual machine and state policy,
not a physically absent-FPU implementation. This limitation must remain visible
in the evidence and does not justify removing compiler security housekeeping.

### C55S Initializer Focused Qualification

The maintained initializer runner and independent parent replay pass 53 actual
M55 two-image QEMU scenarios at O2/Os, with and without LTO. Four hostile
whole-companion links retain the exact nine-entry import surface, no compiler
support dependencies and only the declared pool/two-marker writable state.
There are 152 negative latch-fault classifier checks. Wrong-origin calls,
BFHFNMINS rejection/retry, repeated calls and sticky postcommit failures are
covered; guard-removal and unexpected-store controls are stopped before the
forbidden write executes. Unrelated faults, missing reports and timeouts cannot
qualify a deliberate fail-closed result.

Actual pinned FreeRTOS initializer parity separately passes at O2 and Os:
460 traces, 15 compiled mutants and four CMSE classifier controls per mode.
The differences have individual FAP entries, including the exact compiler
security template and Fiber's one-way/readback hardening.

```text
Parent initializer replay (45 inputs, unchanged):
  %TEMP%/fiber-c55s-initialize-parent-final/
  fiber-m55-secure-initialize-bdab03f1c3d0423da3111de54caeb90f
Actual reference parity receipts:
  %TEMP%/fiber-c55sinit-parity-qualified-o2/C55SINIT/artifacts.json
  %TEMP%/fiber-c55sinit-parity-qualified-os/C55SINIT/artifacts.json
Independent fault-oracle review:
  %TEMP%/fiber-m55-initialize-independent-review-1c0b7cabbbd74fa99b93b1bd7589f531
```

These are focused software/emulator receipts, not the final combined matrix,
physical no-FPU execution, Secure save/load or complete C55S runtime support.
The later README wording clarification changes no qualified production/test
code. The common API and the nineteen complete-runtime count remain unchanged.

### C55S-Inline Combined Software Checkpoint

The full `compile_matrix.ps1` run with the explicit isolated QEMU prefix passed
on 2026-11-01. All 467 tracked/untracked source and document inputs remained
unchanged throughout execution. Every archived source member was independently
checked against its input SHA-256; all 467 matched.

This combines the nineteen-runtime O2/Os actual FreeRTOS parity, A27/A28
repairs, shared/local sensitive inline helper probes, staged C3FP constructor,
the new C55S initializer, executed CONTROL/CM33/C55S emulator gates, and the
existing selection, ABI, cohort, archive, ELF, GC/LTO and settings negatives.
The earlier 438-input checkpoint's known follow-ups are covered by this new
run rather than inheriting its PASS.

```text
Full log, manifests, qualification.json and source archive:
  %TEMP%/fiber-c55s-inline-combined-1a198ebcb5f
Matrix artifacts:
  %TEMP%/fiber-compile-matrix-b19e2376182f4083bf13f4d227b27fed
qualified-source.zip SHA256:
  8C61FE5284908F38ED7A74EFAA15ACFDCA38444BBC817239493EF37FBB87FB23
Base HEAD:
  5c34785088e3496540a8dcbec1351fac241e11ca
Pinned FreeRTOS:
  a50edad08b29052631aa469d4df6e6ec7ff68878
```

This is a local working-tree software checkpoint, not a published commit or a
final port freeze. At this checkpoint C3FP handlers/runtime and C55S
allocation/save/load/Non-secure runtime are still pending. Other profiles'
complete hostile callgraphs, the global all-optimization/final-LTO expansion
and hosted CI remain separate gates.
Hardware and hosted CI were not run. The Context contract's reverse-upcall
wording clarification and this receipt are later documentation-only changes;
no production or test changes were made between the run and recording this
receipt. Later implementation slices require their own qualification.

### C55S Transfer Focused Evidence

The later slice adds guarded NSC allocation/load/save to the initializer and
immutable queries, for exactly twelve exports. The common API, eight-operation
forward boundary, Non-secure layout and nineteen complete-runtime count are
unchanged. This remains a staged Secure companion, not a complete C55S runtime.

Actual pinned FreeRTOS transfer comparison passes separately at O2 and Os:
529 cases, 554 ARM calls and 36 compiled mutants rejected per optimization.
The comparison retains explicit CPU/CMSE and pool/heap doubles; it is not a
physical-M55 or complete Non-secure scheduler execution claim. Normal and
hostile actual companion builds retain the exact twelve-entry surface.

An independent parent initializer replay also passes all 53 existing scenarios
against the twelve-entry companion, with stable input hashes. That regression
qualifies initialization, not the three new transfer operations.

The maintained two-image lifecycle runner subsequently passes 148 scenarios
(37 each at O2/Os, normal/LTO) with all 91 input hashes unchanged. It checks
actual SG and Handler origins, independent numeric pool geometry, owner checks,
ordered transfers and readback, deliberate corruption UDFs, and compiled
guard-removal controls. Twenty-eight partial-update cases stop in the originating
Non-secure SVC/PendSV Handler before exception return. Four deliberately resumed
Thread fixtures and eight compiled unknown STL/STLEX stores are rejected while
paused; unsupported STC/VSTM forms also have classifier controls. Arbitrary
faults or correct-looking text without the actual origin proof cannot qualify.
Independent oracle review subsequently passes twelve separate QEMU replays and
22 terminal-classifier probes. The later combined matrix below closes this
staged-primitives checkpoint, without implying a Non-secure runtime provider.

```text
Transfer parity receipts:
  %TEMP%/fiber-c55s-transfer-qualified-o2/C55STRANSFER/artifacts.json
  %TEMP%/fiber-c55s-transfer-qualified-os/C55STRANSFER/artifacts.json
Parent twelve-export initializer replay:
  %TEMP%/fiber-c55s12-initialize-parent/
  fiber-m55-secure-initialize-f11d6ad9c94b45b18f08b8d719e37e9e
Transfer gateway source SHA256:
  12D9872246181C03200993541F9B9C76562C2728D02E6FEACE25DA11348F2B31
Focused lifecycle runner:
  %TEMP%/fiber-m55-secure-lifecycle-9249e7fdc34e4029b8efdd7fb0af2311
Independent review:
  %TEMP%/fiber-m55-lifecycle-independent-review-bb44f04fe97d4004a6fdda2964f19f4b
```

### C55S Transfer Combined Software Checkpoint

The full matrix with the explicit isolated QEMU prefix passes on 2026-11-01.
All 481 tracked/untracked source and document inputs remain unchanged throughout
execution. Every archived source member is independently decompressed and
checked against its SHA-256 manifest; all 481 match.

This repeats the new 148-case Handler SG lifecycle suite inside the combined
gate, alongside actual pinned FreeRTOS O2/Os transfer/initializer parity,
nineteen complete runtime profiles, C3FP constructor/linker staging, the prior
audit regressions, ABI/cohort/archive/vector/ELF/GC/LTO and selection/settings
negative checks. It does not upgrade the nineteen-profile count or complete the
staged C55S Non-secure runtime, private Secure cohort guard, C3FP handlers,
remaining processor feature tuples, global all-optimization/final-LTO expansion,
or hosted CI.

```text
Full log, input manifests, qualification.json and source archive:
  %TEMP%/fiber-c55s-transfer-combined-b009e647762e4cc8b2d22b53c6fdcaf3
Matrix artifacts:
  %TEMP%/fiber-compile-matrix-8fef1811a0b1455fab70ef06b2250fb0
qualified-source.zip SHA256:
  EB9B6144FA287AC14B8681ACCFEA1E76FA4BFBFC105A8C2E98BA02D2B765FD42
Base HEAD:
  5c34785088e3496540a8dcbec1351fac241e11ca
Pinned FreeRTOS:
  a50edad08b29052631aa469d4df6e6ec7ff68878
```

This is an archived local working-tree qualification, not a published commit or
final port freeze. Hardware and hosted CI are NOT_RUN. Recording this receipt
and correcting the fixture's case counts are later documentation-only changes;
no production or test implementation changes intervene before recording it.
Later implementation needs its own evidence.

### C55S Private-Object Cohort Freeze Gap

A controlled link with the new twelve-entry companion accepts a gateway built
for count 3 / capacity 128 together with a pool built for count 2 / capacity
208. Both images occupy 480 bytes, so a total-size linker assertion cannot
distinguish them. The mixed ELF has twelve imports and no unresolved symbols;
its capacity queries still report the gateway's 3/128 values. Neither the
matching nor the mixed image was executed by this experiment.

```text
Controlled matching/mixed link receipt, unchanged input hashes:
  %TEMP%/fiber-c55s-owner-mix-a41148eb95ae4d8693f80ad79d56c0db
```

This confirms missing build-time private-object binding, not a demonstrated
runtime memory-safety defect. Per-translation-unit manifest/geometry assertions,
versioned NSC names and the nineteen complete runtimes' cohort guard do not bind
these three Secure objects together. Before complete C55S freeze qualification,
add a retained companion-private exact identity covering profile/ABI, record
revision, count, capacity, alignment and seal policy. Test matching/mixed objects
including equal-size collisions at O2/Os, with LTO, archives and section GC.
Preserve accepted constant-expression settings; do not token-paste arbitrary
configuration expressions into symbol names. This gate needs no portable API,
generic eight-operation ABI or Non-secure context-layout change.

### C55S Private Cohort Implementation And Focused Proofs

The later repair adds an independent Secure-private generation-1 contract. Its
one-byte strong read-only key encodes twelve evaluated uint32 facts as distinct
unsigned high/low halves: profile, layout, features, two gateway ABI versions,
record revision, count, capacity, alignment and seal geometry/value. Accepted
constant-expression settings retain their numeric meaning. Record size,
alignment and each offset have local assertions.

A pure sensitive C helper provides archive/LTO extraction. Each immutable query
and the admitted initializer calls it and retains its own exact data relocation.
Allocate/load/save paths are unchanged. The build-owned linker fragment rejects
a wholly pre-guard companion; it does not impose an external exact capacity on
a coherent alternate guarded archive. Board NSC placement remains board-owned.

The initial maintained suite passes 368 links at O2/Os, with and without LTO:
equal-size mixed objects, each object role/direction, count/capacity mismatches,
C/C++ query roots, mixed-LTO archives, expression normalization, missing-data,
duplicate-key and encoding controls. This receipt alone does not prove retention
in each query body: sibling CMSE roots can mask a removed reference. An isolated
query mutation extension requires the separate qualification recorded below.

```text
Initial 368-check cohort receipt:
  %TEMP%/fiber-m55-secure-cohort-0fd9c0c13cb4495fbd12743714feb3dc
Guarded, drift-free 148-scenario lifecycle replay:
  %TEMP%/fiber-m55-secure-lifecycle-e34bcafcac194e4187694e8395c9d25b
Byte-complete hostile helper / 53-case initializer replay:
  %TEMP%/fiber-m55-secure-initialize-d276d696636d404cab444f9d2a437da6
```

The hostile helper audit now accounts for every byte in its sized ELF symbol,
instead of silently dropping an undecoded word. Each mode checks one pure
compiled control and six rejected controls, including the exact default-M55
undecoded STC word. These controls are static, never executed. These focused
results and the historical 481-input snapshot do not qualify later CM33 code
or complete the staged C55S NS runtime.

The subsequent isolated-query extension passes 496 checks, including 32 compiled
single-query RETAIN-removal mutants and 16 native selected-body instruction /
relocation comparisons. A CMSE projection makes sibling entries ordinary
functions, so archive extraction cannot accidentally root their references.
Only the selected query remains in each isolated final ELF and import object.
The source copy retains the actual selected production body unchanged. Removing
that body's RETAIN must remove its exact key, while strict matching admission
must reject the resulting image; merely checking that the link succeeds is not
the oracle.

```text
496-check / 32-mutant C55S private cohort receipt:
  %TEMP%/fiber-m55-secure-cohort-cf6915bc54614551abaf11626705a886
Byte-complete, drift-free 148-case lifecycle replay:
  %TEMP%/fiber-m55-secure-lifecycle-06889f097ff04e488b90f98f91be48d6
Independent source / helper review:
  %TEMP%/fiber-c55s-secure-source-review-a7428b7b98e54d22940bbf07b3591db9
```

The lifecycle replay records 95 unchanged inputs. A separate interrupted
qualification completed all 148 scenarios but failed its final input-drift
check because the parent changed a shared test parser. It is retained as failed
evidence, not merged into the passing receipt. Later shared-runner changes must
be replayed by a new combined qualification.

### CM33 Private-Object Binding Follow-Up

The same class is independently confirmed for the existing CM33 Secure
companion. Controlled GCC 14.3.1 O2 links accept a matching 3/256 gateway/pool,
a 3/256 gateway with a 2/400 pool, and the reverse mix. All retain twelve CMSE
exports, no unresolved symbols and an 872-byte pool section. None was executed.

CM33's central ELF proof is stronger than total-section sizing: it checks the
individual record and stack arrays. It rejects the first mixed pool, but the
reverse mix keeps the expected pool sizes while gateway instructions report
count 2 / capacity 400. Thus those storage checks do not establish agreement
between gateway and pool objects. This does not claim that a mixed image passes
the complete matrix.

```text
Independent matching/bidirectional mixed-link receipt:
  %TEMP%/fiber-cm33-owner-mix-633cbc6590b44764bf6eba54dbc24d44
```

Keep a separate exact private-companion binding gate for CM33 before final
freeze. Its per-TU manifests, record/seal assertions, versioned exports and
NS-side identity/capacity checks remain useful but do not replace that gate.
This is a confirmed build-contract gap, not an observed runtime failure or a
generalization to uninspected Secure profiles. It requires no portable API or
generic forward-ABI expansion.

The later C33S repair implements its own twelve-fact private key and non-NSC
pool extraction helper. All eight immutable queries and the admitted initializer
retain the exact tuple. The actual CM33 pool geometry, void initializer and
masked CONTROL readback remain distinct from C55S. The generation linker
fragment is a required Secure-image integration input; it proves generation
presence, not an application-owned exact capacity expectation.

The maintained C33S suite now separately passes the same 496-check inventory,
including equal-size 3/256 versus 2/400 mixes, each stale object role, C/C++,
archives, mixed LTO, 32 isolated-query removal mutants and numeric-expression
normalization. It does not inherit the C55S result.

```text
Current C33S private cohort receipt (results.json):
  %TEMP%/fiber-cm33-secure-cohort-6607002928d94638af3214319743e295
```

### CM33 Private Pool Compiler-ISA Follow-Up

An independent GCC 14.3.1 experiment links actual M33 gateways against an actual
CM33 pool separately built for M55 at O2 and Os. GNU attribute merging accepts
the image and raises its ISA to `v8.1-M.mainline`; the pool contains `dls`/`le`,
while the identity query still returns C33S. All twelve NSC exports and expected
pool geometry remain present. No mixed image was executed.

```text
Matching, lower-subset and higher-ISA evidence:
  %TEMP%/fiber-cm33-owner-isa-6f1bb34ef3b349cf8edf18a5b7058086
```

This is an unsupported-build contract gap, not a failure of correctly compiled
M33 sources. A nominal profile constant cannot prove another object's compiler
ISA. The accepted M3-built pool is a lower-ISA subset example, not an additional
qualified profile. The repair must constrain the private compiler manifest and
audit the linked ISA ceiling with a real higher-ISA counterexample; it must not
pretend to recover an arbitrary literal `-mcpu` spelling from macros.

The implemented GCC pool translation unit now scopes an Armv8-M Mainline
function-target ceiling around all declarations and definitions, including its
static helpers, then restores the previous options for textual includers. The
CMSIS-free private header rejects incompatible exposed architecture, CMSE,
FP/MVE/PAC/BTI facts. GCC 14's scalar-soft M33 and M55 predefines are identical,
so this cannot honestly reject every literal M55 command line in preprocessing.

The mandatory maintained ISA gate checks both input-object and final-ELF
attributes. It rejects higher-ISA inputs even when the source ceiling produces
compatible instructions, or LTO reduces the final attribute. Real compiled
M55 low-overhead-loop counterexamples additionally exercise the final `dls`/`le`
veto. This is a bounded observed-opcode check, not exhaustive instruction
validation. Correct M33 executable sections remain byte-identical in four modes.

```text
300-check input/final ISA admission replay:
  %TEMP%/fiber-cm33-secure-isa-befee25004b8485dba7851c0b4e1bd6d
Adversarial call-graph / reference / O2/Os owner regression:
  %TEMP%/owner-guards-b77931af28e649da8e30310bcabe4810
```

These focused proofs do not replace a fresh unchanged-input combined matrix or
qualify an arbitrary precompiled companion outside the inspected inputs.

The actual two-image CM33 guard suite also passes again at O0/O2/Os and both
optimized LTO modes, with four caller-origin mutants and five precommit AIRCR
mutants. The latter stop before executing the forbidden store, not after a
generic fault. Its refreshed runner records 74 input hashes before/after,
requires zero drift and preserves an artifact-hash manifest.

```text
14-case CM33 QEMU caller/AIRCR replay, input drift 0:
  %TEMP%/cm33-secure-guards-c492835d04744f64a6b97e2fd44f60f7
```

This is model execution of the companion guards, not complete Fiber switching
or hardware qualification.

### Protected MPU Startup Policy Admission

The follow-up common/settings audit confirms that four active v8-M protected
starts ignore `FIBER_REWIND_MSP=0`: both settings generate identical code with
an unconditional initial-MSP write. Parent inspection finds the same policy in
the M0+, M3 and M4/M7 protected engines. The settings documentation previously
promised preserve-current behavior without restricting its applicable ports.

The conservative correction rejects `0` in all seven active protected
dictionaries and the staged C3FP dictionary. Their first-SVC provenance checks
depend on the initial-MSP relationship; adding a second startup plan would be
a separate behavior-changing feature, not a settings cleanup. Default `1`, frame
geometry, cohort identity and assembly are unchanged. Unprotected ports retain
their existing preserve-current policy.

The maintained runner compiles 54 configurations at O2/Os, including applicable
hard/softfp, region count, M4/M7 and M0+ VTOR variants. Each compiles default,
explicit `1` and rejected `0`; default/explicit objects must be byte-identical
and rejection must contain the selected dictionary's exact diagnostic.

```text
Independent original finding and generated assembly:
  %TEMP%/fiber-common-readonly-6c5c7258dc5c4194a5dad767756d40c7
Initial 54-configuration / 162-compile policy proof:
  %TEMP%/fiber-mpu-start-policy-558225cec2794a9c9bd15dfd5287fae2
```

This is compile/admission evidence, not first-SVC or hardware execution proof.

### M55 MPU Saved-Form Guard Correction

The source-derived state tests expose a representation bug in both M55 FP MPU
engines. Dynamic saved-form admission used the basic guard at backing word 20.
That word overlaps extended payload S4: after an extended representation has
occupied the backing, a basic save does not overwrite that old payload word.
The permanent word-53 guard is outside both payloads and is the correct common
dynamic guard. The constructor and cold initial-frame checks remain distinct.

The fix changes the two C classifiers and comments, not assembly, frame geometry,
ABI identity or context storage. The maintained cases preserve a nonzero S4
payload across a source-derived cold-basic/extended/basic representation sequence
and reject old-guard, basic-guard and extended-guard mutants. This is a backing
representation counterexample, not an observed running exception transition:
stopping FP instructions does not itself clear FPCA, and no public runtime path
that tears down FPCA has been established here.

```text
Focused owner replay:
  %TEMP%/fiber-m55-saved-representation-final-fe5ba4df06d644c5964b74a75d4bb0f6
24 host runs / 180156 checks / 96 rejected mutants
24 production ARM objects / 16 extracted-classifier ARM objects
```

Independent review confirms the word overlap and the permanent guard geometry.
The complete aggregate matrix must still be replayed on the combined tree;
the older 481-input checkpoint does not qualify this correction.

### C3FP First-Start Component Qualification

The staged CM33 scalar-FP MPU port now supplies its private first-start helpers
and strong SVC-70 handler. It remains unselectable and has no running services,
PendSV, runtime provider or complete archive/vector cohort. This does not add a
twentieth complete runtime to the inventory.

The maintained codegen runner passes sixteen O2/Os hard/softfp, 8/16-region,
normal/LTO configurations. It builds 32 normal/countered-hostile production ELFs
and sixteen actual pinned FreeRTOS reference ELFs, checks complete normalized
naked instruction sequences, mapping-symbol byte coverage, literal values and
ordered C/MMIO envelopes, and rejects 48 compiled negative controls. Counterflags
are explicit for the hostile CMSIS-inline builds; this is not an attribute-only
claim. The C-envelope audit is structural, not a semantic proof of every branch.

The separate execution runner passes 120 checks on actual Secure-bootstrap and
Non-secure images under QEMU AN505: O2/Os hard/softfp, real eight-region geometry,
initial integer registers including captured r9, PSP/PSPLIM/CONTROL, all MPU
regions, exact admission panics and actual read/write access faults. Sixteen-
region images are compile/link only. The terminal test SVC is deliberately
rejected; it is not a production syscall. No FP stress, PendSV or hardware result
is implied. This runner pins reference identities but does not execute or compare
the reference; that comparison belongs to the independent codegen runner.

```text
Parent static replay, 16 configurations / 48 negatives:
  %TEMP%/cm33f-mpu-first-start-codegen-294896bfca924c85a79bad0a98ba5241
Parent execution replay, 120 checks / 25 QEMU invocations:
  %TEMP%/cm33f-mpu-first-start-execution-7d2d2e26aa7d47cfbdce8fbedc8e1d76
```

Both runners retain input and artifact hashes. The execution model's MVFR and
eight-region MPU observations are recorded rather than replaced with synthetic
hardware claims. Global optimization parity and board qualification remain open.

### C55S Non-secure Construction And Attachment Qualification

The staged NS source now constructs the complete nineteen-word initial frame
and seals an optional pre-start Secure stack request. It does not implement a
runtime provider, handler, allocation integration, first transfer or switching.
The exact ten-file stage inventory and lack of a global selector route are
checked separately from the complete scalar MPU dictionary.

The maintained runner builds and executes the actual pinned M55 constructor
alongside the unmodified Fiber constructor/attachment and optional common
configuration lifecycle. A numeric oracle checks all frame words, captured r9,
record hash, canary and untouched stack. Its real two-image positive traces all
eight Secure query body entries in order through SG from NS Thread mode.
Invalid query/CPU-state cases deliberately use labelled NS doubles, with actual
register disturbances; they are not presented as Secure implementations.

Seven O0/O2/Os, optimized-LTO and hostile modes pass 892 launches and 1175
maintained checks, including 56 compiled source mutants and three reporter
controls. Hostile flags are not cancelled for the production constructor or
attachment. Exact missing/stale lifecycle and missing staged-cohort links fail.
No frame/layout/cohort identity, public operation or Secure import is added.

```text
Focused maintained receipt:
  %TEMP%/fiber-m55-secure-attachment-b2ee7ca2bccb4734b674ac265b185156
results.json SHA-256:
  F1A7BBE9392C01A22186C5912B5F379829AF44FDC778D304A9A7F53520A4C682
Parent independently rehashed 9899 artifacts and all 133 inputs: PASS
Final focused C55S and scalar-MPU central boundary gates: PASS
  %TEMP%/fiber-c55s-boundary-final-e6037439a885412eb36f1e809928dbe6
```

This is staged construction/attachment evidence, not the pending complete C55S
runtime, physical no-FPU proof or hardware qualification. The shared aggregate
replay is a separate checkpoint and cannot be inferred from this focused run.

### Private Cohort And Staged Startup Combined Checkpoint

The full matrix passes on an unchanged 559-input working-tree snapshot. Its
archive entries were independently streamed and SHA-256 checked against the
input manifest. This is not the clean HEAD alone or a published/hosted-CI run.

The snapshot combines the C33S/C55S private cohort guards, C33S ISA ceiling,
protected-MSP policy admission, M55 saved-form correction, staged C3FP first
SVC codegen/execution and staged C55S constructor/attachment. It includes both
O2/Os actual-reference parity runs, all existing runtime/archive/ELF/GC/LTO
checks, the explicit QEMU gates and final settings negatives. Complete-runtime
count remains nineteen. Hardware and hosted CI are NOT_RUN.

```text
Combined receipt / unchanged input manifest / verified source ZIP:
  %TEMP%/fiber-private-cohort-combined-7a653fac91ff4689bdff9f9386208530
Matrix artifacts:
  %TEMP%/fiber-compile-matrix-bf93879dcd3a42f89471e6e3af09ebd4
Source ZIP SHA-256:
  B46452F080949CDD1A3157CD77BD36C4E83C558D1E32DB0A6A26F4E7A9C46A92
```

This is a preservation checkpoint, not final software freeze. The independent
constructor-only reverse-ABI finding below was not covered by its existing
negative links. Later edits require new qualification, not reuse of this PASS.

### A29: Constructor-Only Reverse ABI Guard Can Be Discarded

An actual CM7 probe with `fiber_init` retained but no start shows that GC/LTO
can discard the sole reverse-v1 anchor read in start preparation. A v2-only
common fixture then links. Keeping start preparation makes the same mismatch
fail on the missing v1 anchor. Thirty-two outcomes cover O2/Os, normal/LTO and
direct/archive links with 225 stable inputs. This is a link-guard coverage gap,
not a demonstrated CPU execution fault.

The header also incorrectly described one relocation in every mandatory port
object. The existing matrix counts undefined symbol entries in designated
runtime objects, not individual relocations or constructor objects. Correct
the wording and enforce cold construction and start dependencies separately.

The scoped repair adds the existing reverse-v1 retention read to all 22 actual
constructors, preserving incoming-r9 capture and existing start reads. It adds
no operation, layout/version change, hot-path read or handler instruction.
Standalone test providers must explicitly supply their v1 marker rather than
disable the guard. A maintained actual-source constructor-only mismatch proof
and fresh combined qualification are required before calling A29 closed.

```text
Pre-repair actual-source finding / 32 outcomes:
  %TEMP%/fiber-reverse-abi-architect-8d1859866d8640e2a08eec79cc7f93d8
Receipt SHA-256:
  78100BCCCD410DF45D0AC1174BED753851F3F052041209474AF7C224A58F0EC7
```

The maintained repair gate now passes 32 actual-source CM7 links: sixteen
matching positives and sixteen exact missing-v1 failures, with constructor-
only and start-retained images, direct objects/static archives, O2/Os and
normal/LTO. Eight source-compiled single-call-removal controls reproduce the
old accepted mismatch; no precompiled archive or compiler-hash allowlist is a
test prerequisite. Constructor-only positives prove that start and handler
symbols are discarded. The direct-header probe requires the exact v1 data
dependency. The source inventory covers all 22 current constructor definitions.

```text
Focused maintained link gate, 276 checks / 265 unchanged inputs:
  %TEMP%/fiber-reverse-abi-constructor-fd7c4a8a183348338555a68ad74c3bc4
receipt.json SHA-256:
  C492113B2B8A382B8A5575ED515769D6F71A7A40FC84F4FC5D494BA03EFB7D16
Parent independent rehash: 330 artifacts and 265 current inputs, PASS
Post-repair MPU constructor attribute gate, 24 configurations / 48 mutants:
  %TEMP%/mpu-constructor-attributes-d33d88392c8e4e00b81b7e830540ff21
Post-repair C3FP constructor/static/execution replay:
  %TEMP%/fiber-c3fp-v1-consumer-20261102002103682
Post-repair H7 Debug/Release offline builds and final-ELF audit:
  %TEMP%/fiber-a29-h7-881455bc0fc14a4c84e806981db3e396
```

Independent patch review confirms only 22 cold reads and ten local includes
relative to the preceding archived sources, with existing r9 capture/builders,
start reads, hot paths and assembly unchanged. H7 text increases by eight bytes
in each configuration; strong handlers, slots 11/14 and the two expectation
pointers still pass. No board was programmed. Focused results do not replace
the still-required post-repair combined qualification.

The first post-repair aggregate run stops at the CM33 MPU constructor's exact
undefined-symbol expectation: the implementation correctly adds the v1 data
dependency, but that old expectation omits it. This is a failed aggregate, not
a runtime failure or a PASS. The exact constructor lists are updated for CM0
(with and without VTOR), CM3, CM4, CM33, CM55, CM55F and CM55 MVE profiles; no
wildcard or general reverse-ABI allowance replaces those checks.

```text
Failed post-repair aggregate, 566 inputs / zero source drift:
  %TEMP%/fiber-private-cohort-combined-d6249ec28ef9474f8441fbbe57a4b691
Matrix artifacts:
  %TEMP%/fiber-compile-matrix-111b1683b3f8418eac112eaedd545701
Source ZIP SHA-256:
  EFF4FD1820321D08CBEC84323AE795399D27C491A950E5E2EA975BC6AD26A4FA
Focused eight actual constructor/layout gates after list repair: PASS
  %TEMP%/fiber-a29-construction-tail-3c5c889855a94f6bb8521d70a56558c2
```

A subsequent focused in-process matrix-tail wrapper stops on PowerShell's
native-stderr conversion, before recording a compiler exit failure. It is not
accepted as qualification. A fresh normal child-process aggregate on a hashed,
physically isolated source snapshot is required. Its result applies only to
that archived snapshot, not subsequent changes in the original checkout.

The isolated-driver setup also retains two failed infrastructure attempts.
The long temporary path first exceeds Git's Windows path limit while hashing
the external reference. A short-root attempt then reaches the scalar-v8 gate
but lacks the library Git history needed by its maintained `git show` regression
fixture. Neither failure is accepted as a library PASS or a runtime finding.
The subsequent replay uses the exact same 566 source inputs and verified ZIP,
with an independent copy of Git metadata added only for that historical fixture.
It does not copy later C3FP/C55S changes from the live checkout.

```text
Failed long-root attempt:
  %TEMP%/fiber-isolated-qualification-c22023c571a041249c61207fbbce4d4d
Failed short-root attempt / preserved source snapshot:
  C:/fibq-55dff272e371
Verified 566-input source ZIP SHA-256:
  A85549ED5761AB300B870EED3910EE89045CE2D32570B1A0ECBC88F127616ABF
Fresh replay receipt/log location (qualification must be read, not assumed):
  C:/fibq-55dff272e371/replay-b89f1ace47ea40b2b25afbd226cb35f2
```

### Subsequent Staged Processor Components

After the isolated snapshot was copied, the live tree adds C3FP running SVC
71/72 plus protected FP PendSV, and C55S first-start SVC with guarded paired
Secure initialization/allocation/load. Both remain runtime-selectable zero.
Neither adds common operations, a complete runtime provider or a global route.
Their qualification must not be inferred from the earlier aggregate snapshot.

C3FP's new separate handler component retains its own reverse-v1 and context
dependency through a cold component anchor called from first preparation. There
is no new hot-path read. A focused source-linked proof records 32 ARM objects,
64 matching links and 64 exact missing-v1 failures with GC/LTO, both provider
orders and no constructor linked. Other imports are explicit `defsym` test
sinks: this proves retention only, not handler execution or a complete runtime.

C55S first-start smoke passes eight ordinary/hostile O0/O2/Os and optimized-LTO
modes, 169 checks and 99 unchanged inputs. Parent independently rehashed all
508 recorded artifacts and the current 99 inputs, with no mismatch. It covers
real Secure objects/imports, strong first SVC and guard links, but not new
two-image exception execution. Reference differences include restoring all
initial r4-r11/r9 slots and moving an attached request's first allocation/load
into the owned startup SVC. Neither difference is hidden by an identical-asm
claim. Trusted physical MSP depth remains integration-owned.

```text
C3FP component retention-only receipt:
  %TEMP%/fiber-c3fp-component-retain-6e645329d83b47168e48937fdb832eec
C55S first-start compile/link/codegen smoke:
  %TEMP%/fiber-c55s-first-start-smoke-2612d0cd15b44d089d52c93208395e2e
Frozen 24-file component archive / independently streamed verification:
  %TEMP%/fiber-staged-components-d495196a623c4bf5999624b4b22a4f98
Component ZIP SHA-256:
  27AD18C612CC4A3090DD0439E877ED02AE1377003A79486CF936405A69892ED9
```

New maintained parity/execution gates, C55S attachment replay, reciprocal
implementation review and a later combined source-state run are separate
requirements. No hardware, hosted-CI, complete twentieth runtime or Context
extraction claim follows from this staged preservation checkpoint.

### A29 Isolated Aggregate Qualification

The normal child-process replay completed with PASS on the exact archived
566-input A29 snapshot. Source drift and extra source files are both zero.
It includes all nineteen recorded runtime groups, O2/Os pinned-reference parity,
the existing ELF/ABI/cohort/LTO/negative cohorts and all explicitly supplied QEMU
gates. C3FP is first-start-only and C55S constructor/attachment-only in that
snapshot; later live files are not covered by this aggregate result.

```text
Qualification:
  C:/fibq-55dff272e371/replay-b89f1ace47ea40b2b25afbd226cb35f2/qualification.json
Qualification SHA-256:
  544E1F52B7B640F81FBD0288128F907F2693DFB76E676D912A78C3F6B2C05DC3
Source ZIP SHA-256 (566 inputs):
  A85549ED5761AB300B870EED3910EE89045CE2D32570B1A0ECBC88F127616ABF
Full matrix artifact root:
  %TEMP%/fiber-compile-matrix-b041a16bf9e141fd9e3e4fdcc57ecc3a
Verified artifact ZIP (44,049 independently streamed entries):
  C:/fibq-55dff272e371/replay-b89f1ace47ea40b2b25afbd226cb35f2/full-matrix-artifacts.zip
Artifact ZIP SHA-256:
  F4F6C648C54AACF85CE9BD5D62CBA034C3165FFBBAEA3FE27A9907FBA5FF5B03
```

The first archive-verification attempt rejected Windows ZIP backslash paths;
normalizing archive entry separators then verified every entry against the
unmodified output tree. The archive was not overwritten. This infrastructure
verification correction does not change the source or matrix receipt.

### Subsequent Focused Qualification

The staged C3FP running components separately pass eight O2/Os hard/softfp and
8/16-region reference comparisons, 264 compiled transfer mutants and sixteen
harness controls. Both final receipts use immutable documentation snapshots;
parent independently rehashed 1,489 inputs and 1,169 artifacts per receipt with
zero mismatches before runtime-adapter activation. The independent running
execution gate passes 988 checks, 57 AN505 QEMU launches and 24 sixteen-region
compile-only ELFs. All 2,083 artifacts rehash correctly. A later Markdown-only
wording fix matches the archived original input; this is not a current
all-inputs-identical claim or an assembly-equivalence execution claim.

The current C55S constructor/attachment replay also passes after first-start
sources are added: 892 launches, 1,175 checks, 137 unchanged inputs, seven
O0/O2/Os, optimized-LTO and hostile modes. Parent independently rehashed all
9,899 artifacts and 137 inputs with no mismatch. First-start functions are
discarded in this attachment-only fixture, so this does not qualify first SVC.

```text
C3FP immutable running-parity receipts:
  %TEMP%/fiber-c3fp-running-provenance-20261102l-O2/C3FP-RUNNING/artifacts.json
  %TEMP%/fiber-c3fp-running-provenance-20261102m-Os/C3FP-RUNNING/artifacts.json
C3FP running execution:
  %TEMP%/cm33f-mpu-running-execution-36a098061f3f4f2e974d8f717b680ac9
C55S post-first-source attachment replay:
  %TEMP%/fiber-m55-secure-attachment-d149f2aff1564a9f9bb9ff92ce41e18c
C55S results.json SHA-256:
  502157203447CD7EDDF7653B625519C1755F64DBEFBC82B2045EC3B5C0F5E91A
```

The next live C3FP slice adds thin forward adapters, a protected first scheduler
bridge and actual context/storage/bundle providers without changing its six
existing naked transfer bodies. Twenty-four strict ARM object compiles pass;
complete-group integration and post-activation replay remain pending. C55S
first execution and the new scalar C5TF group likewise require their own gates.
None of these focused records extends the aggregate snapshot, enables a
twentieth runtime claim, removes the transitional backend, or starts extraction.

### C55S First-Start Execution Qualification

The separate first-start gate completes 568 AN547 launches and 5,740 checks
across ten direct/archive, GC/LTO and hostile O2/Os modes, with all development
selectors absent and `CompleteSuite=true`. It compiles and executes the actual
pinned M55 reference startup/Secure sources as well as the Fiber two-image
startup. Thirty compiled actual-source mutation cases hit their exact execution
rejections. Zero-handle and pre-attached first contexts reach the actual Thread
entry through SG and exception return with the independently checked register,
PSP/PSPLIM/CONTROL, allocation-owner and complete Secure-pool image.

The reference's first restore skips initial r4-r11 and uses later SVC100
allocation; Fiber deliberately restores those GPRs and fulfills pre-start
attachment in its owned SVC70. These remain explicit differences. No running
PendSV, full forward provider, public runtime promotion or board result is
claimed by this first-start proof.

Parent independently rehashed all 12,385 recorded artifacts and all 154 inputs
before the subsequent running-component work, with zero mismatch. Eighty-four
repository-local consumed input files are separately copied and ZIP-stream
verified against that original manifest; external compiler/CMSIS/reference
inputs retain their separate identities.

```text
First-start evidence:
  %TEMP%/fiber-m55-secure-first-start-653753cfc13c43c783c83adaf5a9ae54
results.json SHA-256:
  682896D43CD282CC3567C21DC9F881910F21CD790E0E6837A221C5BB3A53BC4D
sha256.csv SHA-256:
  C4A7C0ED20B35C847BC2C32D3AFD20CE45A6F334F548A33634DF79866A644ADD
inputs-before.json SHA-256:
  A13C30828490AA9DAEEA794FB0134BDE2BB5DF9CDB502478509F8361897AD1F6
Exact 84-file qualified repository-input preservation:
  %TEMP%/fiber-qualified-repo-inputs-2193ab964889409cbcf1bff5ad86ba16
Source ZIP SHA-256:
  1632CAA676E4A25E5D204FEB1F86DBF3E181B78A78DD863D4F43772CD8A6C0E4
```

The following scalar running-component slice must independently qualify both
Non-secure-origin and Secure-origin interruption. A Secure-origin EXC_RETURN
cannot be validated by decoding a nonexistent Non-secure hardware frame.
This requirement is not satisfied by the first-start receipt.

### Matrix Artifact Preparation

The matrix now accepts an exact absent `-BuildRoot`, rejects pre-existing
outputs, and preserves explicit outputs and failed automatic runs. Its actual
top-level cleanup block is executed for all eight ownership/keep/result
combinations by a separate filesystem-only gate. Twenty-eight checks pass,
including root/nested-directory/junction rejection and preserved sentinel
hashes. This is CI preparation, not a hosted workflow or a refreshed full matrix.

```text
Filesystem gate:
  %TEMP%/matrix-artifact-paths-ccd8cb19fb744fa7ab29e21c5af4056f/results.json
```

The later `-RequireArchitectureExecution` admission switch prevents acceptance
automation from silently skipping absent QEMU gates or using `-SettingsOnly`.
Fifteen configuration checks execute the actual matrix guard and verify its
placement before tool discovery and output creation. A separate actual matrix
invocation with a deliberately missing compiler and no QEMU prefix rejects
with the required-execution diagnostic first (expected exit 1). The output-path
gate is replayed with all twenty-eight checks passing. These are infrastructure
checks, not a new aggregate matrix, QEMU run or hosted-CI result.

```text
Execution-policy gate:
  %TEMP%/matrix-execution-policy-5b0c96402d5f463d9de9d0e08c8a482a/results.json
Output-path replay:
  %TEMP%/matrix-artifact-paths-3702c9dc9b6247e48eebd917484ca182/results.json
```

### Runtime-Selectable Metadata And C3FP Activation Replays

Three already-complete build-selected profiles (`ARM_CM55_MVEF_NTZ`,
`ARM_CM55F_MPU` and `ARM_CM55_MVEF_MPU`) now advertise
`FIBER_PORT_RUNTIME_SELECTABLE=1`. This corrects capability metadata, not global
auto-selection or hardware status. Forty O2/Os, hard/softfp, lazy/eager and
applicable 8/16-region configurations pass 567 focused checks. Parent independently
verifies all 160 before/after production/layout object pairs as byte-identical,
all 94 phase inputs and all 1,471 recorded artifacts with zero mismatches.

The four C3FP manifest, constructor, first-start codegen and first-start execution
gates are separately refreshed against the staged production runtime providers.
They no longer inject a counterfeit cohort provider when the actual SVC object
is linked. Constructor-only fixtures retain their explicitly scoped provider
because that subset intentionally does not link SVC. Original execution cases
remain, and the new surface records do not claim that all added adapters execute.

The refreshed results include 51 manifest negatives, 4,176 constructor calls
with 1,216 expected panics, 32 production codegen ELFs and 60 negative cases,
and 120 original first-start execution checks plus 28 surface records.
Parent independently rehashes all 1,773 consumed input entries and 3,353
artifacts with zero mismatches. This is still not a complete C3FP common-runtime
qualification: the complete-group gate and activation decision are separate,
and C3FP's staging flag remains zero at this checkpoint.

```text
Metadata receipt:
  %TEMP%/fiber-runtime-selectable-p3-51b2f6eef09346b28f96a3b0d0ebfb01/after/receipt.json
SHA-256:
  095742844843E7A187E8607BC994EDC3E4049E3DBB4259095DA90BF6C42CDA5C
C3FP four-gate receipt:
  %TEMP%/fiber-c3fp-activation-refresh-8e1bbb7f013443cab869826c2be1e0db/receipt.json
SHA-256:
  717EE6DC42FFA46DBAD473D6A0CEDA0E1C74469EF1B968B1AA98DA065FB74177
Exact 84-file repository-local input preservation for these four gates:
  %TEMP%/fiber-qualified-repo-inputs-da2fa921430b491aa9d805465fabf7da
Source ZIP SHA-256:
  E90F27AFB6BF8736143E39828FDEF4E89CC4685274EAFD05EAD4B7F8C543DB01
```

### Staged C5TF Reference-Parity Qualification

The new scalar M55 TF-M CPU/interface group has separate actual-reference
O2/Os generated-code and bounded data-flow qualification. Each optimization
passes 54 closed generated bodies, 89 scenarios, 36 compiled source mutants
and 46 harness controls. Parent independently rehashes each receipt's 1,496
inputs and 572 artifacts with zero mismatches. This compares actual pinned
M55 NTZ CPU sources and the TF-M OS-wrapper reference against C5TF; it does not
execute an actual TF-M Secure image or qualify the complete public runtime.

The attempted concurrent C3FP parity replay is retained as incomplete because
the matrix-policy documentation changed during its broad input census. Its
partial configurations and mutants are not accepted as a final replay. A
separate immutable-source replay is required; the earlier C3FP immutable
component receipts remain historical evidence for their exact sources.

```text
C5TF O2 receipt:
  %TEMP%/fiber-c5tf-parity-final-20261102a-O2/C5TF/artifacts.json
SHA-256:
  591C0F18A8BAC2D3EF777CCA516C3E30C757BF38A15CA4768AB471C925283855
C5TF Os receipt:
  %TEMP%/fiber-c5tf-parity-final-20261102b-Os/C5TF/artifacts.json
SHA-256:
  039C9C668C5466D21DFB1739BDE7FDB9E074E21B02487904F6FDEBEF2FD2E15A
```

### A30: Existing C33S Secure-Origin PendSV Coverage Gap

Source comparison finds an unimplemented reference branch in the existing
scalar `ARM_CM33/non_secure` runtime. Its `PendSV_Handler` accepts only exact
`EXC_RETURN=0xFFFFFFBC`, always saves/restores r4-r11 and assumes a Non-secure
hardware frame. Its restore validator likewise requires the complete initial
19-word image and reads that image's PC/xPSR.

The pinned `ARM_CM33/non_secure/portasm.c` non-MPU handler (lines 441 onward)
tests EXC_RETURN bit 6 after saving Secure state. A Secure-origin interruption
skips ordinary Non-secure GPR/FP frame transfer and retains only the
`[handle, PSPLIM, EXC_RETURN]` Non-secure header. The corresponding restore
branch also skips those Non-secure accesses. This is present with FPU=0 and
is not merely a future FP feature.

This is a confirmed missing source/parity branch, not a reproduced failure of
normal cooperative Non-secure `fiber_schedule()`. Existing segmented parity
and runtime receipts must not be read as coverage of Secure-origin interruption.
The nineteen-profile number remains a count of recorded runtime implementations,
not proof of complete reference-branch equivalence. No acceptance of this gap or
scope exclusion is implied. It must be repaired and independently executed
before full SecureContext parity freeze. The C55S running work is separately
required to establish the actual architectural EXC_RETURN/DCRS and frame
placement by executed Secure-origin interruption; it does not automatically
qualify a later C33S adaptation.

The subsequent C33S A30 source repair admits exact BC/FC origins, reserves the
appropriate 44/12-byte image, conditionally transfers NS GPRs and never reads
NS hardware words for the compact Secure-origin header. Its restore validator
requires an owned nonzero Secure handle for FC. The paired private layout
generation changes to `0x00020001`, and NSC/scheduler preservation snapshots
include NS PSP. Twelve O0/O2/Os production objects and the existing paired
gateway/NS runtime direct/archive/LTO/vector synthetic gate pass. Its ordered
instruction subsets are not closed-body parity or architecture execution.
Actual dual-origin interruption, poisoned absent-frame controls and compiled
branch-removal mutants remain pending. A30 is not yet closed.

```text
Pre-repair 24-file C33S source preservation:
  %TEMP%/fiber-qualified-repo-inputs-0feb653f546c494dabe91c311bf3f6e0
Source ZIP SHA-256:
  5E821301E165C42ACEC0EC2DAB3A8DDD41D346AEFE7823905E1FE2526E0EE2AD
Post-repair paired synthetic gate:
  %TEMP%/fiber-c33s-a30-gateway-af21d075cf174a15b514a98c8ddcaef6
```

An independent architecture probe now executes Secure Thread -> Non-secure
PendSV on AN505. It observes FC (S=1, DCRS=1), Handler CONTROL_NS=0, unchanged
NS PSP and all eight poison words immediately below it. The NS handler's
recorded clobbers of r4-r11 are all undone by hardware on Secure return.
Secure PSP and both CONTROL banks return to their expected state. Three actual
compiled fixture controls reject omitted exception, omitted GPR clobber and
the wrong NS hardware-frame assumption at exact exits 81/88/83. The full
architecture suite has ten passing expected outcomes; its six previous cases
are retained. This is an architecture-fixture result, not execution of the
new production A30 branch or a full FreeRTOS runtime comparison.

```text
Architecture evidence:
  %TEMP%/arm-control-a41faa3c18eb45059fe4b0febd2bf8e6
receipt.json SHA-256:
  A553D7A804F3A56DB8CA8D40726F8C429081E674DB239F6EC3854B82223D7369
Parent rehash: 15 inputs, 67 artifacts, zero mismatches
Preserved 13-file repository-local source ZIP SHA-256:
  51B40BA5BB4C63F8F1968DA035AEEBEB0B95958316D146FD713242B437A7F144
```

### A31: Qualify R9 According To The Actual Calling Convention

An actual M55 TF-M public-init O2-LTO probe exposes a stronger initial-r9
assumption that requires reconciliation with the existing ABI contract.
The constructor temporarily holds `context_end` in r9 before calling the
frame builder; the builder reads that callee-saved temporary, not the incoming
application seed. Native O2/Os pass, while normal LTO and four hostile modes
fail its exact incoming-register oracle. Two compiled controls are rejected for
that exact mismatch. The pre-repair generated-code parity receipt above did
not exercise this cross-caller LTO behavior and remains historical only.

```text
Reproduction:
  %TEMP%/fiber-c5tf-r9-qualified-reproduction/cm55-tfm-10127862dc3246e29e81f67922879a85
Incoming/post-return r9: 0x13579BDF
Incorrect initial frame r9: 0x20010080 (constructor temporary)
```

The first attempted C5TF repair captures the seed before integration calls and passes
it explicitly to the sensitive/general-registers-only builder. A one-shot
post-build assertion checks the seeded slot. The staged C3SO constructor adopts
the same repair before its full runtime qualification. No naked transfer body,
frame geometry or context identity changes. An early C capture does not
guarantee the caller's register value: a follow-up actual probe still fails
O2-LTO and all four hostile tuples, including a legitimate r9 temporary in
the public C wrapper. That attempted repair is not accepted as proof of
incoming-application-r9 inheritance.

The earlier normative decision (2026-07-17 in `DECISIONS.md`) explicitly makes
platform/static-base inheritance conditional on an ABI that reserves r9;
ordinary AAPCS permits it as a general callee-saved register and gives its
initial task value no static-base meaning. The probe currently tests a stronger
ordinary-AAPCS promise. Qualification must separate that interpretation from
real reserved-r9 ABI failures, preserve all failed receipts, and avoid inventing
CPU-specific public/common wrappers to satisfy an unsupported assumption.
The architecture review confirms the dual-mode interpretation. Ordinary AAPCS
tests require caller-r9 preservation on return, a valid initial image and exact
subsequent saved-state restoration, but not arbitrary public-entry-r9 inheritance
through nested C activations. Reserved/static-base tests require the exact
platform seed in the initial and first-restored frame, with the entire common,
port, hook and LTO cohort compiled consistently respecting that reservation.
`-ffixed-r9` is appropriate in that distinct ABI test, not a substitute for the
ordinary-ABI suite. Seed-corruption and caller-preservation controls remain
required. No naked common wrapper or generic ABI change is justified by the
ordinary-mode mismatch alone; the dual-mode requalification remains pending.

```text
Attempted early-C-capture repair reproduction:
  %TEMP%/fiber-c5tf-r9-repair-early/cm55-tfm-efd9356955e748b7998f70c525495d67
Result: 3 tuples pass; O2-LTO and four hostile tuples fail the exact seed oracle
```

### C3FP Complete-Group Runtime Evidence, Still Staged

The real five-operation common runtime and production eight-operation C3FP
provider pass 9,349 checks with 161 AN505 executions. Seventy-two images are
compile/link-only, including the 16-region variants and default-panic links;
no 16-region execution, FreeRTOS execution or board proof is claimed. Direct
and archive, GC/LTO, hostile, vector, lifecycle and negative-link cases belong
to this separate complete-group receipt. Assembly parity remains a different
gate. The source still advertises `FIBER_PORT_RUNTIME_SELECTABLE=0` until the
remaining current-source parity replay and promotion requalification.

Parent independently rehashes 131 current inputs, 120 immutable input copies and
8,534 artifacts with zero mismatches. The 58 repository-local consumed sources
are preserved separately before further activation edits.

```text
Runtime receipt:
  %TEMP%/cm33f-mpu-runtime-819854eb15ea40aeafceff3db708400c/receipt.json
SHA-256:
  64E4927A4B6CFD7F581C5A8C316AA22F533553B0EA3974E1F9A06AB8E3A2E2D6
Repository-input preservation:
  %TEMP%/fiber-qualified-repo-inputs-28f2469261614b2e85a6f1dc7504aee0
Source ZIP SHA-256:
  0C124EBB0BFCAE8768D141A9B95D796B7F9E1485345058007235FB97F24D399D
```

### C55S Running Component Availability

The staged C55S Non-secure source group now contains fifteen files, including
`fiber_port_pendsv.c`. The component implements Non-secure-origin and
Secure-origin transfer branches, private serialized save/select/load planning,
Secure save before NS image stores, and reverse-only current publication.
This is not a complete eight-operation provider or a selectable runtime.
The central source inventory and assembly-only current-slot audit now admit
that exact component without admitting premature runtime providers.

The focused compile receipt passes forty ARM objects across eight modes,
thirty non-LTO codegen scans and four C/C++ header checks. Parent independently
rehashes all forty objects, fifteen selected source files and seven owned-file
freeze entries with zero mismatches. Actual two-image running execution,
Secure-origin EXC_RETURN/DCRS observations, retention/negative controls and
unchanged first-start/attachment replays remain separate required gates.

```text
Component evidence:
  %TEMP%/fiber-c55s-running-smoke-87b020e3f08a4a6c8416ae6acecdc46f
freeze.json SHA-256:
  B7D1A729A50A4114E3A8E7170C3200EED2C03F6E320916A692A5A1134BF48174
Updated exact inventory/layout/negative-manifest replay:
  %TEMP%/fiber-c55s-layout-running-6815bc634ca24c1587e95e39b5114816
```

### C3FP Promotion Qualification

After the immutable running parity and pre-promotion complete-runtime gates,
only selectable metadata and its exact expected fixture facts change to one.
The post-change six-gate replay passes manifest admission, constructor,
first-start final codegen, first-start execution, running-component execution
and actual common-plus-port runtime. The last gate again records 9,349 checks,
161 AN505 executions and 72 compile/link-only cases. Sixteen-region execution,
default-panic execution, actual FreeRTOS runtime and boards are not inferred.
The separate current-code parity replay is not replaced by this execution gate.

Parent independently rehashes 17,450 recorded input/artifact entries from
15 manifests with zero mismatches. The union's 102 repository-local source
inputs is copied and ZIP-stream-rehashed before documentation edits. This
supports the twentieth recorded complete runtime; it does not qualify all
current-tree profiles, missing feature tuples, global optimization/LTO coverage
or the later Context extraction.

```text
Post-promotion root:
  %TEMP%/fiber-c3fp-promotion-e283e071721b469d9dcbc093358f4f09
receipt.json SHA-256:
  65F8F111BE97C3960ED92082574EFAC8B72FCAB29AA0C6DBB887BC7A21166DE8
Repository-input archive:
  %TEMP%/fiber-qualified-repo-inputs-4cd4170a18d64871824d3c5b51d6a123
ZIP SHA-256:
  F4979D999F23E9C6BCAE9EBDD45DFF9A67D3F2FFC95DBAD864DB3CD622E98D81
```

### A30 Secure Companion Generation Replay

The scalar CM33 companion exact-cohort gate passes 496 link checks and 32
compiled query-retention removal controls after the paired private layout
generation changes to two. Parent rehashes both recorded input manifests
(122 entries) with zero mismatches. The older-generation provider remains an
intentional negative fixture. This is link evidence only, not validation of the
new Secure-origin transfer branch; its execution and whole-body parity remain
separate gates.

```text
  %TEMP%/fiber-cm33-secure-cohort-67e8431f70bb4965b5c71271ce241f9b
results.json SHA-256:
  16C939F472A13B11D932341F5216C0FEBC18B2D4D0A88A3144AD8287CB86D9AB
```

### C5TF Dual-ABI Qualification

The consumer gate now distinguishes ordinary callee-save r9 from a consistently
reserved platform/static-base ABI. Sixteen real M55 execution tuples pass
construction, first SVC and four PendSV transfers, plus a legal ordinary-mode
caller-scratch control and four compiled failure controls. Reserved positives
compile the whole common/port/hook chain with `-ffixed-r9`; handwritten hook
assembly also respects that reservation. The earlier stronger-oracle failures
are preserved, not accepted as evidence of a reserved-ABI defect.

The same separate complete-group receipt passes sixteen target ELFs, 103
negative checks and 200 source-derived host adapter scenarios. It tests typed
TF-M initialization/mutex boundaries, not an actual TF-M Secure checkout/image.
Parent rehashes 4,393 inputs before/after and 2,792 artifacts (11,578 entries)
with zero mismatches. The 72 repository-local inputs are preserved before the
subsequent selectable-metadata promotion. Post-promotion replay remains pending;
no new complete-runtime inventory entry follows from that source edit alone.

```text
  %TEMP%/fiber-c5tf-consumer-dual-final/cm55-tfm-dbac04f368cc48ac8a4ec009a9286687
Input manifest SHA-256:
  E0021C79F2906DA30C307FBCAA3B84305ABB92F97B66237FBFF7DFEE15DAB67C
Repository input archive:
  %TEMP%/fiber-qualified-repo-inputs-43a2bf0b75c442b4866486775e9ccace
ZIP SHA-256:
  F3F5C25EBC9A0A93D8EC8C0274A3FE44DB8D87E21A42373B936BD2851A76C03D
```

### Staged C3SO Complete Group And C5SO Addition

The actual common-plus-C3SO Secure-only M33 runtime passes 40,721 checks and
245 AN505 executions, with four compile/link-only images. Parent rehashes
10,322 recorded entries across its three input/artifact manifests with zero
mismatches and preserves 55 repository-local inputs. This still does not
activate C3SO: closed whole-body parity and stronger actual instrumentation,
stack-protector, coverage, profiling and sanitizer proof remain independent
gates. The earlier modes labelled hostile cover register allocation/frame
pointer transformations, not that complete compiler-instrumentation bundle.

```text
  %TEMP%/cm33-secure-only-runtime-2511c36b61704c9aa04cd97c3d39d0ab
receipt.json SHA-256:
  79524B8F1E47B4770F18A697535BFD1B908A6306E0DE361E7637FF857856305F
Repository input archive:
  %TEMP%/fiber-qualified-repo-inputs-d36458399a6c42a3848ecf92ff7b198e
ZIP SHA-256:
  2CABDE0576E27E90230508DCBF4DB990B5C5A9D31134E924B1E02214B1693C28
```

A distinct scalar Secure-only M55 group is now staged as C5SO, port ID
`0x4335534F`, layout `0x00010001`, feature `0x02`, and storage
`arm_cm55_secure_only` revision1. It uses the audited scalar algorithm but owns
an exact M55/CMSE3 manifest and Secure FD/F9 exception forms. Its real pinned
M55_NTZ Secure-only reference and Fiber O2/Os objects pass 110 focused checks,
including 29 exact-diagnostic negatives. Parent rehashes 328 recorded entries
with zero mismatches. C3SO execution is not reused as a C5SO result; independent
AN547, complete-group and closed-body parity gates remain required. Both
profiles stay runtime-selectable zero and outside global routing.

```text
  %TEMP%/cm55-secure-only-786b358bd94e4652b0db41ef13957c5f
```

The subsequent focused C5SO manifest replay expands to 117 checks and 36 exact
negatives, adding wrong-core CMSIS, VTOR, priority-width and PAC-spelling cases.
Parent rehashes 337 recorded entries with zero mismatches and preserves the
40 repository-local inputs. No runtime, naked body or identity changes in this
test-only expansion.

```text
  %TEMP%/cm55-secure-only-0a9b0ab5d66149d3901af5c5ee677096
  %TEMP%/fiber-qualified-repo-inputs-a19fc5eb19c84606ae3c229936f50514
ZIP SHA-256:
  9C5CECDB38C41824470BBDBCBC3C1D8051E3D153D7D3815DC5B5C8324F945EAF
```

### C5TF Post-Selectable Object-Role Qualification

The post-metadata consumer replay passes with runtime-selectable one. It
checks CPU+boot, initializer and optional mutex wrapper as separate dependency
roles before accepting the combined group. CPU+boot may not import the public
`fiber_current` operation merely because the optional wrapper legitimately
does. Normal and native-lowered LTO roles reject both a compiled public-call
leak and a weak definition of a common-owned reverse symbol.

The final focused receipt passes 24 role proofs, sixteen target ELFs, 112
negative checks, 200 source-derived host adapter scenarios and sixteen actual
M55 dual-r9 tuples with controls. Parent independently rehashes 11,803 entries
across three input/artifact manifests, with zero mismatches, and preserves all
72 repository-local inputs. This records software runtime implementation 21;
actual TF-M Secure-image/PSA integration, global adversarial closure and the
later all-profile/final-LTO qualification remain separate obligations.

```text
  %TEMP%/fiber-c5tf-role-boundary-final/cm55-tfm-d4a569b3ee514afbab41f2d59139a6fa
Input manifest SHA-256:
  735BF9778772B4396A5F992C710C4816CBAD8B3553EED87FFF6FAA87AB3C6186
Repository input archive:
  %TEMP%/fiber-qualified-repo-inputs-c770e3d17baf41138be002473ea0c237
ZIP SHA-256:
  E0D1A75CEE2A08A690E435262B4E077B22930C0A7CF7F123EFD47E120AC51AD9
```

### C55S Component Qualification And Forward Candidate

Before forward integration edits, the independent scalar M55 SecureContext
running component passes 1,000 real AN547/reference launches and 3,964 checks:
70 positives, 810 exact panics, forty Secure-corruption faults and eighty
compiled controls across ten modes. Actual Secure-origin interruption uses
FC/DCRS1 and a three-word NS header, not an invented NS hardware frame. Parent
rehashes 318 input entries and 13,162 artifact CSV entries with zero mismatches,
then archives 89 exact repository inputs before changing production.

```text
  %TEMP%/fiber-m55-secure-running-30e68a6a3b86400db670fb16320a4e7f
results.json SHA-256:
  62B27BA06E6A15AA2E41BFCA676FA87F152C21C268FB748EB022A7EB1257C977
Source archive:
  %TEMP%/fiber-qualified-repo-inputs-6e3ef16a03b64642814b30ccfb3f1fe3
ZIP SHA-256:
  ED168B1790CCF58D7FDD261268138A4FC5074EB899324B8D1445B9A7D3DD8739
```

The next candidate adds `fiber_port.c`, all eight forward operations and the
real common runtime boundary. CPU/vector/priority/MSP preparation now precedes
the protected first scheduler callback; common still publishes current.
Running validation separates optional record hash and address-map hooks from
mandatory structural/frame checks. SVC/PendSV naked bodies are unchanged.
Thirty-two strict O2/Os objects across all four hash/map settings, followed by
the maintained geometry/inventory/six-unit/negative-manifest gate, pass. Those
focused compiles do not transfer the earlier 1,000-launch receipt to the later
source state. Runtime selection stays zero while complete-group execution,
archive/cohort and fresh reference/codegen gates are in progress.

### A32: Transitive Sensitive-Compiler Closure

**Open before software freeze.** New raw-flag compiler proof finds a real
transitive attribute gap in the staged C3SO/C5SO groups: unannotated hash and
validation helpers, port inline helpers and CMSIS inline functions can acquire
instrumentation even when their public caller has the canonical sensitive
bundle. Protecting one enclosing function is not a transitive call-graph
guarantee. The selected-function generated-code probes and existing limited
inline-helper cohorts did not establish that stronger property.

This is an additional attributes-only closure requirement. The existing
runtime-boundary contract explicitly requires counter-options on selected-port
translation units when hostile flags are enabled globally. An unaided raw
failure therefore does not invalidate an earlier compliant counterflag build.
The repair closes the stronger source-attribute property; it does not rewrite
the earlier evidence or silently remove the documented integration flags.

C5SO's complete baseline/counterflag suite passes 293 QEMU executions, four
link-only images and 62,507 checks. Parent rehashes 16,506 input/artifact entries
with zero mismatches and archives 57 exact repository inputs. The explicit
counterflags result is preserved as limited evidence, **not** accepted as an
attributes-only pass or a frozen-ABI/build-policy change. C3SO's separate new
48-case compiler phase is likewise not a new complete-suite qualification.

```text
  %TEMP%/cm55-secure-only-runtime-7cb860c1b3044a6c8ea8a2c80b6fca65
receipt.json SHA-256:
  4794CFC45A1A909D57AF543A93E4349C924B176519712B3160BDEBE4FC77EC5C
Source archive:
  %TEMP%/fiber-qualified-repo-inputs-e41ac5bf733d409da7ed0c0117e702d1
ZIP SHA-256:
  E55A37F22AFDE34C7E75845B6F1C66CA854B08CFA7CCEF3CF5D9FA7E69400319
```

Repair ownership is scoped to the two Secure-only groups first: canonical
attributes on the complete non-inline helper chain, inline-sensitive attributes
on forced-inline helpers, and annotated port-owned CPU operations instead of
unannotated CMSIS function calls. No naked transfer/layout change is planned.
Raw flags must remain enabled in the acceptance proof; counterflags cannot
silently qualify this contract. A maintained whole-group compiler audit is
being added for the remaining profiles, including baseline, actual native LTO,
active compiler probes and compiled annotation-removal controls. Similar source
patterns elsewhere are an audit target, not yet an all-port defect finding.
Recorded ordinary-build runtime/parity receipts remain historical evidence;
there is no new all-profile/no-known-software-gap freeze claim.

#### CM7 Transitive Repair

A direct raw `-finstrument-functions` replay also reproduces the A32 defect
inside CM7 `fiber_port_runtime_schedule()`, via unannotated CMSIS and local
inline CPU operations. All three selected CM7 objects acquire hooks before
the repair. Their exact inputs, preprocessed units, assembly and object
evidence remain at
`%TEMP%/fiber-cm7-sensitive-prefix-3054b82e5e9f4911852835de9bb4aebb`.

CM7 now uses canonical attributes throughout the non-inline and inline helper
chain and port-local annotated CPU/NVIC/barrier operations. Public common cold
`fiber_init` and scheduler-configuration exports are intentionally ordinary;
this repair does not silently change that separate public attribute contract.

The final focused replay passes 160 flag/profile/optimization combinations,
480 actual translation-unit compiles and eighty native LTO group lowerings.
All 320 inspected native outputs are free of compiler hook symbols. It spans
O0/Og/O2/Os/O3, no-FP soft and hard-FP, baseline, instrumentation, SSP, coverage,
UBSan, trace-PC, profiling and combined raw flags, without counterflags. Input
hashes are stable across this run. This focused parent probe is not a claim
that the maintained all-profile transitive-closure gate is complete.

```text
Final focused compiler run:
  %TEMP%/fiber-cm7-expanded-637a8ccd77c34cf5b4e91776ed0841ae
Nine-file exact CM7 source archive:
  %TEMP%/fiber-qualified-repo-inputs-f18a18acfc1b4cf396ce1b068f94a4b8
ZIP SHA-256:
  8323240DDDEA93F3DB2128E628C3C080F5187925EFA9C6FB208201C3ACC62BA8
```

#### C5TF Transitive Repair

The first maintained whole-port raw-flags run independently reproduces A32 in
C5TF CPU, initializer and mutex helper chains. Non-inline helpers already carry
the canonical attributes; the remaining hidden hooks originate in unannotated
CMSIS inline calls. The selected dictionary now owns annotated raw CPU reads,
WFE and NVIC priority byte operations. No naked text, frame or context identity
changes. Source-derived host boundaries retain the same CPU-state semantics
under the new names rather than bypassing production preconditions.

The complete consumer suite passes again: sixteen target ELFs, 112 negatives,
24 object-role proofs, 200 host scenarios and sixteen actual M55 ordinary and
reserved-r9 tuples with controls. Parent rehashes 11,803 input/artifact entries
with zero mismatches and preserves 72 exact repository inputs. This is not yet
the independent attributes-only whole-group closure or fresh immutable parity
receipt, and no actual Secure TF-M image or hardware execution is implied.

```text
  %TEMP%/cm55-tfm-e3dd95d7dce04a3e8c0c824ad88655f7
Source archive:
  %TEMP%/fiber-qualified-repo-inputs-dd9d0efe49db482bbabe68d2816e3f0f
ZIP SHA-256:
  891B15A3B37B5C4E1F6777EA4847F1DF680E1652E7D81FC28F36BED83185C241
```

#### C3FP Transitive Repair

The same raw-flags audit identifies unannotated CMSIS inline CPU operations in
the C3FP SVC/PendSV helper chains. Ten annotated local primitives now replace
those calls: IPSR, CONTROL, PRIMASK, FAULTMASK, PSP and PSPLIM reads, WFE, and
validated priority-byte index/read/write operations. No naked body, context
layout/identity or runtime-selectable metadata changes.

The six maintained profile gates pass again: manifest, constructor, first-start
generated code, first-start execution, running execution and complete-group
runtime. The latter records 161 AN505 executions and 9,349 checks. The parent
rehashes 17,450 entries across fifteen manifests with zero mismatches and
preserves the union of 84 exact repository-local inputs. This does not yet
qualify the independent raw whole-group closure or fresh pinned-reference
parity replay; sixteen-region/default-panic compile-only limits still apply.

```text
Complete-group runtime:
  %TEMP%/cm33f-mpu-runtime-e77cc17fb945475eb601ea05c9b8096d
Other five component gates:
  %TEMP%/fiber-c3fp-a32-components-c2fd9ab296e74c2e966c6326dbed5011
Exact source union:
  %TEMP%/fiber-qualified-repo-inputs-b300424c6cab49779b7dac08ae0abbd4
ZIP SHA-256:
  D97289FE58A0B546D9EC2F6B60403C86435E754100F98A8BFF178D118E814691
```

#### Repaired C5TF And C3FP Reference Replays

Separate immutable-source replays now pass against the pinned reference. C5TF
closes 55 generated bodies per optimization at O2/Os, with 105 bounded scenarios,
43 compiled mutants, eight independent R9 corruptions and 49 harness controls
per optimization. All eleven captured production files still match live bytes.
C3FP running parity passes eight O2/Os, hard/softfp and 8/16-region tuples,
264 compiled transfer mutants and sixteen controls. Seven production files match
exactly and the eighth differs only by the recorded EOF newline cleanup.

Neither bounded-model comparison replaces actual runtime, raw hostile-LTO
whole-group closure or board evidence. The completed profile execution receipts
and the independent raw-closure gate retain their own distinct scope.

```text
C5TF immutable replay:
  %TEMP%/fiber-c5tf-a32-immutable-20261102-bdccb02d3f17410bb468dbb66e363374
qualification.json SHA-256:
  6F5434A42CE01D523F85493121E9A0089AB9B951C58B9458F3981F2EB9B05FB9
C3FP immutable replay:
  %TEMP%/fiber-c3fp-a32-immutable-20261102-c88eaab7aff6485fa1904ded9f2996e5
qualification.json SHA-256:
  10775407DACF2203E318AC97C0C0413EEEAB38E71944A9D4114727A0101219C0
```

### A33: CM7 Native-LTO Literal Reach

Retaining the complete sensitive helper chain exposes a separate real build
failure: native LTO can merge `.text`, leaving a naked pseudo-LDR pool beyond
instruction range. Each of the three CM7 transfer blocks now emits `.ltorg`
only after its final unconditional panic-loop branch. No executable instruction
order or frame semantics change. A matching O2 generated-assembly comparison
retains all forty start, eighty SVC and ninety-two PendSV normalized body lines;
only the local-pool directive is omitted from that sequence comparison. Literal
data placement and complete binary equality are deliberately not claimed.

The maintained CM7 archive/vector gate passes normal and LTO links, duplicate
strong-handler rejection, and a compiled three-pool-removal control. The
control must fail specifically with `offset out of range` and not an undefined
reference. The synthetic ELF and classic-audit fixtures now retain their
freestanding `memcpy`/`memset` implementations through final LTO lowering;
these remain allowed libc dependencies, not a production ABI expansion.

```text
Maintained positive/compiled-negative gate:
  %TEMP%/fiber-cm7-postfix-elf-7b0da974c3d14378a00da1a16332b814
Normalized pre/post instruction comparison:
  %TEMP%/fiber-cm7-pool-instructions-46fb5e3181b143fe9144b49e88474ed8
Refreshed classic guard execution, 84 ARM ELFs / 842 checks:
  %TEMP%/fiber-classic-audit-d2a101c7324442828a54f1dae72b4b41
```

H7 generated Debug and Release rebuilds pass with the current selected CM7
group. Final ELF checks prove strong SVC/PendSV, slots 11/14 with Thumb bits,
one private context cohort, one storage cohort and both matching retained
expectation pointers. The evidence includes pre-build backups, post-build ELFs,
maps and logs. Neither Cube regeneration nor board execution was performed.
This does not reactivate the hardware claim or qualify unrelated port changes.

```text
H7 offline build/ELF evidence:
  %TEMP%/fiber-cm7-postfix-h7-ea403b72083c4110baed3e5ede8e0193
elf-proof.json SHA-256:
  27BC26A1FCD81760E2C53C9276C542BE56C9A5412E3AA1D1B61AD86633495D71
```

### A34: Thumb-1 Vector-Load Operand Constraints

The constructor-r9 exploration exposes a separate real assembly constraint bug,
not an observed R9 ABI mismatch. `ARM_CM0/fiber_portmacro.h` expresses the raw
initial-MSP `LDR` with general `r` output/base operands; GCC can select r8-r10
under register pressure, which the Thumb-1 instruction cannot encode. The same
pattern exists in the CM0 MPU raw vector-slot helper. Both now use `=l` / `l`
constraints, retaining a volatile read and the architectural address-zero path.
The change does not alter a naked transfer or context/frame identity.

The maintained `test_thumb1_vector_constraints.ps1` gate compiles the actual
headers and executes eighty real ELF probes: two profiles, VTOR absent/present,
O0/Og/O2/Os/O3, ordinary/reserved-r9 and normal/native-LTO. Zero/nonzero sources,
SP and callee registers pass 4,800 checks. Four compiled controls restore only
the old constraint pair in real preprocessed source and fail specifically on
low-register LDR encoding. Input capture follows real preprocessor dependencies,
including compiler system headers and resolved toolchain subprogram hashes,
rather than observing unrelated mutable profiles. Parent rehashes 636 recorded
entries across three manifests with zero mismatches.

```text
Focused gate:
  %TEMP%/fiber-thumb1-vector-constraints-284bb351c44b43b2bc06a4afab869141
results.json SHA-256:
  880F488983338835A3DD0A7DE73877CBD737636DA4C03825BDD648E846C4EE69
Exact 28 repository-local inputs:
  %TEMP%/fiber-qualified-repo-inputs-ecd4400040164ddeb8f0c316736623bd
ZIP SHA-256:
  FD7F2D364AE05C98AEFEEFB21E16F58E4B3EDA1494428A26E50B246BBB0336A5
Refreshed classic guards, 84 real ARM ELFs / 842 checks:
  %TEMP%/fiber-classic-audit-e9a6bbc2789345b195145d7fe17f8eb1
```

The prior four failed hostile constructor builds remain historical evidence.
The complete constructor-r9 replay and fresh pinned-reference transfer parity
are separate qualifications, not implied by these focused probes. The gate is
now part of the central matrix. It does not execute SVC/PendSV or a board.

The reference CM0 `portasm.c:vStartFirstTask()` deliberately does not rewind
MSP because VTOR is optional. Fiber's validated rewind/remap adaptation is now
described accurately in the CM0 MPU ledger instead of claiming reference
identity for that stronger policy.

### A30 Actual Common-Runtime Dual-Origin Execution

The generation-two scalar C33S pair now passes a separate actual-common AN505
suite: 75 launches and 2,382 checks across O0/O2/Os and O2/Os LTO. It executes
both real NS and Secure-origin transfers, both mixed attachment directions,
all-register resumption and actual CMSE pool transitions. A bounded FC image
at stack_top minus twelve proves only its final restore path; it is explicitly
not executed as an invented Thread continuation. Mapped poison and a required
CPU read watchpoint check the three-word extent guard, while compiled branch
removals prove sensitivity to erroneous NS GPR transfer. A separately compiled
layout-generation-one companion must be rejected by the current NS identity
query before initialization/allocation.

Parent independently rehashes 204 input entries plus all 2,112 CSV artifact
entries with zero mismatches and archives the 66 exact repository-local inputs.
The central explicit-QEMU matrix now invokes this maintained gate. This closes
that focused runtime branch evidence, not the independent whole-body parity,
transitive compiler-attribute closure or board obligations.

```text
  %TEMP%/fiber-cm33-secure-origin-c72804f2abed47478d18f53cc451e191
results.json SHA-256:
  4F58DB769ECFB670DD209920803A3CD518FFB26A05A8BF39043CDDCDA2AF7310
Source archive:
  %TEMP%/fiber-qualified-repo-inputs-f05d6f2d92414d7faeb75953468ca35e
ZIP SHA-256:
  18CE199698613E73E05536D4D29C6442F27A74B853916B9F9EFB02D1A511E62B
```

### ec02a22 Combined-Matrix Attempt

The complete required-execution matrix was attempted from a Git-archive snapshot
of `ec02a2284aaf068bfaef24664943147c2f80f3d7`, not the concurrently edited shared
tree. It stops during O2 C3SO closed parity on `Boot/exact undefined set`: the
repaired boot object now references approved `memset` as well as `memcpy`, but
that profile's comparison baseline still expects the older set. This is a
**FAIL**, not a combined qualification or evidence that later gates ran. The
parity owner must inspect actual codegen and qualify a precise baseline update;
the existing approved-libc policy is not a reason to bypass the exact check.

All 863 snapshot files rehash without drift. Preserve both the failed output and
the source archive before replaying a later checkpoint. The separate successful
profile/focused receipts above do not turn this full-matrix failure into PASS.

```text
Immutable source/run record:
  C:/fq-0501eb9962a8/qualification-plan.json
  C:/fq-0501eb9962a8/matrix-result.json
  C:/fq-0501eb9962a8/source-rehash.json
Failed matrix artifacts:
  C:/fqm-0501eb9962a8
Source ZIP SHA-256:
  77A8A4CA00BF261C485A845B20296D95CB0A5EEDFE6B768C861462493A44C80A
```

### Staged C3FS Pool And Initializer

The FP Secure companion now owns real static pool backing and a ninth NSC
boot-initializer export. Its private cohort advances to generation two; the
public layout identity does not change. Initialization follows the pinned
Secure Init/Context policy order, adds caller/quiescent-state admission and
sticky failure markers, and verifies the complete pool scrub and owned CPU
policy readbacks. It does not supply an allocator or a placeholder transfer.

Fresh bounded qualification passes 319 checks across eight hard/softfp,
O2/Os and normal/LTO configurations: 1,056 initializer/pool calls, 768 query
calls and 2,664 constructor/attachment calls, with seven compiled controls and
two decoder controls. Parent independently rehashes 8,151 recorded input/artifact
entries and all 35 owned source files with zero mismatches.

System-register/MMIO execution is explicitly doubled and stops before BXNS.
This is not two-image SG, FP preservation, complete runtime or hardware proof.
The profile remains `RuntimeSelectable=0`; real allocation and paired FP
transfer qualification remain required before activation.

```text
  %TEMP%/cm33f-secure-manifest-639466a7c86a4342a2f175f863446530
receipt.json SHA-256:
  AFCDB8AB78AB83050C7FBB709A0B8E15685F20C0CAD487054163D165B068209E
```

### Secure-Only Raw Compiler Closure Replay

C3SO and C5SO complete maintained suites now each execute 293 QEMU launches,
four link-only cases and 48 attributes-only raw compiler cases. They pass
64,266 and 64,275 checks respectively, including forty compiled attribute
removals and eight sensitive-to-cold-call controls per profile. Every real port
object is raw-compiled and its complete native group rejects compiler hooks;
common sensitive function extents are checked separately from the intentionally
ordinary `fiber_init` and scheduler-configuration functions. Runtime execution
pairs the raw port with real neutral common objects, not fake reverse services.

The two smaller manifest gates now admit exactly the observed `memset` import
in addition to already approved `memcpy`; their exact-set comparisons remain
unchanged. Fresh O2/Os manifest runs pass for both profiles. This does not admit
new compiler/internal-helper imports or qualify arbitrary libc implementations.

Parent independently rehashes 30,991 entries across six suite input/artifact
manifests with zero mismatches. Neither test-only change activates a port:
both remain `RuntimeSelectable=0`, and hardware evidence remains absent.

```text
C3SO:
  %TEMP%/cm33-secure-only-runtime-ec2559e75a2046e5a767eb3324d5b3b3
receipt.json SHA-256:
  73EB96649DDB0E515CDEB8DE6BBB9FA4F699549960D41139D2F321D59300BBD3
C5SO:
  %TEMP%/cm55-secure-only-runtime-cafbb9960c7d4777b49bcbc588235bd3
receipt.json SHA-256:
  83EF5D56FB84093B81275DE06FF4EF4B79DA0F642473BFFB7781829C19E407EA
Refreshed smaller manifest gates:
  %TEMP%/cm33-secure-only-974ea1840787494d933aba1776966123
  %TEMP%/cm55-secure-only-821a91f4e62f4e6e825aad81d32b056d
```

### A32/A33 CM3 Helper And Literal-Reach Repair

CM3 now protects its complete selected-port helper chain with canonical
attributes and local integer CPU primitives. The prior immutable baseline
exposes raw hooks and actual unsectioned native-LTO literal-range failures.
Fresh repaired-source closure passes thirty cells and 120 compiled controls
over all five optimization levels, normal/native LTO and both LTO text layouts.
Parent rehashes all 59 inputs and 3,716 recorded artifacts without mismatch.

Frame geometry and executable naked transfer instructions are unchanged.
Terminal `.ltorg` bounds pseudo-LDR reach without a fall-through data path.
Natural post-repair pool removal happens to link; a separately compiled
8,192-byte unreachable layout-pressure positive/removal pair proves range
sensitivity. The leaf ledger records that distinction instead of claiming
every pool-removal build must fail.

Fresh O2/Os pinned-reference ordered checks pass the three CM3 transfer
mechanisms; the independent classic regression executes 842 checks in 84 ARM
ELFs. Eleven architecture/boundary source gates also pass. These focused
receipts do not qualify every helper against the reference, replace a complete
constructor-r9 replay or imply a board run/global matrix PASS.

```text
  %TEMP%/fiber-cm3-raw-repaired-19294e064859413e9fc2e1c3714fbf5b
audit/results.json SHA-256:
  33F25FA1845EC5533C370BAB6D2382314F734BC9BE7DF59F4EC7045C1EACBBEE
Exact forty repository-local compiler-proof inputs:
  %TEMP%/fiber-qualified-repo-inputs-51557fd475124d1095c29cf4587354c9
Source ZIP SHA-256:
  1BF101F4DD065A71073ABDC3BE082BB63E6CC23F96A1F006CA0039EF62C48CE4
```

### Maintained Global Raw-Flag Inventory

The new `test_sensitive_port_closure.ps1` records the entire requested native
source-group inventory and fails on raw compiler hooks, unqualified builds or
input drift. It does not silently skip failing profiles. The immutable O2/Os
inventory completes all 336 attempted cells: 218 pass, 106 fail the additional
raw policy and twelve fail to build. The 1,607 compiled controls and zero drift
do not turn this receipt into PASS. Ordinary builds using the documented
mandatory counterflags retain their separate qualification.

Remaining literal failures concern CM0, CM4, transitional v8-M and the scalar
CM33 Secure companion. Other raw failures require transitive helper protection;
their exact profile/body inventories are retained in the receipt. This is an
explicit software-freeze gap, not a physical-board finding.

The refreshed CM3 constructor-r9 subset separately passes 21 ELFs, 84 calls and
168 bounded restore slices without drift. It does not qualify the remaining
profiles or exception/FP/security execution. Parent also reruns the maintained
CM3 compiler-closure gate: twelve O2/Os cells and 61 controls pass, including
actual preprocessed literal-pool layout-pressure controls.

```text
Global raw inventory, FAIL:
  %TEMP%/fiber-sensitive-port-closure-10f640855c124e58abfd9f79cec30ad2
results.json SHA-256:
  698828CE13A78FC4A0B384EAD6F4FC09D4B200172FFA49187CC1ECC3F3A51FCE
CM3 focused constructor replay:
  %TEMP%/fiber-constructor-r9-74b244db4e004c36be0fe02bf84de9e5
Parent CM3 maintained compiler replay, PASS:
  %TEMP%/fiber-sensitive-port-closure-7f5c68febefb4c1291019568470c23ec
```

### C3FS Actual Paired Initializer Replay

The separate maintained initializer gate now executes two real M33 images,
generated SG veneers and the unchanged production pool/gateway objects on
AN505. The complete hard/softfp, O2/Os, normal/LTO and named raw-hostile replay
passes 628 CPU launches, 24 compiled controls and 1,960 fault-classifier
mutations. Twenty-four actual pinned reference objects are retained separately;
this is not FreeRTOS scheduler execution or whole-port equivalence.

Parent independently rehashes 12,251 entries across three input/artifact
manifests without mismatch. Exact Secure UDF/frame/status oracles distinguish
terminal fail-closed cases from false admission, timeouts and unrelated faults.
Named destination-register readback injections remain explicit corruptions,
not observations of a coherent alternate CPU state. FP access is exercised,
but FP preservation, allocation/load/save and full Fiber runtime are not.
The staged profile remains `RuntimeSelectable=0`; no public identity, layout,
production executable code or hardware qualification changes in this slice.

```text
  %TEMP%/cm33f-secure-initialize-fb5733242101497bb6294c25eaa5759e
receipt.json SHA-256:
  6654D36F9E9C2082C942D913BAE657F2591C5076DEB78AEF6D965501A7C5A8A6
```

### C55S Complete Staged Common Runtime Replay

The maintained two-image AN547 suite now passes its complete 2,490-launch
inventory plus one actual priority-mask probe: 14,998 assertions, eighty
variants and 640 positive Secure-origin switches. It exercises real common
lifecycle/reverse state, all eight forward operations and the production
twelve-entry Secure companion without forced includes or fabricated runtime
providers. Direct/archive/GC/LTO, exact cohort/reverse/provider failures,
vectors, both NS/common r9 ABIs and named hostile builds have separate oracles.

Parent independently rehashes 160 inputs and 44,204 artifacts with no mismatch.
The Secure side uses standard CMSE ABI, not reserved-r9. Hostile cases budget
generic stack-check probes with 8 KiB task stacks; the retained failed 4 KiB
development run prevents a claim that raw flags eliminate probes or preserve
minimum-stack safety. Documented integration counterflags remain required.
This is staged QEMU runtime proof, not physical hardware, whole-reference
equivalence, every model/geometry or automatic public activation. C55S remains
`RuntimeSelectable=0` pending its independent admission/freeze gates.

```text
  %TEMP%/fiber-m55-secure-runtime-5e37cf63fd6d49de9471276f511e8027
results.json SHA-256:
  2EE13B8DD7019AAFF4C1D0B43385B5DE7588EFC618218722226B0F2FB496E2FC
```

### C3FT Actual FP/Common Execution Replay

The staged FP TF-M runner now passes 32 consumer ELFs, 288 exact negatives,
212 typed host scenarios, 320 actual M33 CPU launches, 72 compiled mutants,
four classifier controls and forty raw fixture checks. Actual execution uses
real common state and the complete four-object selected-port group, hard and
softfp, lazy/eager FP policy and ordinary/reserved-r9 modes. All eight forward
definitions remain in every execution image. Parent independently rehashes
20,246 entries across three input/artifact manifests with zero mismatches.

The Secure bootstrap and typed NS TF-M interface are test providers. This does
not execute an actual external Secure TF-M image, qualify hardware, replace
the independent pinned reference parity experiment or activate C3FT. A missing
explicit QEMU root is recorded as `NOT_RUN`, never CPU qualification. The
profile remains `RuntimeSelectable=0` pending its separate admission gates.

```text
  %TEMP%/fiber-c3ft-actual-final/cm33f-tfm-155a6496d2f4414da005db8cc818f073
receipt.json SHA-256:
  515CA94D505B32CBA8CF50CA855BE96103940E124B60A445FA4C409E6188BA2D
Exact 88-source archive SHA-256:
  8C9A44E0AB58927D11897D3B00152663DEA3EF7A2E74FA92A8C0AF2F81A5B38C
```

### Central Staged-Proof Dispatch

The central matrix now invokes the maintained C3FS initializer, complete C55S
runtime and C5SO runtime under its explicit architecture-execution guard. C3FT
consumer/adapter checks run unconditionally, with actual CPU execution only
when QEMU is explicitly supplied; the C3FS manifest/pool gate is also included.
All staged expectations remain zero. No development subset is used by these
dispatches, and no source layout or runtime-selection policy is changed.

The independent matrix policy runner passes 41 admission/dispatch checks.
This is infrastructure proof, not a fresh combined-matrix or CPU receipt. The
profile execution receipts above remain separate until a new immutable-source
combined run completes. The earlier retained combined failure is not relabeled.

### Classic MPU Raw Helper Repair

CM3 MPU and CM4 MPU now own canonical sensitive inline CPU primitives instead
of entering instrumentable CMSIS helpers. The twelve naked transfer bodies,
frame/layout identities, MPU policy and errata mechanics are unchanged. Each
fresh immutable primary-profile compiler suite passes thirty baseline/raw
cells and 150 compiled controls at O0/Og/O2/Os/O3 with ordinary and both native
LTO text layouts. Parent rehashes 59 inputs and 3,716 artifacts for each suite
without mismatch; both preserved pre-repair raw receipts remain FAIL.

Fresh paired O2/Os objects pass the maintained twelve ordered mechanisms across
the two profiles. The existing CM3 layout/runtime and CM4 M4/M7 8/16-region
archive/GC/LTO/ELF integration gates pass separately. This is not all FP ABIs,
whole-body reference equivalence, global matrix qualification or CPU execution.
The exact leaf ledgers retain the commands/artifact roots and limits.

### bc520c5 Combined-Matrix Replay

The required-execution matrix is replayed from 915 immutable files at
`bc520c5a722ca70a461561cf30a59eb4ad8a4b3d`, with zero source drift. An initial
parent PowerShell wrapper abort on compiler stderr is retained separately as
an infrastructure failure. The corrected replay fails the real O2 C33SCOHORT
exact gateway dependency check. Earlier O2 A30/C3SO/C5SO/C3FP/C5TF and ordered
transfer passes do not turn that combined result into PASS; later gates did
not execute. The actual dependency/call-site change requires a precise parity
repair and new qualification, not a blanket allowlist expansion.

```text
Immutable source and both attempt records:
  C:/fq-e6379d9d53
Real failed matrix artifacts:
  C:/fqm-e6379d9d53-r2
Replay result:
  C:/fq-e6379d9d53/replay-02/matrix-result.json
```

### Secure-Only Selected-Group Admission Replay

C3SO and C5SO add unchanged public portable-application/default-policy links
without private/CMSIS dependencies in that consumer, plus constructor-only
incompatible-common static-archive rejection. Each real negative must fail
solely on the absent v1 anchor; removing only its constructor retain read
must link and execute the named causal control. Start/handler extraction is
not used as a substitute for constructor ABI binding.

Fresh complete suites pass 65,798 C3SO and 65,807 C5SO checks. Each executes
297 QEMU cases, 48 raw compiler cases, eight portable/default links and four
exact constructor/archive mismatches. Parent independently rehashes 31,725
entries across six recorded manifests with zero mismatches. Production C/H,
public layout, flags and `RuntimeSelectable=0` are unchanged. Admission-only
and compiler-only invocations explicitly cannot qualify a complete suite.
Reference parity, central integration and hardware remain independent proofs.

```text
C3SO:
  %TEMP%/cm33-secure-only-runtime-8be036efd0194792a0e141c4bc353b41
receipt.json SHA-256:
  7F66040D18F4D115C26124015493C643F8089F45F3F3D3AC3747F3912CEFCECC
C5SO:
  %TEMP%/cm55-secure-only-runtime-d3e6ba0905e74145b75f8a586497c147
receipt.json SHA-256:
  BCD43BE5923245906E8608911227C3BD2EB321D2D6217B85EF4C9F0FC564F3D2
```

### C3FT Reference Closure And C33S Cohort Oracle Repair

The maintained parity entry now runs actual pinned CM33F TF-M reference pairs
at O2/Os with hard/softfp ABIs. Each of the four tuples closes 77 complete
decoded streams and 151 bounded numeric scenarios, rejects 46 compiled mutants
(37 independently of fingerprints), and passes 31 classifier controls. Parent
rehashes 8,884 input/artifact entries across eight manifests without mismatch.
This is object-level reference proof with explicit CPU/MMIO doubles, not native
LTO, real FP exceptions, an external TF-M image or profile activation.

The bc520c5 combined failure is traced to the C33S oracle retaining layout 1
after production had moved to layout 2. The oracle now requires that exact
layout-2 dependency and rejects independently compiled stale-key and extra-helper
controls; no undefined-symbol allowlist is widened. Fresh O2/Os focused runs
each pass 123 ARM calls and six compiled mutants. Parent verifies all 450
recorded source/artifact entries against the existing exact input mirror.
Only the root parity ledger has later prose appended; its archived bytes,
not the modified live document, satisfy the original receipt hashes.

Both repairs leave production sources and RuntimeSelectable flags unchanged.
The failed combined receipt remains FAIL; a fresh combined run is required.
Exact tuple hashes and limits are retained in FREERTOS_ASM_PARITY.md.

### FP NTZ Transitive Helper Repair

CM33F, CM55F and M55 MVE-FP NTZ now keep the complete inline CPU/helper and
non-inline boot-validation chain inside canonical sensitive/GRO attributes.
Port-local MRS, system-exception priority byte accesses and WFE retain the
original register semantics; all nine naked transfer bodies are source-exact.

The fresh immutable primary hard-FP audit passes ninety baseline/raw cells at
O0/Og/O2/Os/O3 with 450 compiled controls, normal and both native-LTO text
layouts. Parent independently rehashes 74 consumed inputs and 11,187 artifacts
without mismatch. The preserved pre-repair receipt remains FAIL; an initial
repair compile attempt with a wrong CMSIS member spelling also remains FAIL.
Neither is relabeled after the corrected fresh run.

The separate hard/softfp, ordinary/reserved-r9 constructor suite passes 126
ELFs, 504 calls and 1,008 bounded GPR restore slices; 93 inputs and every
recorded ELF hash match. Five maintained runtime/layout/archive/vector/cohort
gates and twenty-four unchanged ordered assertions against actual pinned
FreeRTOS O2/Os objects also pass. Exact roots/hashes are in the three leaf
ledgers. These focused repairs do not close global A32, final-LTO reference
parity, actual FP/MVE exception execution or hardware validation.

### Imported Parity Helper Caller-State Regression

The immutable b181ee7 matrix replay passes complete O2/Os pinned parity,
classic/Thumb-1/consumer and A17-A19 subgates, then fails in the owner audit:
imported parity helpers read the caller-only ClassicOnly variable under strict
mode. All 932 source files have zero drift. This remains a failed combined
receipt at C:/fq-8037c672fb/matrix-result.json, not a global PASS.

The compile, disassembly and mechanism helpers now treat focused recording as
optional caller telemetry while keeping every compile and ordered assertion
mandatory. The maintained strict-mode import regression covers absent, false
and true caller state using three real small ARM objects; missing-instruction
controls still reject, and restoring the old caller dependency reproduces the
specific undefined-variable error. The central matrix invokes this guard before
full parity. This is test-infrastructure repair, with no production changes.

An immutable standalone owner/reference replay at 62dca07 subsequently passes
with zero drift across 933 files; its receipt is under
%TEMP%/fiber-owner-import-replay-b9d137f8e1794e9ea29a015d12bd4178.
That scoped result is not a combined-matrix PASS.

### CM0/CM0 MPU And CM4 Raw Helper Closure

The classic ports now own sensitive/GRO inline CPU primitives and protect the
complete non-inline validation chain. CM0 preserves Thumb-1 low-register
constraints and priority word read-modify-write; CM4 preserves byte priority
accesses and FP policy. Terminal literal pools are placed after nonreturning
panic loops; executable naked transfer instructions and context ABI stay intact.

The immutable CM0/CM0 MPU qualification passes 120 compiler cells and 628
compiled controls across five optimizations, both VTOR policies and normal/
native-LTO layouts. Additional inline-only attribute-removal controls reject
instrumentation leakage, and constructor r9 coverage passes 42 linked ELFs.
Parent rehashes 543 consumed-input entries and 19,395 artifact entries across
the four recorded receipts without mismatch. These are scoped qualifications,
not a fresh global A32 PASS or hardware claim.

CM4 independently passes 160 compiler cells, 800 controls, 24 compiled naked
comparisons, four pinned-reference builds and 63 constructor/control ELFs.
Parent rehashes 128 consumed inputs and 21,550 artifacts without mismatch;
the ten frozen owned source files also match. A fresh current-source replay
passes twelve cells/sixty controls. Eight maintained classic boundary, geometry,
preflight, ordering and CM0 MPU layout/runtime gates pass after updating only
the exact port-local reader spellings in their source assertions.

Exact roots and receipt hashes remain in the selected-port leaf ledgers.
The shared closure runner keeps inline-only removal controls distinct from
removing both protection bundles. External memory routines still require their
own transitive general-registers-only integration proof.

### Scalar NTZ Raw Helper Closure

CM23, CM33 and CM55 scalar NTZ apply the same canonical sensitive/GRO
protection throughout local CPU primitives and boot-validation helpers.
All nine naked transfer bodies, frame construction and type headers stay
unchanged. The immutable five-optimization qualification passes ninety
baseline/raw cells and 450 controls, including native-LTO text layouts.
Parent independently rehashes 73 consumed inputs and the original 10,914-entry
closure artifact manifest without mismatch. The separate constructor proof
passes 48 configurations and fifteen controls (252 calls/504 bounded restore
slices); its 91 input hashes and 63 recorded ELF hashes match. No complete
R9 output-artifact manifest is inferred beyond those recorded hashes.

Eighteen unchanged ordered O2/Os assertions against pinned FreeRTOS pass;
parent verifies all 219 entries of that receipt's three manifests. Fresh
maintained CM23/CM33/CM55 runtime/archive/vector/cohort gates also pass.
The first integration attempt exposes LTO dropping fixture libc definitions
before late-generated calls: the CM33/CM55 fixtures now retain real sensitive
GPR-only memcpy/memset definitions, matching the existing CM7 fixture pattern.
Exact construction dependency assertions admit only the newly emitted memset
alongside memcpy, not arbitrary unresolved helpers. This remains scoped
compiler/reference/integration evidence, not a global or hardware PASS.

### Staged C3FT Portable And Default Admission

The CM33F TF-M fixture now links unchanged C/C++ public consumers without
CMSIS/private/optional headers, observes the exact default policy tuple and
rejects constructor-only incompatible-common archives. It retains real common
runtime execution rather than replacing public operations with test doubles.
The fresh complete suite passes 64 target ELFs, sixteen positive constructor
archive tuples, 312 negatives, 212 host cases, 336 modeled CPU runs, 72 compiled
mutants and four strict classifier controls. Parent independently verifies
the seven owned source hashes, the source archive hash and 21,638 entries in
the original three recorded input/artifact manifests with zero mismatches.

```text
Root:
  %TEMP%/fiber-c3ft-readiness-final/cm33f-tfm-85343b9cdce0432e80957fbc163e7f9d
receipt.json SHA-256:
  FF3C8C8808C0F6ECE61E541CC7793925E8B19B7471E802B596B4B70C484455DC
actual-execution/execution.receipt.json SHA-256:
  5638D385A1A8D5187475E203045BEDC2AB424E76563E81A322A41ED18CCBDB18
source archive SHA-256:
  A8A052DB36E306242BFA62220C8888DC26D4FC5F71A07F8691177420FF012457
```

Production sources and RuntimeSelectable=0 remain unchanged. The Secure
bootstrap and typed Non-secure provider are fixtures, not a real Secure TF-M
image, hardware validation or activation approval. Earlier failed receipts
remain failed; reference parity and fresh combined qualification stay separate.

### Split FP NTZ Runtime-Version Guard

Independent retention review finds two separate runtime/PendSV components,
CM55F NTZ and M55 MVE-FP NTZ, with exact cohort reads but no own runtime-version
reference. Their existing first-selection bridges now retain ABI v1 as well.
The read stays one-shot; no naked transfer body, frame, public ABI or hot path
changes. Matching, stale-v2-component and retain-removal causal archives are
checked for both profiles with section GC, normal and native LTO. The named
first-selection function is explicitly rooted for this bounded link proof;
it is not substituted for real-common execution evidence.

Fresh raw qualification passes sixty cells and 300 controls across all five
optimizations and native-LTO text layouts. Parent verifies 66 consumed inputs
and 7,587 artifacts without mismatch. Both maintained runtime/archive/vector
gates and twenty-four unchanged pinned O2/Os ordered assertions pass. The first
new diagnostic classifier attempt rejects its own line-wrapped linker message;
after accepting whitespace only at that delimiter, the fresh complete focused
run passes. Exact roots and hashes are in the two selected-port leaf ledgers.

### ac087c6 Combined-Matrix Replay

The new immutable 941-file snapshot passes both full pinned O2/Os parity runs,
classic/Thumb-1/consumer/owner gates and subsequent constructor/start-policy
checks. It stops in the source-extracted scalar NTZ host model: production
functions now use port-local CPU readers while the fixture still supplies only
CMSIS-named doubles. Its source drift is zero, exit status is FAIL, and later
gates are NOT_RUN. Preserve C:/fq-eb32f77e84/matrix-result.json and artifacts
at C:/fqm-eb32f77e84; a fixture repair requires new scoped and combined runs.

### ABS32 Interior Callback Reachability

The readiness diagnostic exposes six false negatives in the raw audit's common
sensitive-to-cold graph: an ABS32 section relocation points to a callback field
inside a large initialized object, not its symbol start. Production use of that
specific path is not demonstrated. The ELF resolver now includes containing
data-object extents while preserving exact Thumb-normalized function entries.

The maintained regression passes 24 compiled native objects, 48 exact protected/
ordinary direct/indirect roots and six containment-removal causal controls at
O2/Os, normal and both native-LTO text layouts. Parent verifies all 199 recorded
manifest entries. The central matrix runs it before reference parity. A fresh
immutable C5TF/CM7 replay with the repaired classifier passes 24 cells and 120
controls; parent rehashes 72 consumed inputs and 3,186 artifacts without mismatch.
No production file changes in this repair, and previous receipts do not acquire
the new invariant retroactively. Global A32, other relocation forms and dynamic
indirect-call provenance remain separate limits. Exact roots/hashes and the
preserved diagnostic FAIL are in the fixture README.

### CM33 TF-M Transitive Helper Closure

The scalar C3TF dictionary, CPU primitives, boot helpers, initializer and mutex
adapter now keep the canonical sensitive/GRO closure. All existing naked
transfer bodies, context geometry, C3TF identity and selectable status remain
unchanged. The immutable qualification passes 120 baseline/raw cells and 600
controls across five optimizations, ordinary/native LTO and text layouts.
Parent rehashes all 406 consumed inputs, 16,985 artifacts and fourteen owned
files without drift. The leaf ledger is post-qualification evidence, not a
claimed consumed test input. Forty-five compiled old/new naked bodies match;
six actual pinned O2/Os CPU/wrapper reference pairs pass. Constructor evidence
is explicitly a scoped 21-ELF subset, not a full inventory receipt.

The maintained runtime gate initially rejects a new memset dependency. Native
disassembly locates it in the 72-byte zero-initialized boot record construction,
not in transfer assembly. Exact CPU/boot and whole-group import sets now admit
that memory routine only; role-leak and common-definition negatives remain.
The synthetic memory providers retain their definitions through late LTO
lowering and carry sensitive/GRO attributes. The fresh focused runtime gate
passes normal/LTO archive, vector, cohort and negative links at
%TEMP%/fiber-classic-current-integration-170dc0331c9b49989b8e177b59c8d0bb.

The raw receipt uses the captured classifier predating the ABS32 interior-data
repair; it does not acquire that newer invariant retroactively. These results
do not close global raw qualification, real Secure TF-M/PSA execution, external
callback/memory-helper closure or hardware validation. Exact receipt hashes
and the preserved pre-repair FAIL remain in the selected-port leaf ledger.

### Scalar Host Reader Repair

The ac087c6 combined-matrix failure is reproduced by the source-extracted host
fixture: selected functions use port-local register readers while the model
only exposes CMSIS spellings. Both current reader dialects now map to the
original mutable register state, preserving host-width PSP values. No runtime
source or expected register semantics change. Twelve compiled zero-reader
mutants must fail with the exact reader diagnostic; the existing assertions
remain and Handler-entry CONTROL source checks gain stale-Thread controls.

The immutable maintained replay passes fourteen host runs / 29,411 checks,
twelve reader mutants, eight INNER-shareability mutants, 52 ARM objects and
eight archive cases. Parent rehashes 148 captured inputs, 439 recorded artifacts
and both owned fixture files without mismatch. Evidence:

```text
%TEMP%/fiber-v8-scalar-reader-repair-b5e4981da5bf49c6a36a4204ab9214e9/results.json
SHA-256: 2B8AAB0C94F6E6AEE791636B0C8D311464AFC72BA6FA659ABF54D8DA72EDB831
```

This is source-derived C-state, code-generation and archive evidence, not
physical exception execution. The earlier aggregate remains FAIL and its
later gates remain NOT_RUN until a fresh immutable aggregate reaches them.

### Paired CM33 Helper And Cohort Closure

The paired scalar CM33 Non-secure runtime and Secure companion now protect
their complete local CPU/helper closure. NSC entries use the direct CMSE
caller builtin rather than an instrumentable helper; admission ordering is
unchanged. Secure-private exact-key retention uses MOVW/MOVT instead of a
distance-limited literal pool. Context generation, policies and all six naked
transfer bodies remain unchanged. The separate raw gate passes eighty cells,
380 controls and 41 bounded checks under its captured classifier.

Closed pinned O2/Os parity independently passes 68 complete bodies, 69 numeric
scenarios, 25 compiled mutants, 23 independent rejections and 38 controls per
optimization. Only the Boot fingerprints affected by outlining protected
helpers change. Dependency sets and other complete bodies stay fixed. Cohort
mechanism checks retain exact key/call shapes for both address forms and reject
wrong keys, extra calls and broken high halves. Complete cohort, ISA and QEMU
origin/guard proofs remain distinct from that closed analysis.

The frozen handoff is C:/fc33-da1c9f48b9/handoff-checkpoint/qualification.json,
SHA-256 724725863BD4423AB843568FE5A7EBFED20A0FA142638A55F4C46BE8F94A2DAD.
Parent checks all twenty frozen files, eight receipt hashes, 3,412 captured
input entries and 10,690 additional recorded manifest entries without mismatch.
The previously checked raw artifact capture remains separate. The fresh
maintained layout/gateway replay passes at
%TEMP%/fiber-classic-current-integration-d6350f286d6c4d47980663ace6ce487a
after updating only exact local-reader spellings in existing ordering guards.
No full-matrix PASS, new classifier invariant, profile promotion or hardware
execution is inferred from these focused receipts.

### Four V8 MPU CPU-Helper Closures

CM33 MPU, CM55 MPU, CM55F MPU and CM55 MVE-FP MPU replace the remaining
instrumentable CMSIS register/wait/priority helpers with canonical local
inline-sensitive/GRO primitives. No ABI, geometry, policy or activation changes
are made; all 24 naked bodies remain unchanged. The complete immutable grid
passes 360 cells / 1,872 controls at five optimizations, 8/16 regions, applicable
hard/softfp ABIs and ordinary/native-LTO layouts. Parent rehashes 636 consumed
inputs, 46,843 original artifact entries and all seventeen frozen files without
mismatch. Leaf ledgers retain exact receipt paths and historical failures.

The independent current-classifier replay covers 48 default-ABI cells and
240 controls, not the complete 360-cell configuration grid. Parent checks its
82 inputs and 6,025 artifacts. Unchanged pinned O2/Os ordered mechanisms pass
288 comparisons, with all 489 recorded manifest entries matching. These are
not final-LTO closed-body equivalence or hardware proofs.

The maintained FP/MVE host-prefix model gains exactly eight aliases to its
existing register/priority state. A fresh replay passes 24 host runs / 180,156
checks, 96 negatives, 24 target objects and sixteen ARM classifiers:
%TEMP%/fiber-m55-fp-mpu-state-8ce28dcd43cb4a33a85584161b317c50/m55-fp-mpu-state.
This is saved-representation C-state/codegen evidence, not proof of actual FPCA
teardown, exception execution or physical MPU isolation.

The scalar host source guard accepts exactly the old CMSIS or new canonical
CONTROL reader, still requiring Handler CONTROL == 1. Both spellings have
wrong-Thread-value causal controls. Separate immutable committed/local cohorts
pass the maintained suite; parent rehashes 269 inputs and 844 artifacts. This
removes a fixture dependency on uncommitted source spellings, not a CPU-policy
exception. Its receipt SHA-256 is
106DEF500C68396A3A9DDE7847E8AF22F0DB1A9664801E59A7DF0315CCDDE429.
Fresh maintained CM33 layout/protected/runtime and CM55 scalar/FP/MVE layout/
runtime/archive gates also pass, respectively at
%TEMP%/fiber-classic-current-integration-9772896124ce4bc69a95e94bf1dfc262
and %TEMP%/fiber-classic-current-integration-0534e3b9caf242a48d83591e5796d465.

### Current Classifier CM0 And C3TF Replay

A fresh captured run with the ABS32 containment repair passes 36 cells and
194 controls for CM0 VTOR absent/present and scalar CM33 TF-M at O2/Os,
normal/native LTO. Parent rehashes 169 inputs and 5,194 artifacts without
mismatch. Receipt:
%TEMP%/fiber-sensitive-port-closure-0f2851a2113045f0a287f1a6badc1b50/results.json,
SHA-256 4F9A97D1433714B4F32FBDD38115E113CFE37DE817AA7D44062601878B042B99.
This does not upgrade other tuples, the aggregate or external callback/memory
implementations to a new qualification claim.

### Staged C55S Compiler-Group Admission

The raw gate still treated C55S as the earlier incomplete component: it omitted
the standard build expectation TU and exempted the port from eight-operation
presence checking. Both obsolete exemptions are removed, with no production
or activation changes. Twelve positive O2/Os ordinary/native-LTO cells now
retain the four-byte exact-cohort expectation and all eight actual definitions.
Twelve actual runtime-TU schedule-renaming mutants reproduce false PASS under
the exact two-exemption counterfactual runner and fail under the repaired gate
with only the intended missing-operation diagnostic. Sixty positive controls
remain active; no helper/import allowance is widened.

Parent rehashes 69 consumed inputs, 4,282 artifacts and three owned files with
zero mismatch. The complete focused receipt is
%TEMP%/fiber-c55s-raw-admission-8b47614f18be49618c67bd1acbe4e24e/results.json,
SHA-256 1FDA2A399E37C82D1707802BFEA3FED9C976B1B4D644A5C8A073BDE78EC5FDA7.
RuntimeSelectable remains zero; source-group admission is not Secure/exception
execution, hardware qualification or a new global raw PASS. Earlier receipts
retain their captured-runner boundaries.

### 129fc5d Combined-Matrix Replay

The immutable 956-file snapshot passes initial gates and O2 closed analysis for
A30, C3SO, C5SO, both C3FT FP ABIs and the auxiliary C3FP running cohort. It then
stops at the C5TF wrapper-policy source relation: that fixture still requires
CMSIS reader names on the CM33 side after CM33 gained canonical local readers.
This is a maintained cross-profile test dependency, not evidence that changing
register semantics is permissible. Preserve C:/fq-31f2e2afed/matrix-result.json
and C:/fqm-31f2e2afed: FAIL, source drift zero, later gates NOT_RUN. A repaired
comparison needs exact spelling/count controls and a new complete replay.

### C5TF Cross-Profile Reader Compatibility

The fixture now accepts exactly a complete historical CMSIS or canonical C3TF
reader dialect, while C5TF remains canonical-only. Exact per-register counts
and normalized whole-source equality remain required. Forty-three new source
controls reject missing counts, same-count register swaps, changed numeric
policy, mixed readers/files and noncanonical C5TF calls. These source-only
controls supplement, not replace, compiled closed-body checking.

Fresh complete pinned O2 and Os checks each pass 55 bodies, 105 scenarios,
43 compiled mutants, eight independent R9 rejections and 92 controls. No
production body, baseline, instruction oracle or import set changes. Parent
rehashes 1,873 captured inputs, 3,226 artifacts and both owned files without
mismatch. Receipt:
%TEMP%/fiber-c5tf-policy-readers-77ffaf26669c4d42b3c1bf00689585c3/results.json,
SHA-256 3ABBAA9D3268ED75CD2AD55CB7230D1DD9E5EA4A028C7D91C90469C4CA870EE7.
The preceding aggregate remains FAIL; this focused proof does not upgrade later
NOT_RUN gates, LTO/exception execution or hardware validation.

### E69a839 Exported-Source Aggregate

The fresh immutable 958-file snapshot of e69a839 passes pinned O2/Os assembly
parity, 84 classic ARM ELFs / 842 focused checks, 80 Thumb-1 vector ELFs,
156 public C/C++ consumer compilations, 256 cohort/GC links, constructor and
startup hardening, and 32 inline-helper configurations / 256 annotation-removal
controls. The scalar host cases then pass, including the twelve exact reader
controls and independent MPU SH counterexamples.

The run stops in the CM33 archive fixture: its pre-fix-handler negative case
requires `git show` from the Fiber source tree, which is an exported immutable
archive without `.git`. Matching, stale-BASEPRI and stale-reverse archive links
had already passed. This is a source-export test dependency, not a successful
aggregate or evidence of a runtime transfer defect. Preserve
C:/fq-bf2431ee2b/matrix-result.json and C:/fqm-bf2431ee2b: FAIL, source drift zero,
later aggregate gates NOT_RUN. Do not replace the historical handler control
with a skipped test or a weakened identity check; a self-contained pinned input
and fresh replay must establish the same causal rejection.

### Self-Contained Historical Handler Control

The scalar-v8 suite now consumes a plain historical C fixture with a fixed
length/SHA-256 instead of requiring Fiber Git history. Parent independently
compares its 16,959 bytes with the former Git-output join semantics at
5c34785088e3496540a8dcbec1351fac241e11ca; the hash is
21F1285D0F39511560BDD4E1F8CB0B961DFF0D0AF4CE644A2405471B045FB212.
Missing/corrupt inputs fail before compilation. The runner has no Git fallback.

Baseline and exported-source suites each pass fourteen host runs / 29,411
checks, 52 ARM assembly objects, twelve reader mutants, eight INNER mutants
and eight archive cases. The export has no `.git`, Git environment or Git on
PATH. Historical input bytes match in both modes, and the ordinary historical
object also matches. This does not qualify execution of the old handler.

Parent rehashes 1,955 inputs, 2,541 final artifacts and all four owned files
with zero mismatch and a stable artifact manifest. Receipt:
%TEMP%/fiber-v8-scalar-export-4a7f5a2a799648de9ff593c9b4537a37/results.json,
SHA-256 10A9C5D7A0F71A952A1A7914BA7A875058F62F425808111E8C93BB9051F22646.
The earlier aggregate remains FAIL; its later NOT_RUN gates require a fresh
combined replay. Production code, handler semantics and import sets are unchanged.

### Complete Admitted Concrete Raw Inventory

A new immutable current-classifier replay passes all 348 planned cells and
1,769 controls with zero errors, failed/unqualified cells or input drift.
It includes all 27 admitted concrete registry groups: CM0 and CM0MPU each
contribute 24 VTOR-absent/present cells, and the other 25 groups twelve each.
O2/Os and baseline/raw each contribute 174 cells; ordinary, sectioned native
LTO and unsectioned native LTO each contribute 116. Runtime activation flags
are unchanged.

This is the registry's primary ABI and eight-region MPU configuration, with
three-slot/1024-byte Secure companion pools. It is not every hard/softfp,
region-count, geometry, hash/map or optimization tuple. Transitional v8-M stays
compile-only by user direction; the incomplete CM33F paired Secure tree remains
outside this registry. External memory/callback implementations, final-reference
equivalence, physical execution and complete port-roadmap closure are not proved.

Receipt:
%TEMP%/fiber-concrete-raw-46686b7-68b1fa2fe229412893ef5e19975aafd7/results.json,
SHA-256 FAA95D2CF7FE7BBEED5A7949C794B9BA89A0E9748CE984DB139B9E23073C5FA6.
The launch records e69a839; the 272 captured repository files also match
46686b7 after Git text normalization. Thirty CMSIS files complete the source
snapshot. The agent verifies all 558 consumed inputs and 43,534 artifacts;
parent independently rehashes the inputs and final artifacts without mismatch.
The final artifact manifest is stable before/after that rehash, SHA-256
BA4D9A44117586A52EDD4396B17775D8F33230DDA6F524CD22ED6130F77FE3AB.
Early parent counts observed the still-writing CSV and are not the final
inventory. The preceding combined-matrix FAIL is not relabeled by this PASS.

### Secure-Only Export Identity

The reachable C3SO/C5SO runtime wrappers also used mandatory local HEAD reads
for receipt attribution only. Both now retain optional exact-root Git metadata
and a sorted, root-independent SHA-256 source-byte manifest. They never invent
a commit identity or attribute an enclosing repository's HEAD to an export.
Existing copied inputs, dependency admission and final drift rejection remain
authoritative; the FreeRTOS Git/pin checks are unchanged.

Read-only no-Git exports pass the actual AdmissionOnly QEMU gates: C3SO has
5,529 checks / 25 executions, C5SO 5,538 / 25, both with zero drift. The helper
proof adds 129 checks, including changed/removed inputs, causal removal of
actual wrapper drift guards, and invalid/foreign Git provenance. Parent rehashes
95 captured source files and 3,218 artifacts without mismatch. Receipt:
%TEMP%/source-export-identity-e8a335a8eae34b7b9e7bfa0f2e55a557/receipt.json,
SHA-256 9A430332E7923D79EC29F7368731890BBE5CB44192E268027DBECC8AEB298782.
These focused receipts retain CompleteSuite=false. No production source,
activation flag, full runtime suite or hardware claim changes here.

### Secure-Only LTO Tool Provenance

Both wrappers now include the actual GCC-resolved LTO wrapper and plugin DLL
in their before/after tool manifests. This closes a provenance omission, not
a demonstrated runtime defect. Existing receipts retain their captured input
boundaries; no hash is added retroactively to a completed qualification.

A fresh no-Git export proof passes 183 controls, including copied-tool drift,
missing tools, causal drift-guard removal and actual receipt admission. C3SO
and C5SO again pass 25 AdmissionOnly executions each, with 139 and 140 inputs
respectively. Parent rehashes 95 captured source files and 3,252 artifacts
without mismatch. Receipt:
%TEMP%/source-export-identity-cbc2308a81e34be79bb11567344291f7/receipt.json,
SHA-256 912218ACC3904C70AB422FDE8FF783E3691CB563C583D0374E65291CCDFDB4BD.
Installed tools are unchanged; full-suite requalification remains separate.

### C55S Public, Default And Archive Admission

A new composed gate compiles the unchanged portable application in C/C++ with
exact public includes/imports, rejects declaration-only optional-header leaks,
and verifies all eight providers, strong vectors and storage/context identities.
Constructor-only current/stale-common/no-retain archive links separate the cold
v1 anchor requirement from runtime or optional Secure roots. Sixteen additional
direct/archive/normal/LTO configurations execute five cases each with actual
unoverridden default policy observed in the ELF.

Independent review found two assurance defects before integration: the initial
negative-link classifier accepted unrelated errors alongside an expected missing
anchor, and the LTO plugin was missing from the tool manifest. The repaired
classifier admits only the exact linker diagnostic grammar/undefined set.
Maintained controls include real compiled missing-only and missing-plus-RAM-
overflow links, plus counterfeit results through the actual link method. Driver
`-###` plugin discovery must match the queried DLL and its before/after hash.

The repaired focused replay passes 44 links, 44 diagnostic controls, four plugin
controls and 80 default executions plus one model probe. Parent rehashes 2,044
before and 2,044 after input entries, 4,669 artifacts and twelve owned files with
zero mismatch. Receipt:
%TEMP%/c55s-admission-assurance/c55sa-09b50fdb55ec468a/results.json,
SHA-256 99C39BCBAC7BF89FE0BE5EBACAC4B4E04A757DA3602D4AED0FA3675E736B981D.
It correctly retains CompleteSuite=false. The preserved earlier 2,571-launch
full run does not retroactively qualify the strengthened checks.

The central matrix now calls the composed wrapper instead of duplicating the
unchanged full runtime suite. It requires a fresh evidence directory, one PASS
receipt, boolean CompleteSuite=true, exact integer 2,490/80 execution counts,
zero drift and unchanged staged activation. Sixty-five maintained policy tests
include malformed/missing/multiple/subset receipts and boolean/string count
coercion counterexamples. A fresh full combined execution is still required;
no production source, activation or hardware claim changes in this slice.

The post-integration policy follow-up also requires a string Verdict. PowerShell
can coerce boolean true to compare equal to a nonempty string; an explicit
boolean-verdict negative now closes that edge. All 66 maintained controls pass,
and independent replay rejects boolean/array/numeric/null verdicts. This pure
receipt-parser refinement does not change generated ARM code. The running
094ff9d immutable aggregate remains attributed only to its captured sources;
real wrapper receipts use the required string PASS, not the counterfeit value.

### 094ff9d Exported-Source Aggregate

The next immutable aggregate also records **FAIL**, not software freeze:
`C:/fq-d494cb9774/matrix-result.json`, source
`094ff9d17ba231eddf56e9a593b914cd9bafdb9c`, 974 files, zero source drift,
1,169.79 seconds. Its result SHA-256 is
`E86BD97A35EE7B6E980AB841E736542DEA5EAC81BD8705F4B090926EA023D133`.
Pinned O2/Os parity, the repaired no-Git historical-handler gate, FP/MVE MPU
state checks, both private Secure cohorts, CM33 ISA checks, CONTROL transitions,
Secure caller guards and 75 dual-origin CM33 executions passed. The existing
CM33F paired-initializer runner then failed before execution: Bash rejected
`set -euo pipefail` because its exported `qemu.sh` contained CRLF. Later aggregate
gates, including the composed C55S full admission, remain NOT_RUN in this receipt.

The working tree and index both stored LF, but `git archive` applied the active
autocrlf conversion to shell files without explicit attributes. A shared
`tools/.gitattributes` now fixes `*.sh` to LF for checkouts and source archives.
No runtime C, instruction stream, context layout or activation flag changes.

The maintained `test_shell_exports.ps1` checks actual source bytes and creates
real Git tree archives of every shell fixture under autocrlf true/input/false.
It disables global attributes, rejects injected CRLF, and proves that removing
the shared policy reproduces an invalid archive. Its fresh receipt passes all
eleven scripts and 35 checks:
`%TEMP%/shell-exports-f99e3ed5b5aa44529ccd58212e7be836/results.json`, SHA-256
`B208ABC28C37D71C78CFDC2649AFEDD3C32E53226B022936C16EF2925BBA5953`.
The central matrix dispatches this guard before parity; its configuration suite
now passes 69 checks. These are export/configuration proofs, not ARM execution,
and do not relabel the failed aggregate or promote a staged profile.

### LF Export Actual Initializer Replay

A separate full replay of the previously failing existing initializer gate now
passes on the immutable 550b9b1 source archive: 628 actual AN505 CPU cases,
864 checks, 24 controls, DevelopmentOnly=false and zero input drift. Parent
rehashes all 2,119 recorded inputs and 8,013 artifacts without mismatch; the
artifact manifest is stable. Receipt:
`C:/fq-init-550b9b1-a/cm33f-secure-initialize-f243f2081fb14608be4eaf992a4df651/receipt.json`,
SHA-256 `FE41ACC2E703517828B9CA9D60EC29AE8EF98D5349E4185FAB365BBAC38876A5`.
Artifact-manifest SHA-256:
`979C154EC770BC2ADFC0B88DF6B0F303023F6557F287ED328B5F0F20861DE248`.
This closes the export launch failure for its captured initializer suite only.
It does not implement allocation, FP save/load, a complete C3FS runtime, or
hardware qualification, and does not replace the separate combined-matrix result.

### Concrete Selection And Bounded Refactor Baseline

The 2026-11-02 scope amendment is recorded in `CONTEXT_REFACTOR_BASELINE.md`.
The immediate targets are F0/G0/G4/H7/H7S; the remaining concrete feature
profiles and qualification backlog are retained. `transitional_v8m` is removed,
v8-M public selection requires a concrete build-selected profile, and retired
opt-ins are rejected even when set to zero. No concrete context layout,
save/restore instruction or handler implementation changes in this checkpoint.

The focused matrix replay covers six concrete v8-M selections, 36 selection
probes, four matching and sixteen stale-cohort links with/without LTO, and 36
classic namespace/mode cells. Evidence is under
`%TEMP%/fiber-matrix-retirement-focus-cc7685e2aae4420c86a8b860440e64f5/`.
The separate consumer/constructor replay passes 150 C/C++ public compiles,
ten invalid manifests, 256 storage links and 32 constructor links plus eight
controls: `%TEMP%/fiber-transitional-retirement-72799cba8beb43b6ba88791eecb2d5df/attempt4/results.json`,
SHA-256 `A1591EDA20612F2623FA48D787ECB99EBBCD1002E3B9EE3BE8501D155ADB3A37`.

Primary raw codegen inventory passes 90 cells and 457 controls across
O0/Og/O2/Os/O3 and ordinary/native-LTO layouts, limited to CM0 soft, CM4 hard
FPv4-SP-D16 and CM7 soft. Receipt:
`%TEMP%/fiber-primary-raw-retirement-fa56bd60185249e5820d8aa18e9123d6/results.json`,
SHA-256 `13D5555CDEDA96FED7426E9050EB56CADAEE90AE9CF370A4962A48340A8A68FB`.
Independent rehash covers 21,139 hash checks across 17,337 distinct files with
zero mismatch. This is raw closure evidence, not global five-optimization
pinned FreeRTOS equivalence or hardware validation.

Actual external H7S Boot Debug/O2 and Release/Os force rebuilds pass with strong
handlers, correct slots 11/14, one private/storage cohort, an eight-byte readonly
expectation and no undefined symbols. Both complete ELFs are byte-identical to
their archived pre-cleanup builds. All 2,126 inputs and 410 artifacts rehash
without mismatch. Receipt:
`%TEMP%/fiber-h7-header-retirement-8027a66e12524ae6b9a1801c4944c14c/`,
SHA-256 `9C98BE8B8C4BC0B23EEF20B428C58F2D2603C4620C701B45F6D1F716151DE65C`.
No board was programmed. The independent combined immutable 550b9b1 matrix
remains in progress and is not represented by these focused PASS receipts.

The maintained concrete-selection test passes 76 C/C++ cases; dispatch policy
passes 72 checks. A facade is the next mechanical step, not completed Context /
Fiber separation and not a new full-catalog freeze claim.

### 550b9b1 Combined Replay Result

The independent immutable combined run subsequently finishes with FAIL:
`C:/fq-91a1d75f7c/matrix-result.json`, source
`550b9b1fd13038b75c57fceee5e626d006b3e9b3`, 976 files, zero source drift,
3,049.84 seconds. Result SHA-256:
`B3D60F3ECB5F24A18CDA69C132F6A2F8F5402111C26C36898DD4C6E6256B7437`.
The shell-export repair and all 628 existing C3FS initializer CPU cases pass.
The C55S pool, SG initialization, lifecycle and 892 attachment executions also
pass. The next narrow C55S first-start fixture fails at link: its selected
runtime references `fiber_port_arm_cm55_secure_context_pendsv_component_v1_anchor`
but the fixture link does not provide that component. No first-start CPU
execution occurs in this receipt. Later combined gates remain NOT_RUN.
The failure is preserved; neither focused PASS receipts nor the bounded
refactor scope amendment convert it into a combined software-freeze claim.

The bounded fixture repair includes the actual `fiber_port_pendsv.c` in every
first-start source group, including compiled mutants. It verifies real anchor
ownership/import/call retention and forbids a fixture replacement. The focused
complete replay passes 568 launches, 6,354 checks and 30 compiled mutation
controls; independent review rehashes all 157 before/after inputs and 12,523
artifacts without mismatch. Receipt:
`%TEMP%/fiber-first-start-cold-anchor-cc16e2eb0fb542feabfaecec5fcb3d33/fiber-m55-secure-first-start-3ea12eff274448d1994e46e35213bd39/results.json`,
SHA-256 `CFAF6DFD33F6EC246C1C86BD477EE6AF36627A55B128558C5484BA817098DE24`.
The final fixture still omits the PendSV handler and does not execute PendSV.
No production source or runtime-profile activation changes; a new combined
run remains required. The earlier combined FAIL receipt is unchanged.

### Additive Context V1 Facade

The first extraction checkpoint adds five `ctxrt_v1_*` operations over the
unchanged engine, sharing the exact selected storage type and all runtime
state. No concrete port, frame, handler or existing implementation is changed.
The compiler-policy/storage physical paths remain explicit migration debt.

The strengthened maintained gate passes 190 host-mock scenarios with 2,410
assertions, 30 C/C++ public compiles, 40 actual-backend synthetic ELF links,
50 five-optimization facade-body codegen cells and 125 existing causal controls.
It additionally passes 46 diagnostic controls, including real links combining
the expected missing identity with RAM overflow and ten killed counterfeit
classifiers. Negative admission requires the exact stale-input identity,
tracked linker, closed diagnostic grammar, exit status and collect2 trailer.

Receipt:
`%TEMP%/fiber-context-facade-989a7525e3fe40d7bf945b2074a218ac/results.json`,
SHA-256 `128F059EBAD926F9F3FDB30C3A3DEC4C14907A8509CA2888226287EE17DCDA94`.
Independent review rehashes 184 input records, 98 captured copies and 10,495
artifacts with no mismatch or unlisted artifact. Earlier receipt 66eaa0 remains
weaker historical evidence, not retroactively qualified by classifier repairs.

Scope includes CM0 soft, both CM0+ VTOR capabilities, CM4 hard and CM7 hard
FPv5-D16. Actual LTO plugins are driver/query matched and hashed. Host execution
uses a labelled mock port; target links do not execute Cortex-M instructions.
The body/attribute proof is not transitive hostile-compiler closure through the
legacy cold init/setter, global five-optimization FreeRTOS equivalence, completed
ownership inversion, Fiber lifecycle or hardware qualification. The independent
0372d72 combined matrix remains in progress against its immutable source archive.

### Common Source-Role Inventory

The ownership extraction first makes proof recipes select explicit source roles
through `tools/runtime_sources.json`, rather than assume three historical file
names. This manifest contains paths only, never ABI symbol allowlists, expected
frame bytes or safety oracles. Optional configuration remains an explicit role.
The initial mapping still selects the old owners and additive Context bridge;
selection infrastructure alone is not runtime ownership inversion.

The shared PowerShell/Python reader gate passes 139 cases and 556 API verdicts:
`%TEMP%/fiber-runtime-source-inventory-a4cbd76dca124826a7601967bfc1ea75/metadata-repair/runtime-sources-472c4be5f70147d1b9e1f66d74cf8597/results.json`,
SHA-256 `04B0406EC5ECEEC0367CD2C356569B9CC694FF8A489F9ADCF8C3BD89135F362D`.
Independent rehash checks 1,123 input/artifact records without mismatch.
The repaired cases reject JSON `__type` metadata hidden as XML attributes,
including nested objects, ordering, escaped names and duplicates. The earlier
112-case reader receipt does not cover that repaired boundary and is retained
as weaker historical evidence.

Matrix dispatch-policy checks now pass 79 assertions, including mandatory
pre-parity dispatch of both source readers and the Context facade gate. This
is proof plumbing only; neither reader tests nor dispatch checks establish
Context execution, full matrix acceptance or hardware validation.

The matrix recipe migration additionally passes 22 focused checks over eleven
source recipes, preserving their source order and byte-identical output for
the four existing common objects. Receipt:
`%TEMP%/fiber-matrix-source-roles-1782737ef6aa47e0825069bc06525819/attempt2/results.json`,
SHA-256 `FA0AAD6F342C1FB28DE95D7DFE874212C5B1A11B71E0E4568DD3729CEBF2160E`.
Its 456 before/after inputs and 432 artifacts independently rehash unchanged.
The production source-role mapping has not changed in this checkpoint.

The standalone recipes are subsequently migrated to the same roles, including
owner-specific mutations and explicit source-to-object maps. They still use
the old-owner mapping at this proof-plumbing checkpoint. Historical embedded
source/provenance goldens are not regenerated.

Focused PowerShell replays pass public-storage consumers, reverse constructor,
scalar/NTZ security and four Secure-only admission/compiler gates under
`C:/fr-source-recipe-frozen-6a3d9ce2/`. The consumer replay includes 150 public
compiles, ten invalid manifests and 256 GC links. A narrow first-start replay
passes eleven launches and 306 checks with zero drift, explicitly
`CompleteSuite=false`:
`C:/fr-source-recipe-19-4d271bf9/fiber-m55-secure-first-start-c0a6ef015da94a819c5af6644799614b/results.json`,
SHA-256 `5DAEC7BF9B7EEC0430F37849BEC3EB409C81818DAB42728DC002506FF698D1C4`.

The migrated Python facade gate again passes its 190 host scenarios, 30 public
compiles, 40 actual-backend ELF links, 125 causal controls and 46 diagnostic
controls. Frozen receipt/source inventory:
`%TEMP%/fiber-python-runtime-recipes-qualified-1a19e6b7b07/migration-freeze.json`.
Other bounded replays continue against that immutable old-owner export; these
focused results do not establish post-inversion ownership or a combined PASS.

### Context Ownership Inversion

The portable implementation moves into `context/`: core orchestration,
singleton state, fallback panic and the separately selected configuration
service. The old five public calls now delegate into the versioned Context
API. Old implementation files and the additive bridge are deleted, not kept
as alternate providers. Legacy headers forward to canonical Context headers
while preserving typedef visibility and the same `struct FiberContext` tag.
The frozen reverse names, sole current-slot section, eight forward operations,
panic override, startup ordering and selected-backend storage remain unchanged.
Physical compiler-policy/backend paths remain recorded migration debt.

The post-switch reverse constructor proof initially fails twelve LTO shape
checks: the ordinary legacy init wrapper is inlined and Reset directly calls
the canonical Context init instead. Receipt
`%TEMP%/fiber-reverse-abi-constructor-02c21341ff9842f9a13cbf4223a76c71/receipt.json`
is retained as FAIL. No source-runtime repair is made for that diagnostic.
The maintained oracle now follows only the finite exact Reset/legacy/Context/
actual-port-constructor call chain and rejects presence-only, interior-target,
stub and cyclic substitutes. Init-only links also forbid canonical start.

The fresh replay passes 32 production links, eight guard-removal controls and
293 checks, zero input drift:
`%TEMP%/fiber-reverse-abi-constructor-fbb2f05273074b559622e012b5b3789d/receipt.json`,
SHA-256 `AF79DCC9074341D14007D43D634873F2F138C6E6F78AE33FB93D71F9696977E1`.
Independent review accepts the finite-call-chain oracle; 672 input/artifact
records independently rehash unchanged. This is syntactic call-graph/link
evidence, not target execution or instruction-level control-flow equivalence.

The actual-owner source inventory again passes all 139 shared cases. Pure
Context, mixed legacy, matrix-boundary, MPU placement and external H7 build
acceptance are separate post-switch receipts, not inherited facade claims.
The three TF-M OS-wrapper adapters still use the legacy current-identity call
at this engine checkpoint; their optional adapter migration remains explicit.

Post-inversion acceptance uses the actual Context providers, not the earlier
additive bridge. The maintained facade gate passes 190 host scenarios / 2,410
assertions, 30 public C/C++ compiles, 40 mixed and 80 pure Context ELF links,
50 attribute cells, 125 mixed controls, 46 diagnostic controls and 40 pure
dependency controls. Pure links omit both the legacy shim and optional
configuration service and reject injected dependencies on either one. Receipt:
`%TEMP%/fiber-context-facade-phaseb-1a19e7aaea5/fiber-context-facade-ad1756b76afd4c079a9d9bd88f24d26c/results.json`,
SHA-256 `671F34B5AD09097FAC5A7876E178597A17346E4F46A6107AC20DE5B812123B6D`.

The matrix's focused ownership/boundary replay passes 30 checks, including
normal, slim-LTO and native-LTO symbol ownership, independent forward/reverse
ABI oracles, canonical MPU placement and ten causal controls:
`C:/fmb-b158c0e7/attempt2/results.json`, SHA-256
`A84BDD9F8883822BB219CB0AC88050AED4AD3C6D5461C2B18E726A5DF2EC6EF7`.
Its 461 inputs and 5,168 artifacts independently rehash without mismatch.

Canonical init/setter attributes protect their own bodies; they do not confer
transitive protection on ordinary cold registration helpers. The raw classifier
therefore excludes them only as automatic closure roots, never as graph nodes
or edges. An actual hot caller reaching either one must still traverse its
callees. Twelve CM7-soft O2/Os ordinary/native-LTO cells and 84 causal controls
pass; 24 controls specifically distinguish body and transitive boundaries.
Separate staged C55S admission preserves twelve expected missing-operation
rejections and the reproduced false acceptance of the old exemption. Handoff:
`%TEMP%/fiber-context-body-boundary-1a19e86c5dd/handoff.json`, SHA-256
`A0E57282B2A5B6B15FBF6F99DC38DA5EE37515526075B493248E2DA385EA5543`.
Earlier failed candidate receipts are retained, not rewritten.

An independent ELF-object comparator checks 60 native backend pairs across
CM0, both CM0+ VTOR capabilities, CM4 hard FP and CM7 hard FP, O2/Os, comparing
pre-inversion backend objects with pure and mixed Context builds. Executable
bytes, allocated data/BSS, relocations, symbols and ARM attributes match.
Eight comparator controls pass. Receipt:
`%TEMP%/fiber-context-backend-identity-a9fecee87ac541a0a50d7879becd5a37/comparison-1/receipt.json`,
SHA-256 `A37667E4E51C98973449C0B4D9D211D92A2BAE4F8DEC8B608CD567BEFC176000`.
Sixty slim-LTO pairs are explicitly unqualified because they contain no native
instructions. This is backend-object identity, not whole-image identity,
five-optimization global FreeRTOS equivalence, CPU execution or board evidence.

A second read-only comparison checks 30 native pairs for the moved common
state, panic and optional configuration providers across the same five classic
configurations and O2/Os. Executable bytes, data/BSS, relocation identities,
symbols and ARM attributes match after excluding the expected source-file name
records; the differing symbol/string tables remain in the report. Receipt:
`%TEMP%/fiber-context-backend-identity-a9fecee87ac541a0a50d7879becd5a37/comparison-2/receipt.json`,
SHA-256 `3A0DC6A10E37F3FFE683F7F2AB66A2C3D6E30A5C908F9532347E7C6B38A3BF68`.
It excludes the intentionally changed core/wrapper bodies and makes no LTO,
final-linked-image or whole-engine identity claim.

The two Secure-only compiler audit recipes now follow actual canonical owners
and prove the exact legacy/Context/state/current-slot chain. Their independent
causal controls reject both a cold registration edge injected into current and
a compiled NULL-return substitute that retains every expected symbol. The
bounded CM33/CM55 replay passes 96 hostile cells, 98 executions and 50,777
checks; 11,475 artifacts, 305 input rows and 1,033 snapshot files rehash without
mismatch. Receipt: `C:/fr-context-compiler-qualified-860e25a4/results.json`,
SHA-256 `D36DC2A5610899261A554184CE3B91A2AA621C0EE89C61313BECA358411B3E23`.
`CompleteSuite=false`: this qualifies those compiler boundaries, not the full
Secure-only architecture suite or runtime-profile activation.

The actual external H7S Boot Debug/O2 and Release/Os builds also pass after the
ownership switch. Compile commands and final maps identify the new Context
core/state/panic/configuration providers and legacy shim, with retired owners
excluded. The unpublished lifecycle consumer is not part of these builds.
Strong SVC/PendSV, slots 11/14, single current/ABI identity, exact private/storage
cohorts and readonly expectations pass ELF audit. Ten external generated make
files are updated; Cube regeneration and project-metadata edits are not claimed.
Receipt: `%TEMP%/fiber-h7-context-switch-qualified-481f3ec8/results.json`,
SHA-256 `409281A155F210567A8897782B4DC9FB483F9CE59B14C444DCFF02D903B01CA5`.
Those external build files/ELFs are not contained in this library commit. No
board was programmed and no new hardware checkpoint is established.

### Aggregate Artifact-Fixture Repair

The immutable compile/link/codegen aggregate for `53b69aa` stops in its first
artifact-path gate: a stale regex expects the PASS banner immediately after
the successful try-body assignment, before the new final input-drift check.
The matrix correctly publishes PASS only after `finally`. Receipt:
`C:/fcq-a94c7ffba9/matrix-result.json`, SHA-256
`1BBC8A6589BE8C9119FE3609E80BA279B49FC9FCE3F7AFD69E42F3E26F20DAFF`.
This is retained as aggregate FAIL with zero source drift; later gates are
NOT_RUN in that receipt.

The fixture now uses AST structure to require the sole success assignment at
the end of the real try body, an initial false state and the sole final banner
after the actual cleanup/drift finally block. Seven parse-valid causal controls
reject missing/early success state and misplaced, duplicated, conditional or
comment-only banners. The isolated cleanup fixture also supplies real captured
input hashes and executes in the same scope as the matrix. All eight existing
retention combinations remain tested; four input-drift combinations additionally
require terminal failure, false pass state, retained evidence and changed-hash
reporting. No runtime or production cleanup behavior changes.

The focused artifact gate passes 65 checks:
`%TEMP%/matrix-artifact-paths-45033727ef59499ca7b2b2633900d90b/results.json`,
SHA-256 `AC983971B0EC6BB92DEB0D7A6643EC8ACE5352E52B5D7C46272C31B3B442AB5A`.
This filesystem/AST result is not a substitute for a fresh aggregate replay.
Independent review then identifies a proof-only gap: a swallowing catch on
the main try could still reach the final banner. The current matrix has no
catch, but the strengthened predicate now forbids one and adds an eighth,
parse-valid causal mutant. Fresh PASS, 68 checks:
`%TEMP%/matrix-artifact-paths-4cffad711af644c09346fae89f955572/results.json`,
SHA-256 `8460ABCBF82FE79EB23A25B304E3FA89FE9E92970C9CA6290040EC7097FED2F4`.
The earlier 65-check receipt does not cover that added guard.

### Fiber V1 Consumer Publication

`fiber/lifecycle` now publishes the separate static-storage consumer. `FiberV1`
contains the selected Context as its first member plus private lifecycle state;
its runtime contains only selector/user policy. The five public operations and
local adapter introduce no CPU conditional, trampoline, owned current pointer,
dispatcher latch or new port operation. INITIALIZED and STARTED mean constructed
and selected, not completed or successfully entered on CPU. Caller-owned storage
must be valid/aligned, static/nonmoving, privileged where required and disjoint
from execution stacks. This is not an arbitrary-pointer validation service.

Initialization retains and calls the real Context configuration-open service
before construction or state publication. Registration commits policy fields
only after Context accepts it. Current/yield are identity-only Thread functions;
the optional privileged Context accessor does not bypass feature/configuration
guards. The exact v1 layout/semantics must not silently change under the same
version. Rich task states, wait queues, tick/ISR preemption and C++ policies are
not part of this publication.

Fresh mixed-legacy and Context/Fiber-only qualification passes 310 host
scenarios / 1,270 assertions, 44 behavioral mutants, 34 other controls, 40
actual-classic-backend ELFs, 20 public C/C++ compiles and 50 attribute cells.
Pure ELFs omit all five old public symbols and reject compiled legacy-shim
counterexamples. Packaging, exact consumer exports, no owned writable globals,
full-container overlap and cold/hot attribute boundaries remain independent
oracles. Receipt:
`C:/flife-publication/qualified/ef72b35302884ee98bb7e8de70058838/results.json`,
SHA-256 `2267287A39E73E29D22F2E25864635D7CBA552120E27377B1F3D8DC68623FB61`.
The fourteen maintained consumer/test files match the frozen accepted copies.

Publication changes from the accepted draft are comments/documentation only.
Ten C/C++ preprocessing pairs remain identical and ten compiles of the actual
README round-robin example pass:
`C:/flife-publication/equivalence-final-1e9edc8e43ab41ee83da466e7317439a/results.json`,
SHA-256 `7C6DF8A89CCABA333A069A517FE9D11124F23FA61429479095D173F22EAF52A2`.
Matrix dispatch-policy checks pass 83 assertions, including mandatory early
execution of the lifecycle gate. This gate executes a labelled host mock of
the eight CPU operations; target links prove layout/link/placement, not target
constructor execution, MPU enforcement, SVC/PendSV transfer or board operation.
The additional actual-ARM constructor cohort is a separate maintained proof.

### Fiber Constructor R9 Cohort

The maintained constructor runner now defaults to separately identified legacy
and genuine Fiber cohorts. The latter compiles actual Fiber init, Context
engine/state/configuration and existing selected backends without the legacy
shim. Complete EMPTY Fiber storage and surrounding canaries are real; traces
require Fiber -> configuration guard -> Context -> port. Ordinary AAPCS permits
temporary R9 borrowing; reserved-R9 builds require the exact static-base seed
with reservation on every C unit and the final LTO link.

The focused CM0/CM3/CM4/CM7 replay covers both APIs, O2/Os, ordinary/native LTO,
hostile compiler modes and both R9 contracts: 256 baseline ELFs, 96 compiled
controls, 1,408 constructor calls, 736 configuration probes and 2,816 bounded
GPR-restore slices. A compiled consumer borrowing control remains valid ordinary
AAPCS. A separate compiled guard-removal control actually initializes after
configuration closure and is rejected as CONFIGURATION-BYPASSED, not by a
fingerprint or unrelated link failure. Legacy oracles and controls are retained.

Receipt: `C:/r9f/fiber-constructor-r9-8e8bea10c6ac4caaaadde6b640cfdd71/results.json`,
SHA-256 `37B0F1B1D698D821DAFA5869AD935A0E89EAFB5E3A6B9274577AAE36881A1461`.
Independent source/oracle review finds no confirmed issue and matches the five
changed test files to immutable copies. The worker rehashes 13,995 artifacts,
122 copies and 3,704 source/object mappings without mismatch. The only live
input delta is the separately qualified publication README, not code drift.
`CompleteSuite=false`: this is constructor and bounded linked restore-slice
execution, not full exception transfer, FP/TrustZone/TF-M execution, all-profile
new-consumer admission or board validation. No production code changes.

### Post-Publication Aggregate Boundary

The fresh immutable `0e054a8` compile/link/codegen aggregate replays artifact,
selection, source-reader, canonical Context, pure/mixed Fiber and helper gates
successfully, then stops in the first O2 scalar Secure parity group. Its runner
omits `context/context_api_types.h` from the declared hashed input inventory,
and the existing dependency-closure check correctly rejects that actual compiler
dependency. Receipt: `C:/fcq-be47d02769/matrix-result.json`, SHA-256
`40A0FF40B8BF0E6F0948D31A260CDE370AB3C9F8031D1AE7485C6A8B76020C68`.
It remains aggregate FAIL: 1,014 immutable source files, zero drift, 415.56
seconds. Later parity and matrix gates are NOT_RUN in this receipt; conditional
QEMU execution was intentionally not selected. The missing provenance input is
not evidence of a frame/assembly defect or permission to relax dependency closure.

### Canonical Header Provenance And Public Build Recipe

The scalar Secure parity snapshot now explicitly includes canonical Context
headers. Its strict compiler-dependency closure remains unchanged. An immutable
`f87db9e` source archive plus the two reviewed runner/documentation overlays
passes A30, C3SO and C5SO at O2/Os: six profile/optimization groups, six deliberate
missing-header controls, twelve positive/restoration checks, 9,038 input and
2,292 artifact records without drift. Receipt:
`C:/scp-cc72c72e/results.json`, SHA-256
`F63F8B23758DED62CB9A83474F6C8DF9D17AD9A962404BC568C8E1BB2BB3A9D7`.

The PowerShell C3FP and Secure companion initialization inventories likewise
include canonical Context headers, without changing assembly, golden bodies or
behavioral oracles. A separate immutable `f87db9e` archive with that exact driver
overlay passes C3FP O2/Os, both FP ABIs and 8/16 MPU regions, with 132 compiled
mutants and eight harness controls. Its 1,015 source files have zero drift.
Receipt: `C:/fcfp-9b9238d28a/results.json`, SHA-256
`95852111D8E60FEA0B489948361663B0D126454460ABCC6226A59A8CEE27C738`.

Independent integration review also finds a real documentation defect: the main
Project Setup still lists deleted providers and omits the canonical engine.
The active recipe now lists the three Context providers plus the legacy shim,
or explicitly replaces that shim with the genuine Fiber consumer and Context
configuration provider. Retired configuration paths are removed from that
active recipe. A maintained section-scoped validator rejects missing providers
and retired paths while allowing historical records outside the setup section.
The dispatch/recipe regression passes 89 checks. Receipt:
`%TEMP%/matrix-execution-policy-5181c5c7b52946b99294f3ba6b650cc4/results.json`,
SHA-256 `D5EC682DDAFA941E92280EA44A7610A89BFA74A1F0357373A8777FE2C7E34847`.
The canonical ownership gate separately passes against the current source.
These focused results do not turn the preceding aggregate FAIL into PASS.

### TF-M Adapters Consume Context Directly

The CM33, CM33F and CM55 optional TF-M OS wrappers now include canonical
Context declarations and call `ctxrt_v1_current()` rather than `fiber_current()`.
This is the entire production delta: no assembly, frame, mask, priority,
cohort, runtime ABI or Secure service policy changes. CPU/boot role oracles
still reject either public getter; only the separate optional adapter may use
the Context public identity operation. The role boundary is not broadened.

The qualified source cohort is immutable `53b69aa` plus exactly 28 owned
overlays, not a claim for a later aggregate. Sixty-four pure-Context target
ELFs (16 CM33, 32 CM33F, 16 CM55) omit the legacy shim and optional configuration
provider. Thirty-two compiled legacy-wrapper controls fail solely on the
missing `fiber_current` dependency. CM55/CM33F gates also retain mixed-legacy
coverage, 200/212 host runs and exact role/import, vector, archive and cohort
checks. Scalar CM33 raw compiler coverage includes 120 cells / 840 controls
over five optimizations and native-LTO variants, plus the separately bounded
constructor cohort. Historical raw failures remain recorded, not requalified.

Closed parity passes C5TF O2/Os and C3FT O2/Os with hard/softfp cohorts. A separate
native pre/post comparison checks six tuples, 56 objects and 566 functions:
function metadata and allocatable bytes match, relocations differ only by the
reviewed getter-symbol substitution. The only normalized body change is the
call target in the thirteen-instruction wrapper identity helper. Golden edits
are limited to that one body per optimization. Scalar CM33 and final LTO
pre/post instruction identity are not claimed by this native comparison.

Independent source/oracle review accepts this bounded change. All 28 live
files match frozen copies in `C:/fq-tfm-9e9de3ff/HOLD.json`, SHA-256
`EF857620E99D69A77C2D43D4A9133A3DAE6CC737AA9908843FA5DF3BFA2EEBF7`.
The reviewed native delta receipt is `C:/fq-tfm-9e9de3ff/reviewed-delta.json`,
SHA-256 `EE048FC0D44E1A6EB5FCF7C3269FE519294E0832FD9F598E6F1BAAEAAD2EAFD2`.
Primary receipts under that root:

| Receipt | SHA-256 |
| --- | --- |
| `cm55-tfm-65229fc1c4a94de7b8d00a66062cb8fa/receipt.json` | `1E3AB4DFC9501094EA2F86393EFC204CC9AA24CE15C341208899C969E0DC5A84` |
| `cm33f-tfm-d4e242399071402f8372a4c7f9bce4f6/receipt.json` | `0424900196104FC49A3E489F07E5406F5D88324638BA1CDBF1DF593F6A9FAEBF` |
| `raw33-v3b/results.json` | `871151137F83CAB6AFADB5478173BBF18EF2B2DE3C3A2DBFEB90AB3E6E659688` |

The rehashed qualification records contain 5,288 inputs and 32,882 artifacts
without drift. No actual Secure TF-M image, veneer/service execution, board
operation or runtime profile promotion is established by these synthetic
links, host-mock runs and bounded compiler/assembly checks.

### Combined Replay Failures Remain Explicit

The immutable pre-extraction `0372d72a7d7ba98ee2e5ff15908cfbd03d1fec64`
architecture-execution aggregate finishes with FAIL after 8,691.17 seconds,
969 source files and zero drift. Its executed CM33/CM55 Secure-only suites,
staged SecureContext/MPU suites and TF-M FP/R9 suites pass before the later M23
LTO archive fixture fails on unresolved `memcpy`/`memset`. These synthetic
definitions were removed before late structure-operation lowering introduced
their calls. It is a fixture-provider retention defect, not an observed switch
failure. Later matrix gates remain NOT_RUN. Receipt:
`C:/fq-96d5c9e0ed/matrix-result.json`, SHA-256
`3693F8E2F00F5A776FA6088273BFE70FF2EC11A53AEE0567AF9BAFBB63A3AE42`.
None of that earlier-source execution qualifies the later Context inversion.

The immutable post-inversion `1baf85f155f2b20701b476fee5ddb25d66f9a98c`
compile/link/codegen aggregate also remains FAIL: 892.94 seconds, 1,015 source
files and zero drift. Context/Fiber gates, pinned O2/Os parity, classic guards,
consumer cohorts and owner guards pass. The MPU constructor annotation-removal
copy then fails because it omits canonical Context headers, before the mutant
can exercise its intended instrumentation oracle. This compile error is not an
accepted mutant rejection. Conditional QEMU gates were not selected, and later
matrix gates are NOT_RUN. Receipt: `C:/fcq-3c68253a43/matrix-result.json`, SHA-256
`A8FDE2302745BCE1136EB7DF430EECD14C96CCAD07DC5B5E7625962A8FFD75BA`.

### Synthetic LTO Providers And Isolated Attribute Inputs

Eight standalone startup fixtures and the generated exact-cohort startup now
retain their freestanding `memcpy`/`memset` definitions with `used`,
`externally_visible` and `noipa`. This changes test providers only, not runtime
sources or compiler flags applied to production code. The original M23 failure
also reproduces against the post-inversion source before the fixture repair.
The maintained M23 LTO link then passes and retains both strong providers;
removing their annotations reproduces exactly the missing memory-service pair.
Positive and negative links now use separate maps.

Independent review identifies a P2 weakness in the first negative parser:
word-only capture and case-insensitive comparison could accept a suffixed or
wrong-case symbol. The final helper captures complete quoted names, rejects
unparsed undefined-reference messages and compares the exact pair case-
sensitively. Its maintained actual-helper regression passes 99 policy/recipe/
diagnostic checks, including suffix, case, space, foreign, unquoted, empty and
successful-link controls. Receipt:
`%TEMP%/matrix-execution-policy-2c7711d50f5947099ee17b6fccf2dceb/results.json`,
SHA-256 `EB5D0F59BB483996347C998ED18AAF4086C50221679AE3ED0EA6ECD18E7723C3`.
Final source review finds no remaining confirmed issue.

The complete nine-function maintained integration/cohort replay passes against
immutable `1baf85f` plus nine exact test-only overlays, 1,015 files and zero drift.
This includes M23, CM0/3/4/33 MPU, all three M55 MPU variants and exact cohort
mismatch checks. Receipt: `C:/fmem-8c7404ffae/results.json`, SHA-256
`12F3704A330E7DB06A1F1C678D55D8C16128319E7F7DE3ED8BD369EC54B1EDED`.
All nine live overlays match its retained copies. The earlier receipts before
map/parser tightening are narrower, not the final qualification.

The separate MPU attribute runner explicitly hashes/copies canonical Context
headers into its annotation-removal tree. A missing canonical-input control
must produce its exact missing-header diagnostic and is not counted as an
instrumentation mutant. Existing imports, counterflags, frame/assembly oracles
and attribute-removal behavior are unchanged. The full maintained gate passes
24 configurations, 48 hostile mutants and 40 caller compiles against immutable
`1baf85f` plus its two owned overlays. Ninety-nine inputs and 1,996 artifacts
rehash without mismatch. Receipt: `C:/mca-48c2a5ba/results.json`, SHA-256
`0323E907F96D8A3DE611821DB689366B8AA8B41CEF3E860395C42553091DE8AE`.
These are focused repairs/links, not a combined PASS or CPU execution claim.
