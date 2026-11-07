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

### Standalone Canonical Header Inventories

Eight additional maintained PowerShell runners now explicitly enroll top-level
canonical Context headers in their existing hash inventories. The entire delta
is sixteen inventory lines; no runtime code, oracle, counterflag, profile or
admission boundary changes. These gaps did not prevent live compilation, but
the earlier standalone receipts did not account for every consumed header.

Each full affected gate passes against immutable `3ea0f640` plus the eight
reviewed overlays:

| Gate | Focused Replay |
| --- | --- |
| MPU start policy | 54 configurations, 162 compiles |
| M55 FP/MPU state | 180,156 source-derived checks, 96 negatives |
| CM33F MPU manifest | 56 objects, 51 negatives |
| CM33F MPU constructor | 4,176 ARM calls, 1,216 expected panics, 66 controls |
| CM33F MPU first-start codegen | 32 ELF checks, 60 negatives |
| CM33/CM55 Secure-only manifest/reference subsets | 110 / 117 checks |
| CM33F MPU first-start execution | 25 QEMU runs, 120 first-start and 28 compatibility checks |

All eight live files match qualified copies. Seventy-two canonical-header
enrollments, 1,654 input records and 4,370 artifacts rehash without drift.
The handoff, exact overlay identities and replay commands are retained under
`C:/fctx-hdr-6e974d2a`; `HOLD.json` SHA-256:
`6F63FBDEAF8563902955CF077065DBF61EC479D5763F251EAD4569CED7042D3B`.
These separate full-gate receipts do not establish a new combined aggregate,
complete runtime execution for the primary classic targets, global final-LTO
equivalence, hardware validation or staged-profile activation.

### Staged CM55 Gateway Inventory Repair

The immutable `3ea0f640e6f912da320baa38e7ed687f9fd6c692` compile/link/codegen
aggregate remains FAIL after 1,910.15 seconds, 1,016 source files and zero drift.
It passes the repaired M23 LTO links and forward/reverse/cohort guards, then
stops at an obsolete foundation assertion forbidding the already implemented
staged C55S Non-secure runtime source. Later gates are NOT_RUN. Receipt:
`C:/fcq-17405a5964/matrix-result.json`, SHA-256
`7317239EAAC5CC197FD4BA264400E43520BDA3DE16FAD9051201EF5A6EEA0E3F`.

The gateway gate now requires the exact current staged NS/Secure file inventory,
instead of treating the NS runtime as a future artifact. Missing runtime/private
files, new Secure lifecycle artifacts and unexpected nested sources are rejected.
Independent review found and closed a hidden-file/directory enumeration gap;
both now have negative fixtures using actual filesystem Hidden attributes.
The actual-helper policy regression passes 109 checks. The complete maintained
CMSE gateway/private-pool/link cohort, including its existing import/profile/
version negatives, passes against immutable `723878d` plus the two test-only
overlays: 1,016 files and zero drift. Receipt:
`C:/fc55-stage-ec6d170108/results.json`, SHA-256
`5A3231FB8323CC86FFD6976D8902521AD0E9707E752B413A2960EF00B0DF7F0D`.
No production source, assembly, context layout or admission flag changes.
`RuntimeSelectable=0`, the twelve-entry gateway surface, and the separate
complete-runtime admission requirement remain unchanged. This focused PASS is
not a combined aggregate, CPU execution or hardware claim.

### CM4 Historical Raw Gate Uses Explicit Context Inputs

The standalone CM4 raw runner now copies current canonical Context headers,
role-validated providers, the source manifest and both readers into its nested
historical-port tree. It compares the requested relative source-role inventory
after copying and records current contracts separately from the eight Git-pinned
`bc520c5a722ca70a461561cf30a59eb4ad8a4b3d` port files. This is historical port
code with captured current contracts, not a historical whole-repository claim.
No raw-hook, literal-range, transfer or negative-control oracle is relaxed.

The outer immutable inventory also captures the genuine Fiber lifecycle
consumer. Both default constructor cohorts remain mandatory: 96 production
ELFs, 36 compiled negatives, 528 constructor calls, 276 closed-configuration
probes and 1,056 bounded restore slices for CM4. The complete standalone gate
passes 160 compiler cells and 1,120 controls, including O0/Og/O2/Os/O3 and the
maintained native-LTO/raw layouts. It rehashes 156 inputs, 30,298 artifacts and
13 tool images without drift or mismatch.

The exact qualification is immutable `3ea0f640` plus two owned test-only
overlays, both matching their live files. Receipt:
`C:/c4r-0fceb9ba/results.json`, SHA-256
`F0148D89FBCF1F922BFDA31A3A6AEC59EBC8F1FA19B339A2467E5FCCF6706CDA`.
The prior failed attempt remains separately retained at
`C:/c4r-3ba6f5b3/failed-attempt.json`, SHA-256
`189B12366678571101F9CE1583CA4D200AD998A72D329606449A650A9E9FA9EE`.
This is not complete exception/FP execution, all-profile final-linked FreeRTOS
equivalence, board validation, or a combined matrix result.

### H7 Managed Source Admission Follow-Up

The external H7S project had five missing backend exclusions in both managed
configurations. Existing generated make overlays masked admission of seventeen
foreign sources during a future rescan. The local `.cproject` repair adds only
those exclusions. Structured XML comparison confirms exactly ten additions and
no other metadata change. Context providers already belong to its managed
`app_core` source root.

The independently reviewed qualification passes 1,057 checks, 34 pre-repair
guard rejections and 22 post-repair preprocessing probes. Each configuration
retains eleven intended sources and rejects all seventy-nine foreign backend
C files plus 277 tools sources. All 120 retained artifacts rehash correctly.
The exact receipt and before/after metadata hashes are recorded in
`H7_RUNTIME_VALIDATION.md#context-owner-managed-source-admission`.
Actual IDE regeneration, clean builds after regeneration, linking and board
execution are NOT_RUN. This repository records the external integration result;
the external `.cproject` is not part of its commits.

### Main CM33 TF-M Identity Contract Repair

The immutable `b648b4074e6f30d2b2cc37a7a04bc81042e2a6bc` aggregate remains FAIL:
1,854.65 seconds, 1,016 source files and zero drift. It passes the repaired C55S
gateway and subsequent M55 runtime groups, then the main CM33 TF-M gate rejects
the already migrated adapter because its exact allowlist still expects
`fiber_current`. Later gates are NOT_RUN. Receipt:
`C:/fcq-80f8a8564f/matrix-result.json`, SHA-256
`E195BD156CE16B07196674E1B3F25BB461D05DADF51D0394F4472EEC7078C4D3`.

The group and adapter allowlists now substitute only `ctxrt_v1_current`; the
synthetic common fixture provides that canonical operation. Mandatory CPU/boot
permissions are not widened. Compiled normal-mode controls reject both public
getters in CPU code and reject a legacy-getter adapter. The weak-common-definition
control remains. Independent review accepts the bounded diff; it adds no new
LTO-negative claim or production change.

All eight maintained function cohorts from CM33 TF-M through the remaining
classic MPU integration pass against immutable `9dd6a01` plus the exact matrix
overlay, 1,016 files and zero drift. Receipt:
`C:/ftfm-matrix-799c8768a9/results.json`, SHA-256
`F63FD129250E866897F1C5ECB743E25F727D4FF060D34D664117019534268E89`.
The 109-check execution-policy regression also passes. These focused links do
not replace a fresh aggregate or establish CPU/board execution.

### Post-Context Combined Compile Qualification

The complete maintained `tools/compile_matrix.ps1` passes against a fresh Git
archive of `847953da273a30b1594a66bd3facfb8ecf1ac902`, without source overlays:
1,016 source files, zero drift, exit code zero and 1,931.19 seconds. The final
settings positives/negatives and source-inventory `finally` check complete
before the final PASS. All earlier aggregate FAIL receipts above remain FAIL;
none is reused as evidence for this later source.

The snapshot is `C:/fcq-ed1be3f107/experiments/h7s_fiber_test/Boot/app_core/fiber`
and the retained build is `C:/fcqm-ed1be3f107`. Qualification files:

| File under `C:/fcq-ed1be3f107` | SHA-256 |
| --- | --- |
| `matrix-result.json` | `4C2783E71F1D4D8440CC526A7ED4F2D2595B935B552E1352C3B8E8ADA462E065` |
| `matrix.log` | `5DCB60B6FF0D88F77619FA0BD3329FB0E66274CC55B6B578DB066B0EC0E90525` |
| `source-before.json` | `22EBDF995518A54DECC52084C12C12D6C2BC823A3DBC64683AEBA4200E397EE0` |
| `qualification-plan.json` | `57A439B6034A49AD7D6012F4C2D296F363BBC4D731F4E50645BDEB69A846D688` |

The exported source ZIP hashes to
`C93CF9AB812F478971D0F7434B97021EDE0C8D3FA9F09EF926F193DDFE0E2E30`.
The reference remains the clean local FreeRTOS pin
`a50edad08b29052631aa469d4df6e6ec7ff68878`; GNU Arm GCC 14.3.1 is used.

This aggregate covers the actual Context owner and separate Fiber consumer,
the 109 execution-policy controls, pinned O2/Os assembly parity, the applicable
constructor/attribute/compiler gates, forward/reverse ABI and current-slot
isolation, exact storage/profile cohorts, stale-object/archive negatives,
GC/LTO/vector ownership, concrete/staged integration gates, the 42 generic
compile cells and final settings contract. The repaired C55S inventory and
CM33 TF-M identity checks now pass inside the full run, not only as focused
replays. A separate read-only architecture review finds no confirmed new
layering defect for the F0/G0/G4/H7/H7S CPU-profile baseline.

`RequireArchitectureExecution=false` and no QEMU root is supplied. Conditional
QEMU architecture/Secure gates, the C5TF R9 execution probe and C3FT actual
execution are explicitly NOT_RUN. The selected host scenarios and bounded
ARM constructor/FPU-policy calls do execute; they do not establish complete
post-inversion classic SVC/PendSV/exception/FP behavior. No board is programmed.

This is a bounded local compile/link/codegen checkpoint. It does not activate
staged profiles, complete missing feature combinations, establish global
all-optimization/final-linked-LTO FreeRTOS equivalence, certify external H7S
regeneration/builds, provide exact-SHA CI evidence or declare an all-profile
software/hardware freeze. Those remaining gates are retained in
`CONTEXT_REFACTOR_BASELINE.md` and `STM32_PROFILE_BACKLOG.md`.

Independent read-only review rehashes all 1,016 declared source files against
both the inventory and archive bytes without mismatch, confirms the exact
receipt hash, and verifies that the sole final PASS follows the late settings
and `finally` checks. The generated Python cache is not a source overlay.

### Post-Context CM0 Exception Runtime

The maintained `tools/test_classic_context_runtime.ps1` completes all 298 real
QEMU microbit firmware executions. The immutable input is a Git archive of
`2d018453b2b94adeb56021d9617d12a813c8f9a7` plus sixteen explicitly hashed
owned overlays, not a clean-commit or current-worktree qualification. The export
contains 1,026 source files; the runner enrolls 3,370 source, reference, header
and tool inputs. Source, input, repository-inventory and QEMU identity drift are
zero. Exit is zero after 480.03 seconds, with `CompleteSuite=true`.

| Execution class | Cases | Required outcome |
| --- | --- | --- |
| Positive | 32 | Exact semantic CHECK and PASS records, exit 0 |
| Production rejection | 216 | Exact case-specific panic record, exit 64 |
| Compiled causal control | 48 | Exact register/publication oracle reason, exit 66 |
| Deliberate unhandled fault control | 2 | Fault-only record, exit 65; never a substitute for panic |

Both pure Context and the real Fiber v1 consumer run at O2/Os, ordinary and
final-linked LTO, with direct port objects and static port archives. Positive
cases cover both production hash/map 0/0 and validation 1/1. Pure Context omits
Fiber, the legacy shim and optional configuration; Fiber adds its real lifecycle
and configuration providers. The actual backend and portable providers are
compiled, not replaced by a fixture CPU port.

The loaded strong SVC/PendSV vectors transfer to privileged Thread/PSP execution;
dispatcher observations establish actual PendSV IPSR 14, current identity,
PRIMASK protection, first/next, self-selection and bidirectional switching.
Distinct r4-r11 payloads, PSP/MSP, stack cookies/guards and canaries are checked.
A supplemental assembly-owned direct PendSV request prevents intervening C
prologues from masking broken register restoration. Actual compiled controls
remove r9 restore, corrupt r4 restore, or suppress later current publication;
only their intended semantic failures qualify them. The SVC evidence is loaded
vector plus real start/continuation, not a sampled SVC-entry LR/IPSR trace.

Final ELFs retain exact runtime/storage expectations, correct Thumb slots 11/14,
one common current slot and the appropriate configuration dependencies. Every
input object is inspected for exact strong global common-private ownership.
Final LTO may internalize only the named private slot/reverse/configuration
objects; APIs, handlers and cohort providers remain global. Fifteen binding
controls and sixteen strict terminal-classifier controls reject weaker outcomes.
Final private binding is not confused with prelink ownership or version matching.

Pinned FreeRTOS CM0/M0+/CM0-MPU ordered-mechanism comparisons also pass at O2
and Os inside the same run. These are six object builds and eighteen mechanisms
per mode, not paired final-LTO reference equivalence. The classic focused input
inventory now includes `context/` headers; an unenrolled dependency still fails.
The independent CM3 focused O2/Os replay also passes after that shared repair.

Retained export: `C:/ccrq-0ef2b5a91a`; build: `C:/ccrb-0ef2b5a91a`.

| File | SHA-256 |
| --- | --- |
| Build `results.json` | `63978BDA12DAC2BC5E6F77285CF1125C79C6F80C9F9C16EFFD02D22AFF77C6A6` |
| Build `artifacts.json` | `0D00639B0AE1FD1E5BF5D46099BA49043288F7596F221AC0498A0634C75F3637` |
| Export `qualification-result.json` | `CBC4135D3833E56C7FE8CF26C604C13DFF0307AAFD50701EADECA732CB1462C9` |
| Export `overlays.json` | `C04E1C8A4643349AFFD93A28F4F3011081EA1BF284410D4AE13B3A49F7E4A4A0` |
| Export `source-before.json` | `38D95546BA7F28E61AE647BE83EF21592521790F10E10A464C5F098E29E77A3B` |
| Export `qualification-plan.json` | `81C2A579B1B1AC673F21E3E001360538387849F25C0626747CEA2D5EC71FCB2A` |
| Export `source.zip` | `A3842DE6F3A33070EDAEC8C08D5296B2A4886E17AE9BC4571F78E8AC286E5103` |
| Export `runtime.log` | `98FB72644BB8E04E39D6906F76175CD23E8427D4F51AC4787FE60FF37FEF0DF5` |

The two earlier attempts remain FAIL. `C:/ccr-dev-03/results.json`, hash
`7293B45C2B3E590F4B78A9B1D58625CF61C2FA7E25C9D0288636CC1445D71C30`,
passes seven development firmware cases but rejects the missing Context-header
inventory. `C:/ccrq-90614b1b9e/qualification-result.json`, hash
`9DDE6EA56CF5E74E009A5B2ADF3736F0EC8A065D6528C3F5F6C3516875DD518E`,
records zero drift and the new ELF check's incorrect global-binding requirement
for an LTO-internalized private slot. The later narrow ownership-aware repair
does not alter production sources or rewrite either failed receipt.

The conditional matrix dispatch has a separate 114-check execution-policy PASS
at `%TEMP%/matrix-execution-policy-292277b2689c4069b09555b88a259fb4`.
The earlier `847953d` combined compile result stays historical; this focused
execution does not establish a fresh combined matrix or exact-SHA CI result.

This qualifies the captured CM0 CPU cohort on QEMU 8.2.2, GNU Arm GCC 14.3.1,
and the clean FreeRTOS pin already recorded above. The installed emulator has
no separate Cortex-M0+ model: G0 execution is not inferred from CM0. CM3,
CM4/CM7 FP execution, MPU/TrustZone, global all-optimization/final-linked-LTO
reference parity, STM32 peripherals, board integration and hardware remain
separate evidence. No production runtime or assembly is changed by this slice.

Independent read-only review rehashes all 1,026 exported sources, 3,370 inputs
and 18,519 artifacts without mismatch, reconciles all 298 execution/ELF/prelink
proofs and both reference receipts, and confirms the three receipt hashes above.
All twelve non-Markdown overlays still match live bytes. Later documentation
updates are outside the captured qualification; no current-tree or clean-commit
claim is inferred from it. Both earlier failed attempts remain unchanged.

### Post-Context CM4F FP Runtime

`tools/test_classic_fp_context_runtime.ps1` completes the captured AN386
Context/Fiber FP-state suite. The immutable input is Git archive
`3ece64f4cbd85f70e580cb4a7d9cc1703daa8f6d` plus sixteen explicitly hashed
owned overlays, not a clean-commit/current-worktree qualification. It contains
1,042 sources, enrolls 3,386 source/reference/header/tool inputs, retains 21,763
artifacts and 225 generated inputs, and finishes in 592.26 seconds with exit 0.
Source, input, repository-inventory and resolved QEMU identity drift are zero.

| Execution class | Cases | Required outcome |
| --- | --- | --- |
| Positive | 64 | Exact CHECK, policy-specific OBS and PASS, exit 0 |
| Actual-production causal mutation | 224 | Exact case-specific register/frame/publication reason and oracle terminal, exit 66 |

The literal grid is Context/Fiber, O2/Os, ordinary/final-linked LTO, direct/static
archive, eager/lazy, and positive hash/map 0/0 or 1/1. Seven mutations span the
32 primary-policy tuples: r4/r9 restore, high-FP save/restore, low hardware FP
payload, FPSCR and common current publication. High-save omission preserves
frame geometry and separately triggers required lazy materialization. Panic,
unhandled fault, timeout or a wrong reason never substitutes for its intended
semantic failure. Twenty terminal and fifteen binding controls also pass.

Three workers include two distinct FP-active contexts and one GRO/FP-inactive
context. Both public APIs perform real first SVC and later PendSV transfers,
self-selection and every directed worker edge. Initial/basic and active/extended
EXC_RETURN, Thread FPCA, current/argument identity, masks, vector/priority
readback, stack cookies/guards and canaries are checked. The public C-call phase
requires callee-saved GPRs and s16-s31 only. A separately reseeded assembly-owned
direct-PendSV phase checks s0-s31, FPSCR, GPRs and stack state before another C
call or restoring epilogue can mask corruption. This does not invent a C ABI
promise for caller-saved low FP registers or FPSCR.

Validation-policy builds observe FPCCR before the real handler's first FP
instruction, distinguish eager/lazy active and inactive LSPACT, and verify the
post-materialization state. Handler CONTROL is observation-only, not confused
with resumed Thread FPCA. Primary-policy execution has no pre-save observer
and does not independently establish lazy-entry LSPACT. The observer calls no
Context/Fiber API, executes no FP/coprocessor instruction, and writes only its
exact fixture report/arm objects or matched allocated stack slots.

The finite-constant/stack CFG checker rejects unknown stores, widths, indexed
addresses, unsupported writeback, out-of-object writes, unproven returns,
unresolved PC writes, function/literal fallthrough and non-instruction targets.
Every call enters the exact function entry, including same-body/alias calls;
ordinary internal branches propagate their own states. Nine parser controls,
three byte-decoder controls and 32 actual assembled controls pass: five admitted
and twenty-seven rejected. The latter are checker controls, not extra firmware
executions. This is a bounded fixture proof, not a general pointer-range
analyser, whole-program CFI proof or formal verification of the provider.

Every final ELF has actual production providers, strong SVC/PendSV vectors,
exact storage/runtime expectations and correct Context/Fiber isolation. Pure
Context omits Fiber, legacy and optional configuration providers. Prelink
common-private and fixture-output owners constrain the narrowly allowed final
LTO localization; Context APIs, handlers and cohort definitions remain global.
Disassembly bytes are checked against the actual final ELF, including mapping
symbols that distinguish instructions from literal pools.

Eight actual pinned FreeRTOS `GCC/ARM_CM4F/port.c` final ELFs cover O2/Os,
ordinary/LTO and direct/archive links. Actual upstream headers and fail-stop
boundary providers are used, not copied handler bodies or a fake functioning
TCB/scheduler. Each positive has one matching reference tuple, yielding 64
associations, not 64 independent upstream policy modes. Ordered transfer,
EXC_RETURN predicates, BASEPRI envelope, first SVC and bounded CPACR checks are
required. Upstream always selects lazy preservation; Fiber eager is an explicit
policy difference. These references are link-only, not executed FreeRTOS kernels,
closed whole-provider equivalence or cross-image byte equality. Final references
have no remaining relocations; resolved calls, vectors, retained pointers and
actual prelink definition owners supply the stated bounded evidence.

Retained export: `C:/cfrq-a95232dc6f`; build: `C:/cfrb-a95232dc6f`.

| File | SHA-256 |
| --- | --- |
| Build `results.json` | `6785CB110E939B00D139E3CD5045792A3041D85259E1F137AD776399C51016FF` |
| Build `artifacts.json` | `B8577840A24D43E11CF7EB71427A04AE08B4483D8121EECD56D0703463043855` |
| Export `qualification-result.json` | `79BD8E1642B18C769DFF35DFFA4372814324A17BD1AE15803787D30733F1EFE8` |
| Export `overlays.json` | `A09F8E6D84EADCEB4D12DAA9651957ABBCC5C0364931BDC6796E08C033E756A8` |
| Export `source-before.json` | `B079BF398D10CEF355D18B266648C76F1F8C56CF42D1A8EC373C0F7510A89ECB` |
| Export `qualification-plan.json` | `B99D0AD88C513C9FFA5E6FC41DBCE67D9D1C85722C7E26F307B4D814AA2E7578` |
| Export `source.zip` | `DA31D63BDC246CE2060EA448EB542FB78D382FC0CBA2EA62830196C570BB3CB2` |
| Export `runtime.log` | `AE121217E1D872EEC186F9CB3716552AA3DA285527CAC6F6AB1C71344C3D222A` |

Superseded attempts remain unchanged. The completed `a658770cb4` and
`5461d401b2` full receipts pass execution but are not accepted as final observer
assurance: review identified successively missing PC/store and explicit-edge
checks. Their build-result hashes are respectively
`8135BFA0891734C92B831B835F9F0DA6FA19E53C93C37825627722646E86C4B2`
and `304DFE7F2B465AD9FECEA0D41A8603727617D2B9D456F8BA58E55664CF815A75`.
Development `C:/cfp-closure-dev-e4533db12e/results.json`, hash
`6CD1E2906A8236DA03AF915CB854A67AFCF5841B76B2A4DF58E2647323954BE6`,
remains FAIL for a test's overstrict final-LTO fixture binding requirement;
actual prelink ownership now constrains that localization.

Full builds `87d8bf4e67` and `0ae607d1db` each pass all 288 executions and eight
reference links but remain overall FAIL for real QEMU-library drift. Their
build-result hashes are respectively
`91E2923FFDD08BFD6C6AC6DFAECEA6C7CDBF61DA6D4DC66830348BA3EABDFA2D`
and `E2DDC1C77FFF4BC3344AB70C3DE7F12243733D658D9FC3C9B5718CB0A7624346`.
WSL's dpkg log records package upgrades during those runs; system libz/liblzma
contents changed. No packages were installed or update services disabled by
this gate. The accepted fresh run retains stable post-update closure hashes;
neither failure is waived or rewritten.

This qualifies the captured Cortex-M4F FPv4-SP-D16 hard-ABI cohort on QEMU
8.2.2 with eight model NVIC priority bits, PendSV 0xFF and BASEPRI 0x80, GNU Arm
GCC 14.3.1 and the clean pinned reference. It is not a device-priority-width or
STM32G4 peripheral/board claim. Softfp, arithmetic stress, CM7/H7/H7S, complete
FP panic suites, global all-optimization/final-LTO reference equivalence and
exact-SHA CI remain separate. No production C, frame layout or exception
assembly is changed. The old `847953d` aggregate stays historical.

Conditional dispatch has a separate 119-check execution-policy PASS at
`%TEMP%/matrix-execution-policy-ed87dc5cd0c8434cb59245ba0b218d64`.
Later dispatch/documentation edits are outside the captured export and do not
create a current-tree or clean-commit combined qualification.

Independent read-only review rehashes all 1,042 sources, 3,386 inputs, 21,763
artifacts and 225 generated inputs without mismatch, reconciles all 288
executions, 32 assembled checker controls, eight references and 64 associations,
and confirms the result hash above. All fourteen non-Markdown overlays still
match live bytes. Post-export README prose is outside that qualification.

## Post-Context CM7 FP Runtime

The 2026-11-03 CM7 adaptation and independent CM4 regression replay pass from
one immutable export of `471ec5cfd1e69aefc273f6dd47d487bb1b4e5c6a` plus eighteen
explicit owned overlays. The export contains 1,058 source files. Both complete
suites have zero source, dependency, tool, QEMU-library and inventory drift.
No production C, frame layout, handler assembly or public ABI is changed.

The shared runner now has two immutable explicit Profiles, default CM4 and
separately selected CM7. CPU/FPU arguments, machine, fixture/provider/reference
paths, exact runtime/storage identities, report size and terminal policy follow
that selection. The bounded `Image` ELF/CFG checker and its 32 compiled control
cases are unchanged from `471ec5c`; they are neither copied nor relaxed. Nine
parser, twenty terminal, three decoder and fifteen binding controls remain.
Thirty-two additional synthetic classifier controls reject foreign profile
terminals, capability flags, cohorts/storage, missing model identity and wrong
BASEPRI envelopes. These are checker controls, not extra firmware executions.

Each profile independently passes 288 actual firmware executions: 64 positive
and 224 exact compiled causal controls. The grid is Context/Fiber, O2/Os,
ordinary/final-linked LTO, direct/archive, eager/lazy, and hash/map 0/0 versus
1/1. Seven mutations across the 32 primary tuples preserve the prior exact
failure map. Incidental fault, panic, compile failure or timeout cannot satisfy
a register/frame/publication oracle. Both reference cohorts contain eight
actual pinned upstream final ELFs and 64 positive/reference associations.
They are link-only references, not executed FreeRTOS kernels.

The M7 fixture executes actual Context/Fiber and `ARM_CM7/r0p1` providers on
AN500. Its firmware checks CPUID `0x411FC272`, MVFR0 `0x10110221`, MVFR1
`0x12000011`, MVFR2 `0x40` before emitting an exact model marker. The manifest
uses Cortex-M7, FPv5-D16 hard ABI, NVIC8, PendSV 0xFF and BASEPRI 0x80. Its
316-byte report is distinct from CM4's 312-byte report and the synthetic
320-byte compiled-checker object. S0-S31 storage checks cover D0-D15 bits, not
double-precision arithmetic accuracy. The public-call and assembly-only direct
PendSV phases retain their separate AAPCS and all-FP observation contracts.

Actual pinned `GCC/ARM_CM7/r0p1/port.c` and headers supply the eight reference
ELFs. Ordered transfers, EXC_RETURN predicates, vectors, first SVC and bounded
CPACR evidence remain required. The M7 BASEPRI classifier separately requires
upstream's `cpsid i; msr BASEPRI; dsb; isb; cpsie i` followed by later clearing,
versus Fiber's PRIMASK-preserving writes and saved BASEPRI restore. It rejects
unconditional IRQ re-enabling in the Fiber envelope. Eager initialization
remains an intentional difference from upstream's always-lazy policy.

The fresh CM4 replay additionally compares all 296 native ELFs (288 executions
plus eight nonexecuted references) to `C:/cfrb-a95232dc6f`. Allocated executable
section names, addresses, sizes and bytes match exactly, with zero input drift.
This is not whole-ELF, object, relocation or cross-kernel byte identity.

Retained export: `C:/cf47q-f0254f0288`. Separate builds:
`C:/cf47b-cm4-f0254f0288` (623.57 seconds) and
`C:/cf47b-cm7-f0254f0288` (679.61 seconds). Each records 3,402 inputs, 21,763
verified artifacts and 225 generated inputs. The outer driver exits zero with
zero source/inventory drift; outer PASS alone is not the semantic proof above.

| File | SHA-256 |
| --- | --- |
| CM4 build `results.json` | `FF7640A507553FF736255EE4D18808A0B8CD110FA1F4A683426E7FBD4190DA9E` |
| CM4 build `artifacts.json` | `456138839ADC50E21673649FF4CDB98C3D41C6E899E9EEDA6ECE1AB19DD53E1E` |
| CM7 build `results.json` | `C8E37D9150A5DC1512344649B48120A60DF24A0652F37B1480E42E86D1D65D61` |
| CM7 build `artifacts.json` | `993BA11B711F25E0EDA6E1A836FEDA11E07C1378EDAD0641C29947CB26D7547F` |
| Export `qualification-result.json` | `98C34B3F671CFA73967E9B8997DC9A4D429589EBA99806F3A79128E28BABF39F` |
| Export `cm4-native-code-identity.json` | `54521DCC8E95BF540707E8525E0F105E2F6C98C0361E4A7FC89E96F00BD5AC61` |
| Export `source-before.json` | `FE6A8D5B44D2B8E1A4D606A4D11CAA65D1E0088C25ACB2C6A33EBC5E6DCF1A98` |
| Export `overlays.json` | `24916E9382BCF9B25D1606B69F3A83DBF5F8D8F7645C4A47E8D4116831000B29` |
| Export `qualification-plan.json` | `0E65CA4C0249A817B8225858CF77CA93BFE803B79BB215B29F8288679CCB909F` |
| Export `source.zip` | `5BC3216F14063F97F8CF44ABFC5F23FAB4C7E50E1A957DA669F59304D80F3A58` |

Development smokes remain incomplete receipts: each has nine executions, eight
references and `CompleteSuite=false`. Preserved CM7 development output
`C:/cfp-profile-cm7-dev-2479d8d248/results.json`, SHA-256
`47123864D25C65093A0809B2E1A81A3A34026165F5D6A0C75A3B683D70F96B98`,
remains FAIL for real mid-run README drift. It is not waived or a runtime bug.

The model is M7 r1p2, not affected r0p0/r0p1 silicon. No H7/H7S board,
device-priority-width, cache/TCM, peripheral, erratum-effectiveness, softfp,
arithmetic, complete startup/panic suite, global all-optimization/final-LTO
reference equivalence or exact-SHA CI claim follows. Other profiles and the old
aggregate are not requalified by these focused receipts.

Conditional CM7 dispatch has a separate 124-check execution-policy PASS at
`%TEMP%/matrix-execution-policy-5faca0bd6ece46b1800f8778e1bcd597`.
Later dispatch and documentation changes are outside the captured export;
this is not a current-tree or clean-commit combined qualification.

Independent read-only reviewers rehash both complete cohorts without mismatch.
CM7 additionally reconciles 3,200 dependency records / 69,080 references and
replays the retained ELF audits, exact terminal policy and all 32 profile
controls. The separate CM4 reviewer verifies the unchanged checker and live
non-documentation overlay hashes; the 296-image native comparison is also
independently reproduced. All sixteen non-Markdown overlays match live bytes;
only later README prose differs. No new blocker is found in this bounded scope.

## CM0 Bounded Optimization And Final-ELF Parity

The separate 2026-11-03 non-MPU CM0/CM0+ gate passes from immutable
`471ec5cfd1e69aefc273f6dd47d487bb1b4e5c6a` plus fourteen explicit test overlays.
It changes no production source, context layout, transfer assembly or ABI.
The captured profiles are M0/VTOR=0 and M0+/VTOR=1, soft ABI and ordinary AAPCS.
Final Fiber images use hash/map 1/1, canary and MSP rewind; this is not every
configuration of the backend. No firmware is executed by this gate.

Five explicit `-Cm0NonMpuOnly` paired-object invocations at O0/Og/O2/Os/O3
produce twenty actual objects and thirty ordered mechanism comparisons.
The new driver selector excludes MPU without changing old `-Cm0Only` semantics.
Separate O2/Os legacy replays retain three configurations, six objects and
eighteen mechanisms each, including MPU. Nine admission controls reject the
three new optimizations outside the new bounded selector before discovery or
output creation. Ordinary defaults and the global matrix remain O2/Os.

The final executable grid has two profiles, seven modes (five ordinary plus
O2/Os native final LTO), and direct/archive links: twenty-eight pairs and
fifty-six positive ELFs. Pure Context uses actual engine/state/panic and three
actual CM0 providers, no legacy/Fiber/configuration substitution. Every upstream
image compiles the unchanged pinned CM0 `port.c` and `portasm.c`, real headers,
typed retained constructor/scheduler roots and fail-stop unavailable boundaries.
No whole-archive extraction, copied handlers or successful fake kernel is used.

Strong vectors, exact runtime/storage cohorts, prelink common/upstream owners,
real native final bodies, slim input IR and actual link-driver LTO plugin
identity are checked. Ordered first-start, first-restore and PendSV mechanisms
retain the documented adaptations: SVC 70 versus upstream 100, validated initial
register restore versus upstream skip, common/TCB publication and saved PRIMASK
versus unconditional IRQ enable. This is bounded mechanism evidence, not closed
whole-function equivalence or interpretation of retained C constructor bodies.

Each pair compiles three actual-source PendSV mutants: incorrect save stride,
missing high-R9 restore and omitted mask-restoration sequence. All eighty-four
must reject at their assigned mechanism, not an unrelated compiler/link/ELF
error. Eight optimized-Python invocation controls, six parser controls and two
counterfeit-diagnostic controls also pass. Current source/object, dependency,
archive and actual final-ELF records are retained.

Retained root: `C:/cm0fq-c660e0b75f`, source: its `source/`, build: its `audit/`.
The complete receipt has 3,400 inputs, 10,899 verified artifacts and 3,300
captured source-byte records, with zero source/input/inventory drift. An
independent reviewer rehashes those inventories and fourteen owned paths without
mismatch, cross-checks 1,148 compile-command mappings, seventy archive commands,
forty LTO-plugin traces and all assigned compiled-control rejections.

| File | SHA-256 |
| --- | --- |
| `audit/results.json` | `4CA71B77C0AD7BA53ADE0426A97305E42CC53A5FD07720F8701F15C0B914399E` |
| `audit/artifacts.json` | `27C9D865EC75507DB6B5146FCDC0F79121A750D19B27A0E728AA5CA3CEAF35A8` |
| `overlay.json` | `B6504773BB4182877478AA5476E391AC8D1FC2D35DAE2D78C029AE7829ACD022` |
| `HOLD-verified.json` | `AAC201C3E7B3A976274211473881EBA9153E6D5119BEBFD91881B05441DB7977` |
| `base.zip` | `5BC3216F14063F97F8CF44ABFC5F23FAB4C7E50E1A957DA669F59304D80F3A58` |

Earlier roots `cm0fq-878052bd2d`, `cm0fq-8e989961dc`, and
`cm0fq-d918caed67` remain FAIL for, respectively, compile failure, a control's
wrong rejection identity, and final-link failure. Their build-result hashes are
`5C53D9964D2F59F6496C0E37D97A7D2F9D6F018FB850A4FE7EE25D1ABDE0E3E6`,
`2D39B09081DADBF9CBCCC0FFC3192FDCDFA08DB93446DAFC954370588095EDE7`, and
`A5FE20C22DF76CF5CFF4B24C9676A23C6A4306384B3B1B037033609BEE79E38A`.
The old ad hoc `HOLD.json` used an invalid nested PowerShell array check; it is
not accepted. The explicit corrected verifier and independent review above
replace that invalid handoff, not any failed qualification.

A separate live helper-import smoke passes three compiler objects and four
negative controls under
`%TEMP%/cm0-freeze-helper-review-977a9ac555ae45ee988390ba70cb5101/`
`parity-helper-imports-1650a2b4b9884f378b638da97a6aa2f7`.
Later documentation is outside the captured export. This is not a fresh full
default matrix or exact-commit CI result. CM0+ VTOR=0, MPU, reserved-r9 and other
policy combinations, other profiles, global parity, G0 CPU execution and board
qualification remain separate; the earlier M0 QEMU receipt is not extended.

## Isolated H7S Managed Build Qualification

The separate 2026-11-03 offline integration gate passes both fresh managed
Debug and Release builds at `C:/h7sb-68b7390d6731`. Its four maintained harness
files are `tools/test_h7s_snapshot_build.ps1` and the README, `audit.py` and
`test_audit.py` in `tools/fixtures/h7s_snapshot_build/`. No production source,
layout, transfer sequence or live project metadata changes in this slice.

The exact 331-file production export is pinned to
`471ec5cfd1e69aefc273f6dd47d487bb1b4e5c6a` and checked against Git blob IDs.
Only `context/`, `fiber/`, `basic_types.h` and `mcu_core.h` enter it. No live
tools, untracked WIPs or old build outputs are imported. Outer Boot application,
Core, project, linker and Drivers files are separately content-addressed, not
attributed to the library commit. Production C/header/assembly remains unchanged
through `cf56546`; later per-port Markdown is outside this captured export.

Private configuration, p2 metadata, workspace, Java home and temporary paths
isolate the actual installed CubeIDE 2.2.0 launch. The installation directory's
name still says 2.0.0; that name is not used as its version identity. GCC is the
existing GNU Arm 14.3.1 toolchain. No package provisioning, live IDE/workspace
access, CubeMX source regeneration, debugger, programming or board run occurs.
The helper rejects build hooks, unexpected builders, escaped linked inputs,
alternate ports and reused output roots; originals are sealed apart from the
private generated metadata.

Both generated builds admit exactly 35 objects, including Fiber v1: 33 C, one
C++ and the real startup assembler, each reconciled with its source and depfile.
Debug preserves C O2/C++ O1/GNU++20; Release preserves Os/GNU++14, with M7,
FPv5-D16/hard ABI and no LTO or QEMU-derived priority policy. The board application
still uses the legacy five calls; compiling Fiber v1 is not consumer migration.

Prelink provider audits accept exactly the canonical Context/current/reverse
owners and the legacy/forward providers. Only SVC/PendSV permit the exact two
known weak application/startup definitions alongside the strong selected-port
definition. Final SVC/PendSV are strong global functions. Reset instead must
have its exact startup-only weak owner and final weak Thumb function extent,
with matching entry/vector 1 and MSP `0x20010000`. The final ELF audits also
check no undefined symbols, device memory placement, exact runtime/storage
cohorts and the read-only twelve-byte expectation section. Its three pointers
come from `app_core.o`, `fiber_v1.o` and the explicit runtime expectation unit;
older eight-byte receipts are not silently reused. Unused APIs/configuration
may be collected normally.

Revision 2 requires whole executable/allocated/file-backed handler extents,
aligned writable RAM containing the complete current slot, and valid physical
file-load extents as well as virtual memory extents. Eighteen maintained
admission-control groups pass. Each configuration also
rejects eleven changed copies of its actual ELF for the assigned vector,
expectation, handler-binding, Reset-binding, entry or MSP reason. These are
also extended by exact handler-extent, current-slot writable-RAM and physical-load
extent rejections. These are audit controls, not extra firmware executions.
The complete receipt enrolls
19,711 inputs, 525 copies and 1,594 artifacts with zero identity drift.

| Captured file | SHA-256 |
| --- | --- |
| `results.json` | `911EF8B9D1B8655C52D9938B646EFAF4ED070F37BF53C22052043B0CAAE2DB44` |
| `artifacts.json` | `86BCB13BA019606F2F6BE33F5057C1B7D15A0BAED98E161F85BE8B2474975AE8` |
| Debug ELF | `533379EBDAC5F4D7B6684F8EF46183CB6C099CE62546E71E34358E40F178C159` |
| Release ELF | `73BF7CD589F2685F6B27823943E559D6A30AA51D19CC13420AB9FECE3E3AC16F` |
| Launcher | `A2508259E7865FA8810D6DDE22A44A86AD56B3762A1F714404DBD98E40066D45` |
| `audit.py` | `F8D2324A282C0F3F33F616276CFF045F93594D12C3B9F164223AC34C8E9F5C01` |
| `test_audit.py` | `B1709F23FCC00F03BB3EDDF1C609BCC40DCF3C9A20F23BBDEC0729B58BD4861A` |

Independent review of the initial complete PASS at `C:/h7sb-44f0b729e833`,
receipt SHA-256
`3E18C92F0ED00B9467B4384FFD191C97C84DEBE8AF2C2DD926ADE4BCD0926075`,
reproduced six false passes: each of two ELFs accepted a foreign handler address,
a current slot in read-only flash, and a foreign physical load address. These
are oracle defects, not observed defects in the original binaries. That receipt
is preserved unchanged but superseded for ELF admission. Reproductions remain
at `C:/h7sr-p2-5f6e74cff1`; revision 2 explicitly names the superseded receipt
and rejects all three cases by exact diagnostic before fresh acceptance.

Earlier attempts retain their FAIL verdicts and receipts; none is waived:

| Root | Failure | `results.json` SHA-256 |
| --- | --- | --- |
| `C:/h7sf-bootstrap-13ef946bbd` | PS5 default path binding | `077D30BB98622908513204EC78B0BD0090043C476BDEA4A33502D737FD39981D` |
| `C:/h7sp-fed7c1fdaed9` | Archive CRLF conversion violates exact blob identity | `18F19070DED33CBD199A330B8812BC74B56D72390BEE01432BEEA44D50E8A485` |
| `C:/h7sp-ff81e2ed35a8` | SystemRoot environment-key casing | `2CB47759E57DF80C234D1EB3B3EEB63D56157231C1CCD147385C8602A799463D` |
| `C:/h7sb-8e9d5c02feff` | Harness incorrectly demands C optimization on startup assembler | `E46F419DDCE997939EB1DD6312DAFB4300383BE715DDF5CE4A3902DA789F3F51` |
| `C:/h7sb-2855cf2ea442` | Harness rejects the known weak/strong handler ownership set | `D3E8016BEBF365FDC9FEF0F18A0759B79E789F50D0C7F576AF5DC459383D5601` |

The later Reset-owner correction was made before the accepted fresh launch;
requiring a strong Reset would have contradicted the real STM32 startup.
The positive/negative owner checks now distinguish Reset from the port's strong
exception handlers. This scope accepts captured offline integration only.
Active VTOR, real exception/FP behavior, cache/TCM, affected-silicon erratum,
H7/H7S boards, global parity and exact-SHA CI remain separate open evidence.

Independent read-only revision-2 review rehashes 21,830 input/copy/artifact
entries (20,876 unique files) twice without mismatch, missing files or extras,
and confirms all four live helpers and 331 exported Git blobs. The reviewer
replays eighteen control groups, twenty-two retained ELF negatives and all six
historical false passes with their exact revised rejections. Both configurations
retain all eleven allocated sections' geometry and bytes versus revision 1
(NOBITS geometry is compared separately). Release is whole-ELF identical;
Debug is not, so whole-image identity is not claimed for Debug. No confirmed
residual admission defect is found within this bounded offline scope.

## Classic FP Opt-In Seven-Mode Grid

The separate 2026-11-03 CM4F/CM7 full-grid qualification passes from immutable
`910346d3d5d505e0ff0908158cf47d07884cf327` plus four explicitly captured test
overlays. The export has 1,075 files; the CM7 Python entry overlay is unchanged.
Only the shared Python runner and two PowerShell launchers change code. No
production source, frame layout, CPU transfer assembly, ABI or default matrix
dispatch changes. Later documentation is outside this captured source export.

`-FullOptimizationGridFP` is an independent opt-in: ordinary O0/Og/O2/Os/O3
plus O2/Os native final LTO. Each profile passes 504 target executions: 112
positives and 392 compiled causal controls. Both Context/Fiber consumers,
direct/archive links, eager/lazy FP policy and primary hash/map 0/0 versus
validation 1/1 enter the grid. Each of the seven modes contributes sixteen
positives and fifty-six assigned causal rejections. Fourteen actual pinned
upstream final ELFs have 112 positive associations; reference images are not
executed and do not represent 112 upstream policies or complete kernels.

The default grid retains its exact 288/8/64 execution/reference/association
inventory and ordering. Development subsets remain incomplete: default 9/8/2
and full-grid 11/14/4, both `CompleteSuite=false`. Thirty-four synthetic
option/count controls reject wrong types, inventories and request/completion
bindings. They are not extra firmware executions.

The bounded `Image` checker and its 32 compiled observer controls are unchanged,
as are twelve previously reviewed implementation components. Actual-port O0
alone needs a separate CPACR spill/guard proof: every decoded normal exit follows
an exact word read/OR/store or an exact already-full-mask read guard. Path
intersection, allocated-stack provenance and flags are tracked. Reclaimed or
call-crossing spills cannot prove values; conditional calls and nonconstant BIC
RHS fail closed. Other modes and upstream references retain their prior bounded
immediate patterns. This is not arbitrary pointer/callee or whole-provider proof.
Thirty-six separately compiled O0/O2 controls pass: eight admitted positives and
twenty-eight exact rejections, including branch/IT skips, stale spills, missing
normal exits, wrong mask/address/width and inverted BIC guards.

Both complete builds have 3,419 inputs and 38,060 verified artifacts, zero
source/dependency/tool/QEMU-library/inventory drift, and `CompleteSuite=true`.
The outer export is `C:/cffq-af68ee4540`; builds are
`C:/cffb-cm4-af68ee4540` (1,090.45 seconds) and
`C:/cffb-cm7-af68ee4540` (1,131.54 seconds). Separate old-subset comparisons
against `C:/cf47b-cm4-f0254f0288` and `C:/cf47b-cm7-f0254f0288` preserve all 296
native ELFs per profile: allocated executable section names, addresses, sizes
and bytes match, with zero input drift. This is not whole-ELF, object,
relocation, cross-kernel or new-mode byte identity.

| File | SHA-256 |
| --- | --- |
| CM4 `results.json` | `03CFA1FC51E3ABDA7469CF576F94E4FBEB24F429EBF284F9637A2559DEEAF364` |
| CM4 `artifacts.json` | `AD1E82B70C117B4B15D85DF5BBF26DB7FEF57BEE2393F783BCC542262A329D4B` |
| CM7 `results.json` | `BD46EADD08C3B81D0AE69F504B0DBFA3ED232A4311BDF0A9CADCC96EF446B3EA` |
| CM7 `artifacts.json` | `AE1E073DBF0250918446F43D8B66E1F45C52DE157CD07B60BC2118E12CA8B6AA` |
| Export `qualification-result.json` | `062803AD8F3385E010FD5BA44D776C26605BD155DEDBF03187538E61FA8E6F7F` |
| Export `source-before.json` | `554CC32F87CC69C40018AF862CDE6F0F57F756FB8CC543F523FBE66766CD7929` |
| Export `overlays.json` | `3994ABD57A3651BCA2BCE920852A5F93029C6DA9F3D8CE30CD949584795299EB` |
| Export `qualification-plan.json` | `21547F876BB10765FC43330A5365DA4AA4C8D268111C61EAB0768818AFFA52FB` |
| Export `source.zip` | `684D3F2733EA6FBCAAB147709691F9260FD8A57C26E47248D2C21318C72A8E23` |
| Export `cm4-default-code-identity.json` | `0F7DC87F9EB4825417D0E35A20DA697C56AAB55B0A95AA033A85995800FA81AA` |
| Export `cm7-default-code-identity.json` | `7A86C9CB756EA802342BD1A7364D21F8417A954A244F8D4B984028ED369D294B` |

Development evidence and failed/superseded oracles remain distinct. Final
incomplete development handoff `C:/cfp-fullopt-q-76d45c7706/handoff.json`, hash
`DD937E02B14F90927F0227CDA855D238E950410021B1AD1B22EBE114A92247C6`,
records the final source and both 11-case receipts; it cannot qualify the full
grid. Earlier CM4 `C:/cfp-fullopt-cm4-dev-1ef4076c8d/results.json`, hash
`B3E63260274921C966B5FFA6B7C30FEB36E7C61DEFFB62138FCB58BCFC665488`,
and CM7 `C:/cfp-fullopt-cm7-dev-2565e11bcb/results.json`, hash
`870AB206252533DD8C7E1553AB169E5471AC2CD550125AE129D64695D2E8CD00`,
remain FAIL for the old immediate-only CPACR oracle rejecting actual O0 code.
`C:/cpacr-controls-dev-2f77cec0c3/failed.json`, hash
`F6CCE1469D20EE6B36DECD9E3252F75DBDD718DD9FD7F3C2B142E79CD138E556`,
remains FAIL for a control's wrong diagnostic. Provisional source-only
branch/spill and inverted-BIC false passes were repaired before this complete
run; preserved source-derived reproductions are not mislabeled as compiled
reproductions of those older oracles.

The final shared runner hash is
`9691A8543513BB2BA00F22C464C03B87EF498C5689F0BD15C21394901AFD8A7A`.
Independent CM4 review rehashes 41,479 unique input/artifact files and reconciles
395 generated files, 5,600 raw depfiles and 120,554 dependency entries without
mismatch. Separate semantic review for each profile replays all 112 positive
ELF audits, fourteen reference mechanism checks, 112 associations, 504 exact
recorded terminals, 32 observer controls and 36 CPACR controls with no finding.
The CM7 review additionally verifies exact r1p2 CPUID/MVFR terminals and the
PRIMASK-preserving mask envelope rather than inferring them from CM4.
Independent CM7 inventory review rehashes its 41,479 unique files twice and
reconciles 395 generated files, 5,600 depfiles and 120,890 dependency entries,
again with no mismatch or missing/extra artifact. A separate direct review of
592 old/new CM7 ELF files reproduces all 296 executable-section identities;
it does not rely solely on the parent comparison receipt.

CM4 remains the AN386 hard-FP model; CM7 remains AN500 M7 r1p2 with the exact
capability/terminal identities above. S0-S31 storage is not arithmetic accuracy.
Softfp, non-FP/MPU profiles, other profiles/policies, affected-M7 silicon, STM32
peripherals/NVIC widths/cache/TCM, complete startup/panic suites, hardware,
global final-LTO equivalence and exact-SHA CI remain separate open gates.
These focused receipts do not replace the historical default aggregate.

## Post-Grid Combined Compile Qualification

The complete default compile/link/codegen matrix passes on 2026-11-03 for
clean committed source `ad29f15a0d4e2659c6bad8c46c8d79de27b29f72`, without
overlays. The retained export is `C:/fcmq-9edf4c0570`; its actual repository is
`experiments/h7s_fiber_test/Boot/app_core/fiber/`. The absent-at-launch build
directory is `C:/fcmb-9edf4c0570`. Source archive, driver, log, plan and before/
after manifests are retained. No untracked or stopped WIP enters this export.

The child exits zero after the final settings negatives and common-source
inventory checks, with the exact `PASS: compile matrix completed.` footer.
Elapsed process time is 2,142.00 seconds, not a runtime performance benchmark.
All 1,075 source files retain their bytes and inventory. All 916 recorded
external FreeRTOS/CMSIS files retain their hashes and inventory; the reference
remains clean at `a50edad08b29052631aa469d4df6e6ec7ff68878`.

An independent source-provenance review verifies all 1,075 files / 10,540,308
bytes against their exact Git blobs, ZIP entries/embedded commit, and source
manifest. There are no missing, extra, duplicate or reparse source files.
The launcher uses explicit existing tools, a new Git archive, cleared child
QEMU/Python-optimization environment and an explicit pinned reference. It does
not provision packages, alter services, program a board or write live project/
IDE metadata. Its external junctions do not enforce read-only access; before/
after input checks, not filesystem ACL claims, establish the observed identity.

The selected gates include Context/Fiber ownership and consumer checks,
ordinary O2/Os pinned FreeRTOS parity, ABI/cohort/archive/GC/LTO controls,
applicable protected/staged source/codegen/link tests, and final settings
negatives. Included host and bounded Unicorn constructor/guard execution are
not full exception or MPU-enforcement execution. Conditional QEMU architecture,
Secure and TF-M probes are explicitly `NOT_RUN`; neither
`-RequireArchitectureExecution` nor `-SettingsOnly` is selected. The separate
classic full-grid receipts above remain independent evidence.

| Retained file | SHA-256 |
| --- | --- |
| `matrix-result.json` | `71C4B6CE37B8F942B2F21569099D9C70D63C0ACE594DAE69A9EB3568654773FE` |
| `matrix-plan.json` | `DF82E5FF3F1BA2DFE7F51FBDD4CFA295418171BB47897285F135D8C106440346` |
| `source-before.json` and `source-after.json` | `3DBB20428D420D29AFD2463C2C27A01ABAECC022F2DC36868D1E48890141C2B0` |
| `external-before.json` | `0B365988E5519992709FC48101A1ED9FCDFBD5C5AD6E9CC5C8172F01C5417411` |
| `source.zip` | `B025BB82E36DA82155A429AD995D190DF1645DF5167E627F84CB8AD7F23CE0D0` |
| `matrix.log` | `993EA388728F7A2D9930F85A2E4B53FD7BB430C6FB22D6413EEA30A0610EEC60` |
| `driver.ps1` | `919976E5077B0660A7ADCA61587510FF3D79FC3B9C9A0DB446587DD25FEB72BC` |

Independent bounded reviews confirm all 81 applicable static gate headers in
source order, both O2/Os parity completions, 42 generic cells across eighteen
configurations, the late settings gates and exactly one final footer. All nine
runtime-role/reader/matrix inputs retain their closing hashes. A separate review
rechecks the 1,075 source and 916 external records plus 657 selected Context/
Fiber/consumer/source-reader inputs and copies, without mismatch. It does not
claim a rehash of the entire build directory. CM0 no-VTOR, mutant unused-variable
and synthetic optional-configuration RWX warnings remain visible in the log.

This replaces `847953d` only as the latest captured default aggregate; that
earlier receipt and all historical FAILs remain unchanged. Later receipt prose
and the separately developed CM4 MPU execution pilot are outside the export.
No whole-build artifact inventory, exact-SHA hosted CI, global all-optimization/
final-LTO reference equivalence, staged-profile activation or hardware claim is
created by the outer PASS. The all-catalog freeze gates remain open.

## Classic MPU Handler CONTROL Repair

Status: source repair implemented; fresh bounded CM4 MPU pilot execution and
the combined default matrix pass. The new guard-regression review is pending.
The first seven-image pilot is deliberately not a complete qualification gate.
Its manifest is M4 hard-FP, eight MPU regions, O2/native/direct, eager policy,
FP-inactive workers, hash/map 0/0, with separate Context and FiberV1 consumers.
All receipts retain `CompleteSuite=false`. No board is used.

Both immutable attempts use tracked base
`30036f8426858dce98680b5bb124e2e3f58f38c2` plus eleven explicitly hashed new
fixture files, 1,086 total source files, and zero source/inventory drift:

| Retained receipt | Outcome | SHA-256 |
| --- | --- | --- |
| `C:/cmpb-1e46914fe4/results.json` | FAIL, startup panic V | `79C3B61C90C6BF11B7A80C8010C698EEEB5B24AA1345E9E53A77EBB016AEC9CE` |
| `C:/cmpq-1e46914fe4/pilot-result.json` | Outer FAIL | `65346D6DA593F8D2E4D918569B3E96BDF102FAF4D58D7E2FAA34B2EC4307DE5F` |
| `C:/cmpb-4bfe3654df/results.json` | FAIL, first running SVC panic l | `12FCB94F49BBB5C858CB44608B0834499C6F457C446B3289CE7C6EE4E355030D` |
| `C:/cmpq-4bfe3654df/pilot-result.json` | Outer FAIL | `231D52199B9CE48E7A1E095649CEB5EF12FE852630CE9824B48D6EE02DCDC3A6` |

The first attempt violated this selected port's explicit nonzero-VTOR
precondition. It is a fixture integration failure before MPU activation or task
execution, not a switch defect. The replacement preserves reset MSP/PC words
at zero, installs the full active vector table at 0x400, and starts privileged
code at 0x800. Linker and native-ELF checks admit the matching reset words,
strong handlers and actual VTOR store/barriers. The port guard is not removed.

The second attempt exposes a production validation defect. A separately
retained diagnostic replays the unchanged failing ELF under QEMU/GDB and
observes Thread `CONTROL=3`, `IPSR=0`, then actual SVC MRS `CONTROL=1`, `IPSR=11`
with exception return FFFFFFFD. Panic receives l and LR=23E5, identifying the BL
at 23E0 after the incorrect `CONTROL & 3 == 3` guard at 23CA..23D4. QEMU exits
with status 66 and GDB with status 0. The ELF and 82 recorded tool/library hashes
are unchanged, and no debug process remains. Diagnostic receipt:
`%TEMP%/cm4mpu-control-diag-20261103-61da2cf4/diagnostic.json`, SHA-256
`5C4853A4513C893F327754B9EF0C665B64097364F4ACDFD78FCF6510B00D538C`.
This is diagnostic evidence, not a successful runtime qualification.

The distinction is architectural: live Handler CONTROL is not the initial
Thread CONTROL template. [Arm DUI0553B, section 2.1.3](https://documentation-service.arm.com/static/5f2ac76d60a93e65927bbdc5)
describes Handler SPSEL read/write behavior and exception-return selection.
[Arm DAI0298A](https://documentation-service.arm.com/static/5f0352c0cafe527e86f5bc66)
separates Handler FP activity from the interrupted floating-point context.
Pinned FreeRTOS classic MPU paths capture raw CONTROL; CM4 does so before
conditional VSTM. EXC_RETURN, not live Handler FPCA, identifies the interrupted
frame. The old serialized 3-only basic and 7-only extended requirements are
also incorrect. PendSV is not reached in the failing diagnostic; that follow-on
issue is source/compiled-code analysis, not an observed saved-image failure.

The accepted repair contract preserves original raw save/restore and geometry:

- Fresh initial images retain exact CONTROL=3 and the exact basic PSP frame.
- Saved CM0/CM3 and CM4 basic images admit raw 1 or initial 3; CM4 extended images
  admit raw 1. Reserved/control-policy bits and exact EXC_RETURN stay checked.
- Running Thread/PSP SVC and pre-save Handler CONTROL is 1. Initial Thread/MSP
  start-SVC admission remains 0. CM4 post-VSTM guards admit exactly 1/5; full raw
  callback-state preservation remains mandatory.
- Both CM0 Handler MSR readbacks expect 1, not the Thread template 3.
- Private cohort semantics advance to 0x00020001 for CM0/CM3 and
  0x00020008/0x00020010 for CM4/M7 region variants. Public storage geometry and
  mandatory forward/reverse ABI versions do not change.

Analogous CM0/CM3 defects are source-confirmed, not newly executed on those
cores. Scoped v8-M review finds different, already separated Handler/saved-image
contracts; this repair must not mechanically modify those ports. Actual-source
guard controls, emitted success-path GRO closure, stale-cohort negatives,
reference-mechanism checks and fresh execution evidence remain required.
FP-active/eager/lazy MPU execution is not established by the basic-frame pilot.

### Focused Repair Qualification

The refreshed focused O2/Os receipt retains twelve repaired production compiles,
six baseline compiles, six pinned-reference compiles and 36 maintained mechanism
assertions. Its 858 checks close with 1,493 inputs and 173 artifacts unchanged.
GCC-resolved `as` and `cc1` are enrolled before compilation, matched against all
24 compiler traces, and rehashed at closing. This corrects the earlier focused
driver's guessed assembler enrollment; the old `DA95929F...` receipt remains
historical and does not gain a retrospective tool-identity observation.

| Record | SHA-256 |
| --- | --- |
| `C:/classic-mpu-control-repair-workers-098ea650d058472e88cd0eef14d373f3/results.json` | `BDF6C2977EFFC31DA0AD7737A41D9FEDA34C7644287D74FB2D9DFD0F9AE0893A` |
| `C:/classic-mpu-control-repair-handoff-workers-098ea650/handoff.json` | `D54ACDB6F9B87615573D5D385796B113FA22E590C2BDB161C37B652178D35F66` |

Independent assembly review compares 36 transfer bodies across the baseline
and current builds. Only the two intended CM0 Handler readback immediates per
optimization change in those instruction spans; raw MRS/save/MSR ordering is
retained. This focused driver does not itself prove relocation identity.
These are bounded mechanism checks, not complete generated-program equivalence
or execution on CM0/CM3.

### Clean-Commit CM4 MPU Pilot

Exact source `624a4353983e03e766533df3abaa396593c750be` is exported with no
overlays to `C:/cmpcq-d7389ea0cf`; the build is `C:/cmpcb-d7389ea0cf`.
All 1,086 source paths and bytes match Git blobs. Opening/closing source
inventories and the recorded 2,416 inputs and 480 artifacts have zero drift.
Resolved compiler subprocess identities are enrolled before the first compile;
native nm is explicit. No archiver, gcc-nm or target board is used.

All seven distinct images execute successfully on the existing AN386 model:

- The separate model image reports CPUID `410FC240`, MPU_TYPE `00000800`,
  IRQ0 priority mask `FF`, MVFR0 `10110021` and initial MPU_CTRL `0`.
- Context and FiberV1 each run the return, current-aperture write-fault and
  peer-stack read-fault images. The return images observe eight selections,
  one self-selection and six cross-selections before the worker entry returns
  through the constructor-installed return veneer, enters the actual production
  SVC72 path and reaches panic `R`.
- Fault images observe MemManage IPSR `4`, EXC_RETURN `FFFFFFFD`, CFSR `82`,
  HFSR `0`, the exact compiled access PC and MMFAR `20000000` or `20004080`.
  A generic fault, timeout or mismatched terminal channel is not a PASS.

| Record | SHA-256 |
| --- | --- |
| `C:/cmpcb-d7389ea0cf/results.json` | `63E6AA02B995634C2B51AF435ACD7C5F96D0437827E08B9052C54B19E8927F25` |
| `C:/cmpcb-d7389ea0cf/artifacts.json` | `88FF4E9447F9C0F69BAD6993DC81FDE7413976CFF9AA69C2B8A7E6B58B10BF1A` |
| `C:/cmpcq-d7389ea0cf/pilot-result.json` | `AB2FE7FB0863DDBD8ABB5D3B36A1184520074D624DB532E056D21DB0AA615F44` |
| `C:/cmpcq-d7389ea0cf/pilot-plan.json` | `8F5963CC085E3F6CFD4B284EDB4E28C019BDAB71DA4CD1275BA437252A0ACA20` |
| retained `driver.ps1` | `87201DD34443C75C579261E0647D3450D26D38ECBE56FB071C4971868107CB40` |

Both receipts deliberately retain `CompleteSuite=false`. This is O2, ordinary
direct linking, eight regions, eager policy, FP-inactive workers and hash/map
0/0. It establishes real basic-frame MPU transfer and these two enforcement
cases on that model, not explicit GPR/FP stress, lazy FP, other configurations,
CM0/CM3/CM7 MPU execution, STM32 peripheral behavior, CI or hardware validation.
The pinned reference identity is captured, but no new paired final-reference
ELF/LTO parity or upstream runtime execution is claimed. The two earlier FAIL
receipts remain FAIL; this fresh candidate run does not relabel them.

### Post-Repair Combined Matrix

The complete default compile/link/codegen aggregate passes for exact
`624a4353983e03e766533df3abaa396593c750be`. It runs from
`C:/fcmq-733485291b/experiments/h7s_fiber_test/Boot/app_core/fiber`, with build
outputs in `C:/fcmb-733485291b`, and exits zero after 2,178.28 seconds with the
final matrix footer. All 1,086 exported source files and 916 external inputs
(the pinned FreeRTOS regular files and CMSIS headers) have zero closing byte or
inventory drift. The reference remains clean at
`a50edad08b29052631aa469d4df6e6ec7ff68878`.

Both O2/Os FreeRTOS mechanism passes complete, including the repaired classic
MPU groups. Common/runtime ABI, Context/Fiber, archive/cohort, generic build
cells and the late settings gates also complete. The new standalone
`classic_mpu_control` development runner is not committed in this export and
is not admitted by this result; its oracle/closing review is separate.

Independent review matches every exported file to Git blobs and ZIP bytes,
rehashes the complete snapshot and all 916 recorded external files, and checks
81 static headers in source order, 42 generic cells across eighteen
configurations, all 67 late settings headers, 62 expected rejection diagnostics
and exactly one final footer. This does not invent an external-after manifest
or strengthen the driver's recorded host-tool identity boundary.

| Record | SHA-256 |
| --- | --- |
| `matrix-result.json` | `A70D665472CD91FC5C4C9D19AD2785DB29D2913A46FD1E3578241B9D63441F2D` |
| `matrix-plan.json` | `FB5F0866FC1719BFE90163A2AE3EABDF252BE8BA1B9E5A610D8A34D9290EB44B` |
| `source-before.json` and `source-after.json` | `9244D9F4CC4F3DB2C0F3A5CB489D8E278544FC3D54468F8726BF63129A9D110E` |
| `external-before.json` | `0B365988E5519992709FC48101A1ED9FCDFBD5C5AD6E9CC5C8172F01C5417411` |
| `source.zip` | `9637BBBB54B2F78028F31E8A7362159DF698C64D65EB34D3C06A0E31E9C425C4` |
| `matrix.log` | `DD9AD818920822F63BD59D93F57A37B56903FE30DDDC9A81494C0FB541FA00B9` |
| `driver-postrun.ps1` | `919976E5077B0660A7ADCA61587510FF3D79FC3B9C9A0DB446587DD25FEB72BC` |

Paths in the table are relative to `C:/fcmq-733485291b`. The retained driver is
copied and hashed after the run; the external closing rehash is reported by the
driver, not persisted as a separate external-after manifest. Neither is an
additional before/after tool-identity observation. Known CM0 no-VTOR, mutant
unused-variable and synthetic optional-configuration RWX warnings remain in
the log. No whole-build artifact inventory is claimed by this outer receipt.

This replaces `ad29f15` only as the latest captured default aggregate. Earlier
receipts and FAILs remain intact. Conditional QEMU architecture/Secure/TF-M
execution is NOT_RUN here; the separately admitted seven-image MPU pilot is
not silently included in the aggregate. Global all-optimization/final-LTO
reference equivalence, hosted CI, staged-profile activation and hardware
qualification remain separate gates.

### Clean-Commit Classic MPU CONTROL Guards

The standalone [CONTROL regression suite](tools/fixtures/classic_mpu_control/README.md)
passes for exact `e971263e4fa6d6c65565f4fb6836d8f649352afd`. The no-overlay
Git export is `C:/cmgcq-2dd4f3a4b1/experiments/h7s_fiber_test/Boot/app_core/fiber`;
outputs are in `C:/cmgcb-2dd4f3a4b1`. All 1,096 exported file paths and bytes
match Git. The outer driver exits zero after 262.10 seconds, with no source,
inventory or enrolled-tool drift. The child closes with 817 inputs and 7,079
verified artifacts. This source commit adds only ten test files; the nine
production C/header files from the CONTROL repair remain unchanged.

The bounded inventory covers CM0+ with and without VTOR, CM3, and CM4/M7 with
8/16 MPU regions:

- Thirty-five host runs perform 238,680 source-derived scalar guard checks at
  O0/Og/O2/Os/O3. These are not complete validator or validation-order execution.
- Sixty-three actual ARM codegen cells cover those five ordinary modes and
  O2/Os native LTO both with and without function sections. Six hostile compiler
  flag families remain active, with a compiled unannotated control in each cell.
- Fifty-six matching final links and 56 strict cohort mismatches cover direct
  and archive linking in ordinary/slim-LTO modes. The old-generation provider
  is an explicitly labeled identity-only mutation, not historical behavior.
- The emitted pre-MRS graph derives its roots from actual handler transfers and
  retains section/entry/extent identity. Its bounded byte CFG rejects reachable
  undecoded bytes, unsupported transfers and altered capture/store sequences.
  Captured objdump decoding is trusted; this is not a general ARM verifier.
- All 129 additional assurance identities pass: 24 capture-sequence controls,
  32 derived-prefix controls, 32 duplicate-local-helper controls, one paired
  copied-classifier closing control and 40 byte-coverage records. The last set
  includes 32 intended gap rejections and eight proven-unreachable pool
  acceptances under the bounded CFG. The closing-only pair reuses genuine
  parent observations; it is not another compile suite.
- The actual PowerShell receipt checker accepts one complete receipt and
  rejects 162 malformed variants. The outer driver independently binds the
  complete Assurance and Closing identities before the child executes.

GCC-resolved compiler delegates, explicit native binutils and the slim-LTO
plugin are enrolled before their use and checked at closing. This is a bounded
installed-tool inventory, not complete transitive host/OS dependency closure.
The ten reviewed source bytes also match the committed Git-LF bytes without
normalization changes; metadata and closing identities are pinned before launch.

| Record | SHA-256 |
| --- | --- |
| `C:/cmgcb-2dd4f3a4b1/results.json` | `AD7D52E291C24CBE0D3CE64DF335176F8DCCD44703EB41DEEB68CBD951EC5E54` |
| `C:/cmgcb-2dd4f3a4b1/artifacts.json` | `1A0D9CB6DA9087FEA4C21BB347F38961B8A03AC3C3861D351AB47E11F5396739` |
| `C:/cmgcb-2dd4f3a4b1/assurance-controls.json` | `7EE8AB5D0FD589E675FDA7F9C6046AACD16A4DCA25B2EDAF6127CC13C4661E2A` |
| `C:/cmgcb-2dd4f3a4b1-closing/results.json` | `B952DAF619BB107ABDBC203F65B542272AF515CA17F9A05951C64668B6FF71B9` |
| `C:/cmgcq-2dd4f3a4b1/guard-result.json` | `ABFB93ACA00694BBB69525D60AC758A90CCD94684E79E9BC2C6851E0743D24A8` |
| retained `driver.ps1` | `5E3FE74BECFAB24B746BEBBC7AA0EECA74CAF3D9616ED3088F7318330989BA2F` |
| retained `expected-source-metadata.json` | `6639473D1A981957AAF09A87DFE1CC8FE02A1B02B059BA6D9976B72640BA407D` |

The two retained files in the table are under `C:/cmgcq-2dd4f3a4b1`. Earlier
development FAILs and the incomplete v1/v2 scanner receipts remain distinct;
they are not upgraded to byte-coverage qualification. This standalone run is
not new QEMU/ARM execution, pinned-reference parity, the default combined
matrix, global all-optimization equivalence, hosted CI or hardware validation.
The separate basic-frame MPU pilot and its exclusions remain unchanged.

## CM4 MPU Lazy-Save Observer

Status: separate read-only O2/native/direct AN386 observations PASS on
2026-11-03. Four existing positive FP-pilot ELFs are copied byte-for-byte from
the explicitly supplied qualified pilot receipt. No production provider,
fixture C/assembly, protected frame, scheduler policy or frozen pilot/grid
file changes. No compilation, linking or reference firmware execution occurs.

`tools/test_classic_cm4_mpu_lazy_observer.ps1` captures its reader, planner,
checker, transport and supplied input identities before importing local code.
It independently admits the pilot's complete artifact inventory with the
captured maintained pilot checker, then requires the same twelve stable QEMU
identity files. ASLR-bearing diagnostic `ldd` text is not compared, but resolved
library hashes are. No tools are installed and no board is accessed.

The planner binds two unconditional decoded PendSV instruction boundaries:
`TST LR,#16` before the first high-FP VSTM and `TST r3,#1` at the post-copy
FPCCR guard, before the scheduler callback. It verifies all thirteen maintained
FP mechanism facts, actual strong vectors, exact private/storage cohorts,
three privileged workers, disjoint user stacks and the real SVC72 return PC.
These are bounded existing-code checks, not a new full FreeRTOS parity claim.

The collector uses only private AF_UNIX RSP and hardware-assisted `Z1/z1`
breakpoints, alternating pre/post stops. No software-breakpoint fallback,
single stepping, PC adjustment, register/memory writes or monitor commands are
allowed. Queries and reads are narrowly whitelisted before sending. TX/RX
framing/checksums are retained; the independent validator binds each event to
the actual register/memory replies rather than trusting an asserted read-only
flag. The approach follows QEMU's documented GDB/TCG breakpoint interface,
not a physical debug-timing guarantee. [QEMU GDB documentation](https://www.qemu.org/docs/master/system/gdb.html)

The successful `C:\cmlz-20261103-e3` run observes:

| Worker state | Pairs | Pre LSPACT | Post LSPACT |
| --- | ---: | ---: | ---: |
| FP-active, lazy | 30 | 1 | 0 |
| FP-active, eager | 30 | 0 | 0 |
| Basic, either policy | 28 | 0 | 0 |

The four Context/FiberV1 x eager/lazy images each produce 22 paired saves,
44 snapshots and the unchanged exact three-line terminal with exit 0. Total:
88 pairs, 176 snapshots and 6,080 framed packet records. Every pair preserves
current owner, PSP, EXC_RETURN and complete own-stack frame identity. Raw pre
r3 is the Handler-mode architectural CONTROL capture, value 1; pre r0 is
PSP+32, not PSP. Post r3 equals a fresh FPCCR read. XML-described PSP is read
directly; it is never inferred from r0 or silently substituted. Debugger CONTROL
is recorded separately, not treated as equivalent to the saved MRS value.
Pending FPCAR identifies PSP+32. The observed transition is bounded to the
FP-copy interval, not attributed to a particular instruction or exception-entry
instant. This interpretation follows Arm's lazy-preservation description.
[Arm AN298](https://documentation-service.arm.com/static/5f0352c0cafe527e86f5bc66?token=)

All four QEMU children exit and are reaped; their private sockets disappear.
Each trace closes 267 Linux input-role records, including actual Python/QEMU
executables, mapped libraries, loaded Python source/cache files and QEMU support
files. The run captures 77 files, closes 1,465 host inputs, 115 artifacts and
17 commands, with zero input/QEMU identity drift. Four original/captured ELF
hashes agree with the supplied pilot. Target-state writes and recompilation
remain zero.

Maintained synthetic controls remain separate from CPU observations: 48 parser
controls, four producer/validator compatibility controls using the actual
snapshot producer, 40 fake transport controls, and nine actual-image planner
controls per image. The original `C:\cmlz-20261103-e1` bootstrap FAIL is retained:
Store Python reported an activation alias via `sys.executable`. Enrollment now
uses `GetModuleFileNameW` to identify the actual loaded executable; no native
inspection or QEMU execution had occurred in the failed bootstrap.

Execution receipt SHA256:
`CE57E5E81BAEE75D41DA5758C5C70B9A96DC5176E80476DFBF5B103116964BCB`

Artifact manifest SHA256:
`54C6E1BE65AD47BD0FAF288BB1A0C2D219488FC78E51751D5F1798CEBF6F1162`

Capture manifest SHA256:
`914217864354ACE85C37DF29D12E234AB3339FE9EECF6DC6CACF4A52DC05D018`

Independent provenance review rehashes all 115 artifacts, all 77 original/copy
pairs and all 1,465 closing inputs twice. The 1,453 opening identities remain
unchanged; twelve generated disassembly/attribute/manifest inputs are added
explicitly after creation. All four ELF pairs and twelve stable QEMU identities
match, and all seventeen commands are compiler/archive/link-free.
Review report: `C:\cmlz-review-20261103\review-e3-b138c65a\checkpoint-report.json`, SHA256
`46F35085DC8640E8B4395CA10C96CBC4D366174495943B39293DF597AFC5B542`.

The earlier e2 observations also pass, but independent review found two future
admission gaps: RX wire bytes were optional, and a balanced simultaneous pair
of breakpoints could pass the validator. Neither occurred in the actual e2
traces. Both are now rejected explicitly; the producer also rejects a second
active breakpoint before transmitting it. The fresh e3 run captures that
hardening and the fixture README clarification, with the same immutable ELFs.
Independent packet review verifies all 6,080 frames, reproduces the 48+40
maintained controls and rejects 20 actual-trace counterfeits. Each former
counterfeit is rejected for all four images with its exact diagnostic.
Packet review: `C:\cmlz-review-20261103\e3-mw1a3blx-1198f87a\review.json`, SHA256
`585F37E94DEA3B4DA89890A820306C1D3D74D9123279385B20E8AD614651B7D6`.
These are parser/admission negatives, not newly executed CPU mutants. This
remains a captured-byte receipt, not an automatic exact-final-commit claim.

This is selected-byte evidence for four frozen pilot images, not all 32 FP-grid
images, strict low-FP/FPSCR self-selection, reference execution, whole-handler
equivalence, physical lazy-stacking timing, global all-optimization parity,
hosted CI, default aggregate update or STM32 hardware validation.
`CompleteSuite` remains false.

## CM4 MPU FP Grid

Status: separate bounded O2/Os, ordinary/final-LTO, direct/archive AN386
FP-active grid PASS on 2026-11-03. The published `e81f3f3` FP pilot, all 25
basic-grid files, production C/assembly and public ABI remain unchanged.

`tools/test_classic_cm4_mpu_fp_grid.ps1` closes these independently fixed keys:

- 32 positives: Context/FiberV1 x eager/lazy x O2/Os x ordinary/final LTO x
  direct/archive provider linkage.
- 20 causal backend controls: five mutations x eager/lazy for Context O2 native
  direct, and for FiberV1 Os final-LTO archive.
- Eight actual pinned FreeRTOS link-only final ELFs, one for each
  optimization/LTO/archive tuple, and one AN386 model probe.
- 32 same-configuration hash-bound reference associations: 96 maintained basic
  mechanism-check results plus the explicit FP-copy facts.

Fresh compile root `C:\cmfg-20261103-c2` closes as COMPILE-PREFLIGHT-PASS without
WSL/QEMU. Fresh execution root `C:\cmfg-20261103-e1` closes as FP-GRID-PASS with
all 53 observations: model, 32 positives and 20 exact expected FP mismatches.
All 61 final ELF hashes match between the compile and execution builds.
All positives observe post-save CONTROL mask `0x22` and LSPACT 0. Return PC and
complete frame checks use each image's actual symbols and include STKALIGN
padding rather than assuming the O2 pilot's addresses.

Archive variants package only the two actual selected-port provider objects,
use the enrolled explicit AR plugin, and verify exact members and genuine
extraction in the final map. Common, application and external cohort expectation
objects remain direct inputs. No whole-archive or forced-symbol extraction is
used. The reference archive similarly contains the actual pinned upstream port.

The first attempt, `C:\cmfg-20261103-c1`, remains FAIL: the frozen ordinary-only
pilot audit rejected legitimate final-LTO LOCAL binding of the common-private
current slot. The separate grid adapter applies the already-qualified basic
grid rule to only the three named common-private objects, only with exact
prelink common ownership and final STT_OBJECT/extent proof. Public functions,
strong exception handlers and cohort symbols still require GLOBAL binding.
This changes the test adapter, not runtime visibility or the qualified pilot.

The successful execution captures 216 selected input files, enrolls 1,811 inputs,
records 20 generated backend mutations and 4,084 artifacts, and closes with zero
input/QEMU identity drift. It runs 76 synthetic grid contract controls in
addition to the inherited 60 decoded and 64 pilot receipt controls. Synthetic
controls are not CPU observations. The captured independent PowerShell checker
requires exact keys, terminals, observed facts, reference tuples, canonical
model/61-ELF bindings and full artifact-byte closure before admission.

Execution receipt SHA256:
`D758117469244D5939A140866EC90EC44811D48E3FA3F6DC2956522C7B3F7B8A`

Execution artifact manifest SHA256:
`3D0088148AFB820A213E2084055489B4B179A2370EF9F882CBB2722CEB50EE38`

Execution capture manifest SHA256:
`0CB3D84D3650A69EA67111A07F4E53844663A4995B9998437D46243099ED1440`

Compile receipt SHA256:
`A56B480221BC6DA99281DAE456DE93DC0C6B077310518486494FA87AEC247A8E`

Independent compile/provenance review rehashed all 1,811 inputs, 20 generated
mutants, 216 captures and 3,950 compile artifacts. It checked 130 prelink
definitions across 52 subject images and all 70 final LOCAL private bindings:
each is LTO-only with the exact strong common prelink owner. Independent review
of the Os/LTO/archive representative also confirms byte-exact real provider
archive members, genuine extraction, and GLOBAL public/handler/cohort symbols.

Independent execution-receipt review verifies 53 outcomes, 61 ELFs, all 32
associations and 4,084 artifacts with zero rehash mismatches. It passes 115
full-checker negative controls and 24 AST-extracted association negatives.
Review report: `C:\cmfg-review-20261103\e1-2b4e9a1f\review-results.json`, SHA256
`3CEA1231F6334E15B36797DF1F429703E05EA97ACC334E583188CE93E8BF0F84`.
These controls do not constitute new target executions or reference runs.

This is selected-byte evidence, not an implicit exact-clean-Git claim.
`CompleteSuite` remains false; `RequestedInventoryComplete` describes only the
32/20/8 grid. No reference execution, whole-port equivalence, O0/Og/O3, MPU16,
softfp, other CPUs, STM32-specific NVIC-width manifests, hosted CI, default
aggregate update or hardware qualification is claimed. Strict low-FP/FPSCR
self-selection and pre-save lazy-state observation remain separate bounded
coverage items; the qualified application/probe/checker are not rewritten.

## CM4 MPU FP-Active Pilot

Status: separate opt-in O2/direct/non-LTO AN386 pilot PASS on 2026-11-03.
This changes test tooling only, not production providers, frame layout, public
API, exception assembly, or any of the 25 qualified basic-grid files.

`tools/test_classic_cm4_mpu_fp_pilot.ps1` captures selected source bytes before
import/build, reuses the basic fixture's pinned 26-file FreeRTOS inventory at
`a50edad08b29052631aa469d4df6e6ec7ff68878`, and requires a fresh external output
root. It does not depend on an old receipt, invoke Git, install tools, program a
board, or launch WSL in compile-only mode.

The successful compile-only root is `C:\cmfp-20261103-c4`; the independent fresh
execution root is `C:\cmfp-20261103-e1`. Both close the same literal inventory:

- Four production positives: Context/FiberV1 x eager/lazy FP, MPU8, hard-FP.
- Three privileged contexts with disjoint 4 KiB user stacks per positive:
  two distinct FP payloads and one GRO/FP-inactive worker.
- Ten compiled production-backend mutations, five under each FP policy.
- One model probe and one actual pinned, link-only FreeRTOS reference ELF.
- Four hash-bound reference associations, each with the maintained three
  basic mechanisms plus explicit decoded FP-copy ordering facts.

All 15 requested AN386 observations pass: model, four production positives and
ten expected FP mismatches. The latter require exit 66, worker 0, and these exact
reason/phase pairs, never a generic fault or timeout:

| Backend mutation | Reason | Phase |
| --- | --- | --- |
| Omit high save | 131 | 1 (public yield) |
| Omit high restore | 131 | 1 (public yield) |
| Omit low save | 134 | 2 (assembly envelope) |
| Omit low restore | 134 | 2 (assembly envelope) |
| Corrupt saved FPSCR | 132 | 2 (assembly envelope) |

The user assembly oracle checks R4-R11, active SP, cookies, Thread IPSR/CONTROL,
and FP data. It requires only ABI-preserved high FP across the genuine public C
yield, then re-seeds all S0-S31/FPSCR inside an assembly envelope around the
real naked SVC71 primitive. Unprivileged MRS PSP is deliberately not used as an
oracle; privileged save/restore code validates PSP and complete frame bounds.
The constructor-seeded task return reaches the real SVC72 panic path.

The dispatcher observes 23 selections, one self and 21 cross transitions,
eight/seven extended saves and seven basic saves. After protected capture it
poisons only the outgoing low16/FPSCR hardware-frame copy. This forces the
restore oracle to detect omitted reconstruction instead of trusting surviving
user-stack data. Core8 remains at PSP, low17 starts at PSP+32, and the reserved
word is untouched. Self-selection covers public/high-FP preservation here;
strict low/FPSCR self-restoration remains a separate coverage item.

All four positives observe post-save CONTROL mask `0x22` (raw Handler values
1 and 5), post-save LSPACT 0, return PC `0x0001042E`, PSP `0x20002F98` and xPSR
`0x21000000`. These are this pilot's observations, not universal addresses or
proof of pre-save LSPACT. The reference always-lazy policy and subject eager
policy intentionally differ. Decoded checks prove ordered named mechanisms,
not whole-handler equivalence; extra saved-FPSCR corruption retains mechanism
PASS and is rejected only by the runtime payload oracle.

Closing evidence includes 209 captured files, 1,797 enrolled inputs, ten generated
backend mutations, 1,036 artifacts, 16 native ARM ELFs and zero input drift.
Sixty synthetic decoded controls and 64 synthetic receipt controls run before
the builds; they are not target executions. An independent captured PowerShell
checker verifies exact terminals, observed values, canonical model/ELF bindings
and every artifact byte against the manifest before admitting the receipt.

Execution receipt SHA256:
`03F23D31C88B8ADB24C488872EB2B2E52D52B99CCAB51A4822BE28B7233F335C`

Execution artifact manifest SHA256:
`F3361FE79C8E5F540FFE1CDFA4A381EFCCA489C1F0712549E2D93DECBFF16A22`

Execution capture manifest SHA256:
`8D0A2CEB4F4FFD0B1B9FC43B429518F32C04A6FF2014181D23F2D6088C030E01`

Independent review rehashed all 1,036 artifacts, 16 ELF bindings and four
associations. Fifty-five in-memory PowerShell negatives, including malformed
terminals with matching mutated Observed facts, reject at the intended
terminal/causality guard rather than a later persisted-receipt mismatch.
Review report: `C:\cmfp-review-20261103\e1-6e72a441\review-results.json`, SHA256
`82FBA36E34FCB991D2A9327BD42C96D6A23151F42256D338D62F2891A7C15C6C`.
These are offline receipt-admission controls, not additional CPU executions.

Historical failures remain preserved: `c1` rejected decreasing RAM section order
under fatal linker warnings; `c2` rejected objdump's SVC operand annotation;
`c3` rejected the equivalent `ldmia sp!` spelling of POP. These are test/linker
and decoder failures, not executed target failures. Source review also removed
an invalid unprivileged MRS PSP comparison before the first QEMU execution.

`CompleteSuite` remains false and `RequestedInventoryComplete` applies only to
this pilot. This is fresh selected-byte evidence, not an exact-clean-Git claim.
It does not update the default aggregate, global parity, hosted CI or hardware
status. Os, final LTO, archive layouts, MPU16, softfp and other CPU profiles
remain separate. Broader FP coverage must use a separate grid rather than
rewriting either qualified fixture.

## CM4 MPU Basic Grid

The opt-in [maintained basic grid](tools/fixtures/classic_cm4_mpu_basic_grid/README.md)
is committed as `b2a7d17c7c54e3f1ae9a6f6919dfbc4482491f2b`. It adds 25 test
files, not production C, context layout, SVC/PendSV assembly or a new public API.
The earlier seven-image pilot and default combined matrix are unchanged.

### Bounded Execution

The exact no-overlay Git export contains 1,121 files. Before execution, its
inventory and every raw Git blob are independently rechecked. The maintained
wrapper then captures its selected source/dependency inputs before local helper
imports and uses a separate fresh build directory. All 49 requested observations
exit zero with exact terminals; the wrapper and outer launch both exit zero.
The outer run takes 211.42 seconds and detects no source or inventory drift.

The fixed profile is AN386 Cortex-M4, eight MPU regions, hard FPv4-SP-D16 ABI,
eager policy, FP-inactive/basic frames and hash/map policy 0/0. The observed model
reports CPUID `410FC240`, MPU_TYPE `00000800`, NVIC mask `000000FF`, MVFR0
`10110021` and initially disabled MPU. These are CPU-model facts, not STM32
device/NVIC-width or peripheral integration evidence.

The sixteen configurations are Context/FiberV1 x O2/Os x ordinary/final LTO x
direct/archive. Each executes three production cases:

- Normal switching retains r4-r11, exact SP and stack cookies across public and
  direct SVC71 yields. Each normal terminal records 32 scheduler selections,
  one self selection, 30 cross selections, 16 public and 15 direct transfers,
  GPR/SP success masks `0F` and cookie count `1E`. Task return reaches the
  constructor-installed SVC72 target and panic `R` in SVC, not an entry wrapper.
- An unprivileged current-slot write produces MemManage at the exact access PC
  decoded from each image, with MMFAR `20000000`, CFSR `82`, HFSR zero and
  EXC_RETURN `FFFFFFFD`.
- An unprivileged peer-stack read produces MemManage at its image-specific
  decoded access PC, with MMFAR `20004080` and the same fault class. LTO may
  change those PC addresses. Generic HardFault/timeout text is not accepted.

The model executes first, followed by all 48 production images. The final
receipt is `BASIC-GRID-PASS`, `Execution=BOUNDED_BASIC_GRID`, `CompileOnly=false`
and `CompleteSuite=true` only for this literal bounded inventory. It closes
1,775 enrolled inputs, 40 generated inputs and 6,720 artifacts with no drift.
Existing-prefix QEMU/tool/library manifests are checked before and after;
the run provisions nothing and touches no board or live CubeIDE build.

### Reference And Receipt Boundaries

Eight actual pinned `portable/GCC/ARM_CM4_MPU/port.c` final ELFs remain link-only.
The selected 26-file reference inventory pins FreeRTOS
`a50edad08b29052631aa469d4df6e6ec7ff68878`. Each production ELF has a hash-bound
reference association for the same optimization/LTO/archive key. The 48
associations check the maintained SVC-dispatch, first-restore and PendSV-MPU
mechanisms: 144 named mechanism-check results, not byte identity or whole-kernel
equivalence.
Upstream's always-lazy FP policy intentionally differs from this eager subject.
`ReferenceExecuted` and `NewFinalReferenceParity` both remain false.

All 32 subject and eight upstream compiled omissions are rejected by their
intended decoded diagnostic; they are not additional CPU executions. The 132
synthetic closing controls, ten actual-finalizer controls and 25 typed
PowerShell finalizer mutations remain separate from target observations.
The model's actual bytes, canonical path and manifest entry are bound before
success. Source/tool identities include the six GCC-resolved workers, native
nm/ar and explicit LTO plugin, not complete transitive host/OS closure.

The 97 final ELF role images preserve executable/data bytes and NOBITS geometry
against the earlier admitted compile-only v2 inputs. Only two trailing LF bytes
in each of `build.py` and `engine.py` were removed before the source commit;
that source-only bridge is not substituted for new compile or execution evidence.

| Execution Record | SHA-256 |
| --- | --- |
| `build/evidence/results.json` | `3A41B553B90E4D2DC55D3348A2454779EE4617D969228713ECD1A4BCAFAFF4F9` |
| `build/evidence/artifacts.json` | `2FA41490C0A98116E8D40C61DD653818889D20356A4BCFB9CAD71FDC055CA563` |
| `execution-result.json` | `F2E131088DDF4D5111368682C5F27ED60E8F3268E6C7B63C592CCD3A563BCBFC` |
| retained `driver.ps1` | `9414D7639DCE39B4A1C125F51C27092DC98679FDB9BAAD3D62D79BD37489B254` |

These records are under `C:/cmbge-b2a7d17-20261103-a2`; the immutable export is
under `C:/cmbgq-0b465e0c82/experiments/h7s_fiber_test/Boot/app_core/fiber`.
The earlier `a1` outer launch remains a pre-child FAIL: PowerShell 5 nested a
JSON array, so the source-count assertion stopped it before compilation or CPU
execution. Its receipt is not relabeled.

The first separate clean-commit compile-only child under
`C:/cmbgb-0b465e0c82/evidence` exits zero and passes, but its outer result under
`C:/cmbgq-0b465e0c82` remains FAIL. The TEMP outer adapter incorrectly expected
all 40 generated files to have one role. The fixed adapter requires the exact
predeclared 12/20/8 path/role split with uniqueness, containment and artifact
hashes, rather than learning allowed roles from child output. That fix changes
no maintained source or existing receipt; fresh qualification is separate.

A second fresh compile-only child under `C:/cmbgb-83856a744c/evidence` also
exits zero, but its outer result under `C:/cmbgq-83856a744c` remains FAIL: the
adapter treats the two-field retained control envelope as a raw closing report.
The corrected outer checker must bind both closing and finalizer reports.
Its fresh qualification is not part of the independently reviewed execution
claim above; neither failed outer result is promoted to PASS.

### Clean-Commit Compile Closure

A new full compile-only run, not a reevaluation of either failed outer run,
passes for the same exact `b2a7d17c7c54e3f1ae9a6f6919dfbc4482491f2b`.
Its no-overlay export is under
`C:/cmbgq-3ea2104f3e/experiments/h7s_fiber_test/Boot/app_core/fiber` and its
fresh outputs are under `C:/cmbgb-3ea2104f3e/evidence`. All 1,121 exported
paths and raw Git blobs match the commit, including all 25 reviewed test files.
The child and outer driver both exit zero after 214.00 seconds, with no source,
inventory, metadata/dependency or enrolled-tool drift. Opening and closing
source manifests are byte-identical.

The child remains `COMPILE-PREFLIGHT-PASS`, `Execution=NOT_RUN`,
`CompleteSuite=false`: 48 production ELFs, one model, eight link-only reference
ELFs and 40 compiled omissions give 97 final ARM ELFs. The outer closing checker
binds 1,775 inputs, 198 captured files, 6,594 artifacts, 48 associations and the
exact 132/10/25 control identities. It requires the predeclared 12/20/8
generated path/role split and both payloads in the exact two-field retained
control envelope. The TEMP adapter's 172 Python and 203 PowerShell causal
controls pass before this new launch; the earlier read-only development probe
is not substituted for the fresh run.

| Compile Record | SHA-256 |
| --- | --- |
| `C:/cmbgb-3ea2104f3e/evidence/results.json` | `1B1EEA13A7C05567F8926B76D7DBFC7666F2F9875F601E1366824799BD0C2D9F` |
| `C:/cmbgb-3ea2104f3e/evidence/artifacts.json` | `58F440311182BF411241F9D3BD4D4B5F195F8422013525DEED272708369E9445` |
| `C:/cmbgq-3ea2104f3e/grid-result.json` | `FBBC43B2D644F658B3215E46B7977A162434CB051FC61EF410EC295DC8477762` |
| retained `driver.ps1` | `BE8792D33DA7C878E0E9E749F15C503FA6C7BF66D9CB58F8D456685DCEC2B13F` |
| retained `expected-source-metadata.json` | `3DBA545AA414CD2994EB8BD757E4584538878090B99028CEFA96786BFAB7D085` |

The two retained files are under `C:/cmbgq-3ea2104f3e`. This separate receipt
closes the additional compile-only provenance checks, not new CPU execution.
The independently reviewed 49-observation execution receipt above remains the
execution evidence. Both old outer FAILs and the pre-child launch FAIL remain
unchanged. No production code, frame, handler, API or default-matrix dispatch
changes were needed to obtain either successful receipt.

This does not qualify FP-active/lazy MPU contexts, MPU16, softfp, ordinary
O0/Og/O3, CM0/CM3/CM7 MPU execution, the global all-optimization/final-LTO parity
gate, the default aggregate, hosted CI or STM32 hardware. Those remain explicit
backlog, not implied by the bounded `CompleteSuite` flag.

## Recorded Host Tool Identity Boundary

A later provenance review identifies an enrollment omission in the historical
classic 288/504-case FP receipts and relevant default-aggregate children:
gcc-nm/gcc-ar wrappers and the LTO plugin were recorded, but their delegated
native binutils executables were not identified under another enrolled role.
The aggregate's 916 external records describe FreeRTOS/CMSIS, not all host tools.
Recorded source/artifact hashes, wrapper/plugin identities and observed target
execution outcomes remain evidence; no wrong backend, symbol result, ELF or
runtime false PASS is demonstrated. Complete delegated-binutils identity and
unchangedness throughout those historical runs are not established. Later
capture cannot retrospectively supply that missing observation.

The native-only MPU pilot selects and hashes native nm explicitly. Its complete
compile-only preflight records 79 native-nm invocations and invokes neither
gcc-nm nor an archiver; the second failed CPU attempt stops after 13 nm
invocations among 50 total commands. Future LTO closure needs an explicitly
captured backend/plugin contract and semantic
symbol/archive-index controls, not just a subprocess exit code. That future
hardening is separate from the classic MPU CONTROL repair; no universal host/OS
dependency-closure claim is made here.

## Exact-Cohort Inventory and Coverage Plan

The 2026-11-04 inventory slice changes no production C, context/frame layout,
handler assembly, dispatcher or public ABI. `tools/freeze_cohorts.json` lists
27 canonical source groups with 77 C files and 141 explicit declared cohorts.
Four NS/Secure pairs yield 145 separately typed artifacts. The required plan
contains 725 object cells (O0/Og/O2/Os/O3) and 2,030 final cells (the same modes
plus O2-lto/Os-lto, each direct/archive): 2,755 keys, all initially `NOT_RUN`.
Secure companions do not acquire a fictitious forward-eight/reverse-v1 runtime.
The runtime and common proof obligations retain the real directional ABI,
current-slot, handler, vector, exact-cohort and negative-link requirements.

This is not an exhaustive admitted-vector inventory or a new global parity
receipt. Twenty-three Pending and three ReferenceOnly backlog entries preserve
missing feature tuples and reconciliation work. Compiler admission, source
runtime selectability and scope are distinct facts; staged headers remain
non-selectable. M23's reserved PSPLIM format word does not imply an accessible
Non-secure PSPLIM register, and companion BASEPRI zero means not-applicable.

The standard-library CLI uses the full canonical runtime-source reader and
captures all six source roles. Duplicate identities ignore independent option
ordering and metadata-only policy assertions. Known policy, FP-lazy, R9,
BASEPRI and MPU-region defines are checked against the declared tuple.
Coverage accounting recomputes the complete expected plan from the manifest;
empty/truncated replacement plans, mixed snapshots, wrong cohorts, duplicates
and unexecuted statuses cannot satisfy its key checks. Even complete synthetic
accounting remains `KEY_ACCOUNTING_NOT_CPU_PROOF`, not a processor verdict.

Fresh `C:/fzin-20261104-e5` returns `INVENTORY-PLAN-PASS`, with 339 captured
inputs, 369 artifacts, zero closing drift and 28 read-only Git commands.
All 26 declared upstream C-source bindings match the pinned LF Git blobs after
the explicitly permitted whole-file LF-to-CRLF checkout expansion; both raw
hashes and blobs are retained. This is not header/compiler dependency closure.
No ARM compiler, archiver, linker, emulator or board executed in this slice.
The first `e1` FAIL (raw CRLF-versus-blob mismatch) and the earlier `e2`
inventory-only PASS remain separate, unchanged receipts. The later e3/e4
snapshots also remain separate; e4 captures the runtime manifest before provider
selection and rejects C octal/invalid leading-zero define spellings. E5 repeats
that version after removing an extra trailing blank line from the input JSON;
the parsed inventory and required-cell plan are unchanged. Later prose records
the captured e5 snapshot; it does not make that run exact-commit CI evidence.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzin-20261104-e5/results.json` | `F35FDD7211F7FA3D00113C04442AA9E6754343FAF08D07FF0E4465B4F1986088` |
| `C:/fzin-20261104-e5/artifacts.json` | `C1BA370F46DD29F3172E22945008E5B9A585365E909C903F11FBA25AE2D1A82C` |
| `C:/fzin-20261104-e5/capture.json` | `2EF12C0F38D6C2EA0884E466D5F6FB3BAE6493FE62F27A788AB415ECDDC9AF50` |
| `tools/freeze_cohorts.json` input | `A988CD5D7A2BFA197E43950AB42A1E09CAD6BF5AE2A585165E676F76C904B689` |
| Pure control results | `6F1CC749A8EB3FE753D6A722F8B6281681C07C38B8F089C0360EF0F488309F6D` |

The separately retained pure run is at
`%TEMP%/freeze-inventory-controls-20261104-e2/results.json`: 128 controls
(31 positive and 97 expected rejections) pass, with no compiler/CPU execution.
Its final test-source SHA-256 is
`F50CA2F8A50507A43E266B17CA5CACFA0997B5FDB65BC070E194C7913961BBE2`.
These parser/accounting controls cannot validate asserted CPU-proof hash bytes.
The default combined matrix, global optimization/final-LTO parity, staged
profile admission, hosted CI and hardware evidence are unchanged and pending.

## Exact-Cohort Native Compile Preflight

The next 2026-11-04 slice adds `tools/freeze_compile.py` and pure fixture/recipe
controls, without production C, assembly, frame or API changes. It reuses the
maintained sensitive-closure dependency compiler, native ELF parser and
relocatable lowering, but not that runner's default tuples or fixed device
header. Each artifact supplies its own CPU/FPU/ABI, policy defines and CMSIS
fixture facts. Source inventory and the complete expected plan are verified
before ARM-tool queries; generated fixtures, compiler dependencies, seven
resolved workers, commands and object bytes are retained and checked at close.

`C:/fzcn-20261104-e2` returns `COMPILE-PREFLIGHT-PASS` for all 725 native cells
in the current finite inventory: 141 cohorts, four NS/Secure pairs, 145
artifacts and O0/Og/O2/Os/O3. This covers 25 runtime source groups and two
companion groups, yielding 2,085 individual source objects and 725 native
relocatable groups. There are 6,355 recorded tool commands, 1,011 compiler
input records, 13,769 artifact entries and zero closing drift. Seventy-five
diagnostics are the bounded no-VTOR fallback warning, not ignored compile
errors. The source inventory receipt is `C:/fzin-20261104-e6`.

Independent read-only review reconstructs the exact 725 keys and source-flag
recipes, verifies all artifact hashes and inputs, and checks all ARM objects
are native ET_REL without LTO IR. The earlier one-cohort CM4 e1 pilot is a
separate retained result (five groups/15 objects/55 commands), not a substitute
for this full declared-inventory run. The final receipt-scope guard rejects
claims of CPU proof, nonzero/boolean execution counts, errors and input drift;
its synthetic tests use generated one-CM4 receipts, not fake real-port evidence.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzcn-20261104-e2/results.json` | `6837B300938706A3CD3856AEBD61D8B954FBC2E9F0B1D79A45B7815469CA3FD6` |
| `C:/fzcn-20261104-e2/artifacts.json` | `47E5981E3D706EB4F5D9EECC85EEBCC82AEBDF8088CE2E13C19FF4B5C8978B85` |
| `C:/fzcn-20261104-e2/inputs.json` | `9C96F4223FCD1BA2DBD85AD8AB3595532A647B83CEC41FF627940FB367B50B36` |
| `C:/fzin-20261104-e6/results.json` | `D10456BC853DB9362E973BED9D973606A587CDBFDED009A8ABAC54707B428606` |
| `C:/fzcn-review-20261104/e2-audit.json` | `B03B12492C0FB7F46D89364FAA2CA04F5D8E19E6C8D1B88CB054D89264E16271` |
| Pure receipt controls | `C9CFFC873410F6B95C1075DEADC89AE6990736E6A329B8C313E5ECECA2088684` |
| Pure recipe controls | `D977FBE1FD82072D58316C885478E4E53B394C8438CB7AD29E9D0FDADA24AC68` |

The two pure results are under `%TEMP%/freeze-native-pure-20261104-e1`:
40 receipt controls (3 positive/37 negative) and 53 recipe controls
(20 positive/33 negative) pass without compiler/process execution. The exact
native compiler-input fingerprint is
`4F2756F29A5D5502E510E41245EACA5B9D7E798802425D7C272E882273E85DFA`.
The captured CLI SHA-256 is
`D83A794C9357EBAA041332316F3915E391350090058AEB4B8106A15D30977D89`.

This proves native compile admission for the declared inputs, not FreeRTOS
instruction/mechanism equivalence or every possible admitted tuple. There are
zero final executable links and no CPU/board executions. No upstream source
is compiled by this new adapter. Every row keeps `RequiredCellSatisfied=false`,
`GeneratedAssemblyParity=false` and `FinalElfProof=false`; global qualification
and the 2,030 final-mode/direct/archive coverage keys remain unclosed. Host
executables and resolved workers are captured, not all transitive host/OS
dependencies. Staged profiles stay non-selectable, no CI workflow is added,
and the default combined matrix is not rerun or promoted by this result.

### Reference Recipe Reconciliation

Source-only review of the exact upstream lists finds 264 translation-unit
instances per mode: 1,320 planned reference compilations across the same 725
artifact/mode keys, not executed successes. Before that separate adapter can
claim paired evidence it must resolve the following explicit prerequisites:

- Seventeen TF-M artifacts (85 mode cells) need a pinned real provider for
  `os_wrapper/mutex.h` and its transitive headers. The upstream adapter names
  TF-M tag `TF-Mv2.0.0`. Do not replace the missing interface with a stub.
- Seven soft-ABI artifacts map to CM4F/CM7 reference sources that require
  `__ARM_FP`. Keep the Fiber soft/no-FP cohorts; do not fake compiler macros or
  silently change their ABI. Select and justify a separate reference witness
  where necessary, rather than claiming an identical compile recipe.
- Seventy eager-FP artifact policies need explicit FPCCR difference rationale:
  the pinned enabled-FP reference paths set ASPEN/LSPEN for lazy preservation.
  The twelve lazy artifacts meet only that bit-policy prerequisite, not parity.
- All four companions declare three Fiber contexts, while their current
  upstream define maps omit `secureconfigMAX_SECURE_CONTEXTS` and fall back to
  eight. A reviewed reference binding must reconcile the budget before claiming
  matching pool/lifecycle evidence. The existing maintained parity driver
  explicitly uses three; the inventory is not yet a complete reference recipe.

These categories overlap and are not failures in the measured native run.
Mainline reference priority adapters must bind the already shifted BASEPRI
value, rather than retaining the old fixture's unconditional 128 or shifting
again. Baseline PRIMASK profiles and companion-only artifacts must retain an
explicit not-applicable threshold policy. Reference includes must select one
portmacro provider; a union of every port include directory is not acceptable.

## Exact-Cohort Reference Compile Preflight

The separate `tools/freeze_reference_compile.py` adapter builds the manifest's
pinned FreeRTOS translation units, without modifying upstream or production
Fiber/Context code. Each recipe selects one actual `portmacro.h` provider;
compiler dependencies must confirm that provider and the generated config.
The pinned companion `secure_init.c` intentionally has no config dependency.
Both reference priority macros receive the already shifted manifest BASEPRI,
and all four companion artifacts explicitly bind the context count to three.

The TF-M adapter uses unchanged official headers from `TF-Mv2.0.0`, peeled
commit `9ca8a5eb3c85eecee1303dffa262800ea0385584`, with the original BSD-3-Clause
license under `tools/fixtures/freeze_cohorts/tfm_v2`. Hardcoded content hashes
and actual dependency paths reject synthetic or shadow providers. This is a
compile-only interface fixture, not a TF-M Secure image or integration proof.
Every discovered FreeRTOS source/header is also compared with the pinned Git
blob, permitting only explicit whole-file LF-to-CRLF checkout expansion.

The retained e3/e4 runs each pass 725 reference cells at O0/Og/O2/Os/O3:
1,320 source objects and 725 native ARM relocatable groups, 4,895 commands,
1,555 input bindings, 11,319 artifact entries and zero closing drift. There
are 690 unchanged-target-flag recipes and 35 explicitly limited softfp
witnesses. Seventy eager-FP artifacts retain an explicit FPCCR difference;
neither unchanged compiler flags nor compilation proves equivalent policy.
No final executable, LTO or CPU run occurs and required parity cells remain
zero. The e1 harness failure (config expected for config-free secure_init.c)
and successful ten-cell e2 pilot remain separate, unchanged records.

| Retained E4 Record | SHA-256 |
| --- | --- |
| `C:/fzrc-20261104-e4/results.json` | `8924C96B528748D4CFDC4C13DA5AFEF5A1D578A695A1A045B4141A8D067D4D7A` |
| `C:/fzrc-20261104-e4/artifacts.json` | `5ECE0ACEACC0F1B3CA0FA5F64DD420590084CD4431A9E3C8EADD62AEB7749752` |
| `C:/fzrc-20261104-e4/inputs.json` | `2457E440A30FC119407B9FDF3D8AA3620DF29B58A47F9A1AD4290D5D8DC2B868` |

Independent e3 review checks all artifact hashes, exact cell keys, native
objects, command grammar, dependencies and 66 pinned FreeRTOS files. It binds
the captured e3 runner, not the later e4 escape guard or subsequent tooling
repairs. Pure controls separately exercise 248 recipe cases and 39 reference
adapter cases, without compiler, Git or CPU execution.

Subsequent review found three native-preflight tooling defects: a resealed
receipt could omit a header capture row, a relative CMSIS path was not
canonicalized before changing compiler cwd, and timeout attempts were not
logged or guaranteed to clean up descendants. Their repair must receive fresh
controls and compiler receipts; the older e2 native/e3-e4 reference snapshots
are not relabelled as evidence for changed runners. Root-level public headers
are additionally enrolled in new inventory captures. Runtime C/assembly and
hardware claims remain unchanged. Global mechanism/final-LTO parity, hosted
CI, staged-profile activation and board qualification are still pending.

### Repaired-Runner Paired Qualification

Fresh inventory `C:/fzin-20261104-e8` and native/reference runs
`C:/fzcn-20261104-e4` / `C:/fzrc-20261104-e5` close successfully after the
three tooling repairs above. Both compiler runs bind the same source-inventory
fingerprint, `E99DFC023B9F11F19A6109E37338E81DBE37574B8831B99244378A21D52179A3`,
and all 725 declared artifact/mode keys. The native run retains 2,085 source
objects, 725 groups, 6,355 commands, 1,014 input bindings and 13,772 artifacts.
The reference run retains 1,320 source objects, 725 groups, 4,895 commands,
1,558 input bindings and 11,322 artifacts. Both close with zero input drift,
zero final executable links and zero required parity cells satisfied.

The repaired input verifier recomputes complete capture membership, including
root-level public headers, rather than accepting a resealed subset. The native
run deliberately uses a relative CMSIS path, resolved before compiler cwd
changes. Tool commands are recorded before execution and on failure/timeout;
managed processes use a Windows Job assigned before the suspended primary
thread resumes. Timeout and abnormal descendant cleanup fail closed. This is
bounded process containment, not a complete host/OS dependency-closure claim.

The separate pure controls pass: 65 native receipt/path cases, 39 reference
adapter cases, 248 reference recipe cases and 12 command-record cases. The
18 process-runner controls include five actual Python-only process cases;
they exercise binary output, nonzero exit, timeout/descendant cleanup, orphan
rejection and resume-failure containment without executing ARM, Git or a board.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzin-20261104-e8/results.json` | `35642CD737ADBE9186065DCBBF1762673E137B68935413A7120A0C113819D141` |
| `C:/fzcn-20261104-e4/results.json` | `E6A401727808D2D3FC353B707E95FDC9FD7933593ACD4D06CEC592C0D2F7E2E0` |
| `C:/fzcn-20261104-e4/artifacts.json` | `199068E8880FABB612233FA393CEF3A97A2BC5CC1DCBE4456CC08B8387A6548F` |
| `C:/fzcn-20261104-e4/inputs.json` | `D598D3E7109389EC035FE115596C99696A114A37B47D030A108C8B2A1D6B183E` |
| `C:/fzrc-20261104-e5/results.json` | `690032B130C5B5E25880ECDA64D00109FCC154BFBAAFADEE82153FF0BF0594B9` |
| `C:/fzrc-20261104-e5/artifacts.json` | `246BC05B768CEF85115FBD2667688062B3E2816CB99F6604EB4D61AFA1DC094E` |
| `C:/fzrc-20261104-e5/inputs.json` | `20DB71F4E5B388A820C104AE30885A59F58A09C1A514BBEA09CEAAF19CEC8947` |
| Python process controls | `0632E4B4EA19ABD27DFFA1B5B94DA964A7418B57D26551EC05E3F470B42FA921` |

The four pure JSON outputs are under
`%TEMP%/freeze-reference-pure-20261104-e2`; process controls are under
`%TEMP%/freeze-process-parent-20261104-e1`. These are new receipts for changed
tooling, not replacements for historical failures or earlier successful runs.
The captured runner bytes were published in `8a5f199`; later receipt prose does
not retrospectively make the captured snapshot exact-commit hosted CI.

Compilation alone still proves neither mechanism equivalence nor a global
freeze. The 35 softfp witness cells, eager/lazy policy differences and separate
Secure/TF-M integration obligations remain explicit. All 2,755 required parity
keys, including 2,030 final direct/archive/LTO keys, remain unqualified by these
preflights. Complete-body mechanism comparisons and their negative controls
are the next independent layer; runtime, staged admission, CI and hardware
claims remain unchanged.

Independent paired review at `C:/fzpair-review-20261104-e1` verifies every
artifact/input binding, the identical 725-key sets, command/dependency recipes,
all native ARM ET_REL objects and all 66 pinned upstream file bindings. It
finds no mismatches or current-original drift at its own audit snapshot and no
confirmed Windows process-containment blocker. That drift statement is not a
promise about subsequent edits. Retained `paired-audit.json` SHA-256 is
`E909FB44DAA84EB697816F234B493FFB03C1BE4DFD2CD94231E0C5E155030F14`;
`PAIR_REVIEW.md` is
`99E0480F00FD37ABACA95F20B09BE2610F5E3928325DCD8F728868F6827F6AAA`.
This independent audit adds no instruction/mechanism or CPU-execution claim.

## Captured CM3 Closed-Root Mechanisms

`tools/freeze_cm3_mechanisms.py` consumes the closed e8/e4/e5 inventory/native/
reference receipts above. It compiles nothing and invokes neither objdump nor
a CPU. The bounded cohort is CM3 soft/no-FP, VTOR1, priority width four and
BASEPRI16, ordinary AAPCS. All five modes O0/Og/O2/Os/O3 must be present.
The driver checks complete artifact membership/hashes, captured compiler/source
bindings, exact cohort identity and result scope before reading native groups.
It executes the captured checker/decoder bytes, rejects reader/input/output
drift, and cannot accept a partial or proof-promoting checker result.

`C:/fzcm3-20261104-e3` returns `CM3-MECHANISMS-PASS`: five paired cells,
three complete roots per side, 30 closed bodies. The independently described
protocols match every returned instruction, local branch target, external call,
literal-island descriptor and padding NOP. The driver requires one post-island
NOP per root at O0 and zero at the other four modes, not either layout at any
optimization. Six existing rationale IDs cover startup, provenance, mask
restoration, scheduler ownership, EXC_RETURN and local pool adaptations.
Constructor/C-helper semantics, whole-object ABI/ownership, final executable
vectors, direct/archive/LTO links and CPU behavior are not established here.
Every required global coverage cell remains unsatisfied by this bounded proof.

The canonical reader's literal-island representation is explicitly opt-in.
Its default behavior is independently compared on three roots per runtime
group across all 725 native and 725 reference groups: 4,230 equal outcomes,
3,668 complete token lists and 562 identical rejections. Forty companion
groups are typed skips, not unperformed scheduler-root tests. This default
regression binds all 2,900 consumed ELF/disassembly files and finds zero
differences. It is not a new mechanism or opt-in decoder qualification.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzcm3-20261104-e3/results.json` | `7F9CF0FAA844B972179E3B67EA1FB48C57A6BCCE283E420782A46CDC006FF54D` |
| `C:/fzcm3-20261104-e3/artifacts.json` | `E3FBA26DFE7933A6F218BA59D8F39B6915063BE713B35D05CE11082E1F095D49` |
| `C:/fzcm3-20261104-e3/readers.json` | `12805BEE1E8C46D4F74D30D635CA3929C3D6F148F97B342EEDE0C7174DCFBEA3` |
| Default-reader regression results | `F5D30344F23C2015F4F10736D1C67912739424344AA79F6F3BED4A1577A95322` |
| Default-reader full outcomes | `0EE26E8DEC2B3F82D244F9FC0A236F48FA04CFC4A08BA79624D4328D6DAE2E0F` |

The regression directory is `C:/fzreader-review-20261104-e1/receipt`.
The earlier e1/e2 mechanism receipts remain separate; e2 adds the driver's
exact code-generation attribute guard and e3 captures the later ledger prose.
Receipt/join/scope pure
controls pass 86 cases at `%TEMP%/cm3-receipt-controls-20261104-e6.json`, without
compilation or CPU execution. These results remain captured-source evidence,
not exact-commit CI. Production C/assembly, public ABI, default matrix,
staged-profile admission and hardware claims are unchanged.

The new matcher additionally passes 13 unit/retained-ELF tests: 221 pure token
mutations, eight private byte/disassembly mutations and the five actual pairs
again. Mutations reject changed referenced data, branch-to-tail, an altered
operation, non-NOP tail, wrong literal relocation, unconsumed relocation,
disassembly/ELF disagreement and changed call addend with their expected
diagnostics. Original receipts remain unchanged. The test invokes no compiler
or CPU; mutated ELFs are parsed, never executed. The separate exhaustive
token-delete/change and synthetic function-decoder controls pass 905 cases.
Those synthetic decoder states do not exercise the ELF constructor and are
not represented as additional real-object tests.

| Control Record Under `%TEMP%` | SHA-256 |
| --- | --- |
| `cm3-receipt-controls-20261104-e6.json` | `D075D67E09CC5D9F8FC3F8B5FB3C857B46088A5282D8FD6A28E97F26D8315AB8` |
| `cm3-actual-mutation-parent-20261104-e1/results.json` | `5789E2453692F119528084BCF0B7CEA3ADCE60E271F3C4C01EB2CF57DE77D1B3` |
| `cm3-protocol-controls-20261104-e1.json` | `977F4A42DA6CB119E4E12B47D69BB62F18C9B0D78CD3FB1A53DE7C5C2A649449` |

## CM0 MPU Two-Bit Priority Cohort

The next inventory-only change adds one Pending CM0+/MPU8/VTOR1 cohort with
two NVIC priority bits, BASEPRI not applicable and ordinary AAPCS. Existing
CM0 non-MPU p2 rows already cover that declared axis; their evidence did not
cover this protected context layout. The selected MPU header already admits
this tuple. No port implementation, CPU mechanism, selection literal or public
API is changed. This is a target-bound G0-oriented fixture, not a claim that
every G0 device has these MPU/VTOR facts or that a board was qualified.

The finite plan now has 142 cohorts, four NS/Secure pairs, 146 artifacts,
730 object-mode keys and 2,044 final-mode keys: 2,774 required keys total.
The old 141-cohort/725-cell receipts remain unchanged historical snapshots.
They are not combined with this partial run to claim one current 730-cell
qualified snapshot. Scope stays Pending despite compiler admission and the
unchanged header's runtime-selectable literal; complete parity is still open.

Fresh `C:/fzin-20261104-e9` returns `INVENTORY-PLAN-PASS`. The selected cohort
passes all five native and five reference modes at O0/Og/O2/Os/O3 using that
same source fingerprint,
`69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313`.
Each side produces ten source objects and five native relocatable groups;
native/reference record 45/61 commands, respectively, and zero closing drift.
The generated native header explicitly binds NVIC bits 2, VTOR 1 and MPU 1;
all five reference cells retain exact target recipes, not softfp witnesses.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzin-20261104-e9/results.json` | `1910B53001FD37DF4B6DC57805EE49E4381B2529E1E3ECB47FDB312EB43A4DFC` |
| `C:/fzcn-cm0mpu-p2-20261104-e1/results.json` | `77913D948B911210CCFA509CD4B396C50A93A7AF5C467A092E2C44BDD6BBD24B` |
| `C:/fzcn-cm0mpu-p2-20261104-e1/artifacts.json` | `82E0B352BB1C63100F74A00AF0E20461E9ABC9B921F4CACC3E08F016DBE552A6` |
| `C:/fzrc-cm0mpu-p2-20261104-e1/results.json` | `DE761547CC6BCE7FD9D11F936B5AFF0669B6C9D4E214B372A1D042D067B86530` |
| `C:/fzrc-cm0mpu-p2-20261104-e1/artifacts.json` | `182F96B6FE534E62D9148795412025F98A8AB9D66F6F6541AC6D5F7656A63813` |

The separate `%TEMP%/freeze-p2-pure-20261104-e1` run repeats 128 inventory,
65 native receipt, 39 reference receipt and 248 reference recipe controls,
all passing without compiler/CPU execution. The two actual compile preflights
satisfy zero required parity keys and perform no final executable links, LTO,
CPU or board execution. Later receipt prose makes this captured-source
evidence, not exact-commit CI. The default matrix and hardware claims are
unchanged. No VTOR0/fixed-R9 or additional M23 tuple is silently added.

Independent bounded review finds no concrete blocker in the new manifest row,
selected 5+5 cell identities, target headers, dependencies or C-source binding;
all 30 source-object/group hashes agree. Its verdict applies to captured e9
inputs, not subsequent live-document identity, and adds no parity/CPU claim.

## Captured CM4 And CM7 Closed FP Roots

`tools/freeze_classic_fp_mechanisms.py` reuses the closed e8/e4/e5 inventory,
native and reference bundles, rather than merging the later CM0/MPU partial
compile into a new global receipt. Exact CM4 and CM7 hard/eager, no-MPU,
ordinary-AAPCS, VTOR1, p4/b16 cohorts each pass O0/Og/O2/Os/O3. The driver
requires every declared target fact and exact compile flags; its admission
guard rejects a p5 target retaining a p4 name, boolean/integer aliases and
other mismatched target facts. Independent review found this missing p4 guard
before publication; the repair changes tooling only, not production behavior.

Each profile closes the native/reference first-start, SVC and PendSV roots:
five paired cells, six complete bodies per cell, 30 bodies and 15 mechanism
comparisons. The complete protocol consumes every instruction, local branch,
FP predicate/register transfer, stack extent, mask operation, call/literal
relocation, literal island and padding NOP. Reference recipes retain their
threshold binding and eager/lazy differences. The native CM7 PRIMASK-preserving
BASEPRI sequences retain r12 scratch explicitly. Source-to-protocol review
finds no remaining confirmed blocker in these bounded rules.

The final e2 receipts below capture the completed checker, driver and ledger.
The earlier e1 runs are retained separately, not relabelled. Their results
remain captured-source proof, not exact-commit hosted CI. No compiler or CPU
is invoked by this comparison driver.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzcm4-20261104-e2/results.json` | `3BA212B5B3A7D8F618187EBDDD801F8DA9747DBC8AFEFA8D62E2348B8EF6E878` |
| `C:/fzcm4-20261104-e2/artifacts.json` | `C9214C5C4F78E3F4A47BDBD0AB45962AD16BF8C3DF8FFB952DC620FD74D16E47` |
| `C:/fzcm7-20261104-e2/results.json` | `BFB0F59C0046D244A11933125C157B08F942B73CBB03046DF2539452EA54E954` |
| `C:/fzcm7-20261104-e2/artifacts.json` | `3412C950FD495B2FA1074C09E78C60D68AAF474003419B9EB8CCF17DA1054A5F` |
| Both e2 `readers.json` files | `09321C1F5EA8838B6BCAA395A3D06309E10FC85DC0CF4D8AB11D6EA97726E79A` |

The parent-run retained-ELF suite passes 18 tests, 529 pure token mutations,
29 actual byte/disassembly mutations and all ten original pairs/60 bodies.
Changed bit-4 predicates, S16-S31 sets, FP frame extents, BASEPRI snapshots,
CM7 PRIMASK operands, literal/call relocations and extra instructions fail.
Original receipts rehash without drift; mutated objects are never executed.
The outer driver's 118 pure controls pass, including 14 positives and 104
negative admission/result/attribute cases. Neither suite invokes a compiler
or target CPU. Their separate records under system TEMP are:

| Control Record | SHA-256 |
| --- | --- |
| `classic-fp-negative-parent-20261104-e1/results.json` | `F088E2D7641961E41EAFB636FDCD64197989C166F9CEF2EE79E92D001E018EA9` |
| `classic-fp-driver-controls-20261104-e2.json` | `8338F57CA83B8B5F79409F6F652FEC67E41B75030AEDB36267E86EB1F8D36B24` |

The shared CM3 receipt join accepts explicit cohort/source-group arguments;
its defaults remain CM3. Replayed `C:/fzcm3-20261104-e4` again closes all
five CM3 pairs. Its result hash equals the earlier e3 result
`7F9CF0FAA844B972179E3B67EA1FB48C57A6BCCE283E420782A46CDC006FF54D`;
its changed captured-reader artifact manifest is
`EDD0E65DB2FAB8B475805DBC8C0FA2FE3CCCFE1BCE9FD7672305C903E17BC60E`.
The expanded 96 join/scope controls pass at
`%TEMP%/cm3-receipt-controls-20261104-e8.json`, SHA-256
`C7880A76537995BE0E9D79AD6FF6010F26F8D6E30C4AC225B2527CAEFE0EED4E`.

These roots do not close C-callee/constructor semantics, whole-object ABI,
vector routing, SVC nonreturn, final executable direct/archive/LTO links or
CPU/board behavior. Native eager FPCCR versus the reference's ASPEN=1/LSPEN=1
is explicitly `UNRESOLVED-BY-THREE-ROOTS`; policy equivalence is false. All
required global cells remain unsatisfied by this bounded gate. Default matrix,
runtime C/assembly, profile promotion, CI and hardware claims are unchanged.

## Captured CM0/M0+ Eight-Root Protocols

`tools/freeze_cm0_mechanisms.py` closes the three declared non-MPU p2,
soft/no-FP ordinary-AAPCS cohorts: M0/VTOR0, M0+/VTOR0 and M0+/VTOR1.
Each requires O0/Og/O2/Os/O3 against the same closed e8/e4/e5 inventory,
native and reference snapshots used above. The later CM0/MPU p2 partial
compile is not merged into these old snapshots or used as non-MPU proof.
These are F0/G0-oriented architecture tuples, not physical board claims.

All 15 paired rows pass: 120 complete bodies and 45 mechanism comparisons.
Three native roots cover first request, SVC and PendSV. Five actual pinned
reference roots additionally close its `vPortSVCHandler_C` dispatcher and
`vRestoreContextOfFirstTask` helper. The C helper's three emitted mode layouts
retain their complete prologues, PC+24/byte-PC-2/SVC100 dispatch, call relocation,
assertion loop, epilogue and padding. The native SVC70, full staged-register
restore versus reference first-restore GPR skip, validation and preserved
PRIMASK remain explicit differences; neither register-value equivalence nor
actual SVC routing/nonreturn is inferred.

The new `closed_roots.py` does not replace the existing CM0 final-ELF
`check.py`/`run.py`. The driver validates every declared target fact and exact
compiler flags, Thumb-1 attributes, complete receipt membership, captured
source/compiler bindings, reader bytes and closing inputs/outputs. An early
pure-driver admission failure expected `fpu_unit="none"` where the manifest
uses the empty string. It was corrected before actual receipt comparison;
the failing e1 pure output remains separate from later passes.

The exact Thumb-1 `46c0` tail admission is an additional explicit reader option
requiring literal-island opt-in. It retains tokens/counts and makes no CFG or
unreachability claim. Parent-run decoder controls pass 33 cases; all 90 selected
roots decode and 180 pre-existing API comparisons remain unchanged. Independent
source review finds no confirmed reader blocker. A separate default-API replay
over all 725 native and 725 reference groups again finds 4,230 equal outcomes:
3,668 complete token lists and 562 identical rejections, with 40 typed companion
skips. All 2,900 consumed ELF/disassembly files rehash without drift.

The parent-run closed-protocol suite passes 26 tests, including 1,409 token
mutation cases, 80 structural controls and 20 private retained-byte mutations.
It repeats all 15 successful pairs/120 bodies. Source/frame/mask/dispatch,
literal/relocation, branch, tail and byte-binding changes fail with expected
diagnostics. Original inputs remain unchanged and no mutated object executes.
The outer driver's expanded 253 pure admission/result controls pass. No
compiler, objdump, CPU or board is invoked by these new gates.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzcm0-20261104-e2/results.json` | `F4FF47203438DDCC8D43789D066D5C63EA4031F47F02649857F758F28FBF49E7` |
| `C:/fzcm0-20261104-e2/artifacts.json` | `38A32305D5EE7A283733134846E3B77383104B143D2E8A82927AB3A3641A9D0C` |
| `C:/fzcm0-20261104-e2/readers.json` | `88E3E95CD1C32ED7C09DAB418891BC79669A39E4BB326FA82E5E72130C86C720` |
| `%TEMP%/cm0-closed-negative-parent-20261104-e1/results.json` | `FF0CCECDCA083A205E91491CF36D3515788C09EE2F3B695D26CD556BC52BB68E` |
| `%TEMP%/cm0-driver-controls-20261104-e3.json` | `9D34A69BE3B68935453D170F81CDA95F7874513B98147BC467B993431505A3C8` |
| `%TEMP%/freeze-cm0-decoder-parent-20261104-e1/results.json` | `CC14FF0D2F1B38BD8F6B683D32BBDC54D30484630EBC1298740C3708103218D0` |
| `C:/fzreader-review-20261104-e2/results.json` | `33894DEAB71E9ED71AC39CD1A3B7D325FFF1C53397A39E7969888F48F5605C7D` |
| `C:/fzreader-review-20261104-e2/artifacts.json` | `5D6E89FA5F6BB7F4A568B3920514DF8A8D27772692B271D9679E198FAB5A5DDB` |

The reference/non-MPU protocol source review and the e1/e2 positive comparisons
are independent of the mutation-control generation. The new reader also passes
the existing 905 CM3 pure controls, 13 CM3 retained tests (221 token/eight byte
mutations, five pairs) and 18 CM4/CM7 tests (529 token/29 byte mutations, ten
pairs). Fresh reports are `%TEMP%/cm3-protocol-controls-20261104-e2.json`,
`%TEMP%/cm3-actual-mutation-parent-20261104-e2/results.json` and
`%TEMP%/classic-fp-negative-parent-20261104-e2/results.json`; their SHA-256
values are respectively
`977F4A42DA6CB119E4E12B47D69BB62F18C9B0D78CD3FB1A53DE7C5C2A649449`,
`AC390BACAA6652D123ADBFB8F7A275690FFA7193DA6FF02BA998343D8CD7275D`
and `B0C79788BF738F63BD30293959E20DAA8B5422716183442786F0B121DF568F50`.

These records do not qualify context construction/other C callees, whole-object
ABI, final direct/archive/LTO images, exception routing or CPU/board behavior.
All required global parity cells remain unsatisfied by this bounded gate.
Production C/assembly, public ABI, default matrix, runtime admission, CI and
hardware claims are unchanged. Receipt prose is later than the captured code
and is not exact-commit hosted CI; no earlier failed/partial run is relabelled.

## CM4/CM7 Distinct FPU Setup Contracts

The next proof-only slice adds `--kind setup` to the existing classic-FP
driver. Its default `transfer` selection and validators remain unchanged;
`ProofKind` is additive report metadata. Both kinds share exact cohort facts,
attributes, closed source/compiler/receipt bindings, captured checker execution
and closing input/output verification. The setup checker is a separate file,
not an instruction normalizer or a replacement for the transfer checker.

Each exact hard/eager p4/b16 CM4/CM7 cohort passes all five ordinary modes.
Ten pairs close 30 complete bodies: native `fiber_port_runtime_prepare` and
reference `vPortEnableVFP`/`xPortStartScheduler`. Fixed protocols consume all
surrounding SHCSR/CCR setup, NVIC priority probing, assertions, calls/inlining,
literal data/relocations, branches and NOPs, not only the FPU subsequences.
The native and reference CPACR mask is `0x00F00000` at `0xE000ED88`. Native
eager FPCCR sets ASPEN and clears LSPEN (`0x80000000`); the reference sets
both (`0xC0000000`) at `0xE000EF34`. Native conditional stores, DSB/ISB and
masked panic-on-failed-readback edges remain distinct from unconditional
upstream read/OR/stores. The ledger maps both differences explicitly.

Parent-run controls pass 4,386 cases: ten positives and 4,376 negatives,
including 2,012 token mutations, 2,012 deletions, 30 extra-tail cases, 226
branch-target, 20 branch-order and 14 call-order mutations. All 38 private
retained-ELF byte mutants reject; the ten original pairs/30 bodies pass and
closing drift is zero. Expanded outer-driver controls pass 200 cases, including
24 positives and 176 negative admission/result/attribute cases. Independent
source comparison/replay finds no confirmed checker or driver-logic blocker.
The initial review's missing setup-ledger headings were added before the
successful parent receipt comparisons; the driver fails closed without them.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzcm4-setup-20261104-e1/results.json` | `90DADD04F2C90CA915DEBA22BC492BC3A44AA9707AAE3DFB02D383B5A61E6509` |
| `C:/fzcm4-setup-20261104-e1/artifacts.json` | `23005CEF22C6F3A20B236A80EEB1A56E975C25A915E69679A0008064E5552A26` |
| `C:/fzcm7-setup-20261104-e1/results.json` | `501A80244C359650C79F5C002B7C061233950B8CBBFFA8D46CAA2E479CB1D0CA` |
| `C:/fzcm7-setup-20261104-e1/artifacts.json` | `80841FCD2DCE81A03AFDD209998EF2AFE2DE2DCB44560635678B23E3A718F46D` |
| Both setup `readers.json` files | `BC92CFEC8686E152A5F5990A8A049E9CFC5A1C8660720D0547385856127BB763` |
| `%TEMP%/freeze-fp-setup-controls-parent-20261104-e1/results.json` | `9EE8E96FC249AD94E0232484B10C9752CC396701F51530EFED2A761F55A48F79` |
| `%TEMP%/classic-fp-driver-controls-20261104-e3.json` | `564E78504F8FA62368F2ABBE023065DCD1922498E99AEFE805722262F3D2C60B` |

The new default-transfer replays at `C:/fzcm4-20261104-e3` and
`C:/fzcm7-20261104-e3` again pass ten pairs/60 bodies. Their complete per-cell
proof objects are identical to the earlier e2 proofs, not just their verdicts.
The result hashes are respectively
`94A296BC0987E332494096F8A36572A65F78BBAF3461C3B277F83CD771EA7D1B`
and `B6D1DD79008C388F5E5307AE607D0158E498C4B59D77BDD32DBD4076D239D852`.

This checks two different emitted setup contracts conditional on entering the
matched functions. It does not prove successful MMIO/readback, LSPACT handling,
callee bodies, exception routing/nonreturn, whole startup or instruction/policy
equivalence. The transfer gate's policy-equivalence flag remains false and its
unresolved-by-three-roots status is unchanged. All required global cells remain unsatisfied.
No compiler, CPU or board is invoked; runtime C/assembly, feature admission,
default matrix, CI and hardware claims remain unchanged. The captured snapshot
precedes this receipt prose and is not exact-commit hosted CI.

A separate read-only Context/Fiber architecture review finds no confirmed
ownership, CPU-detail leakage, init/start/configuration or supported-use
interoperability defect in the reviewed priority-port boundaries. One common
current slot, dispatcher and configuration gate remain; the compatibility shim
delegates and Fiber owns lifecycle metadata only. Temporary compiler-policy
and selected-storage header paths under `fiber/` remain explicit physical
migration debt. Optional MPU/TZ feature and board qualification are not
established by that review.

## Native CM4 Final-Image Pilot

The next proof-only slice adds `tools/fixtures/classic_final_image` for
exactly `cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default`, O2,
direct linkage, without LTO. The captured e8 inventory authorizes this tuple;
the build compiles fresh copied current source/header bytes rather than
reusing old object groups. Three actual Context providers, three CM4
providers, the build-owned expectation, a typed consumer and startup make
nine translation units. No legacy shim, Fiber lifecycle or optional
configuration module is linked. Strong handlers, vector slots 11/14,
common state ownership and private/storage expectations are audited.

The same objects and script link twice, with `--build-id=none` on both.
Only `--emit-relocs` and output names differ. Complete PT_LOAD geometry and
file-backed bytes, zero-fill extents, allocated sections and entry agree.
Actual `-MD` compilation dependencies must match discovery membership and
hashes. Original `.d` files remain retained; repeated GCC header spellings
and aliases resolve to one physical file without discarding distinct files.
Object hashes are checked before/after prelink and both links, and at close.
Commands have prelaunch and terminal records and use the managed process
runner. An explicit environment allowlist avoids recording unrelated secrets.

The separate pyelftools-based ET_EXEC reader leaves the existing ET_REL
reader unchanged. Every root byte is unchanged or belongs to an explicitly
verified applied relocation field. Original addends come from real prelink
objects. Admitted Thumb-16 local branches/literal loads and Thumb-32 BL
destinations are decoded from instruction bits and cross-checked with text
and target identity. No address rebasing, literal zeroing, instruction
filtering or learned body oracle is introduced. Fixed existing native O2
protocols independently check the three fresh prelink functions.

Independent review reproduced and closed three false-accept classes before
qualification: coherent callee-symbol/BL retargeting to mapped padding;
coherent SLOT redirection into another cell or file-backed code; and writable
BSS with a non-writable owning load. Root/callee/SLOT placement now binds
actual defining input object, section and symbol extent to a unique retained
linker input-section placement. Final symbols are not their own authority.
Allocated sections cannot overlap; NOBITS must lie in zero-fill and writable
sections require PF_W. This proves entry provenance, not callee semantics.

The parent fresh build at `C:/fzfinal-cm4-20261104-e10` passes 73 commands,
nine TUs, two final links, three matched prelink roots and seven object
checkpoints with zero closing drift. Its manifest contains 818 artifacts,
538 original/captured input bindings and one generated device header.
Independent audit rehashes the complete artifact membership and all
input mirrors/originals, not only selected result files. The installed,
captured pyelftools version is 0.33; Python is 3.13.14 and GCC is 14.3.1.

Parent reader replay passes 81 pure controls and three complete actual roots:
first start 104 bytes/34 instructions, SVC 212/73 and PendSV 252/89, totaling
568 bytes, 196 instructions and 14 references (12 BL and two SLOT ABS32).
All 13 retained actual-ELF byte/metadata mutants reject at their required
validator stage. Eleven first pass twin equality; the NOBITS and writable-load
mutants reject during structural validation. Original, captured and mutant
closing hashes have zero drift. Separate build-envelope controls pass 30
tests, and the managed process runner passes 18 tests including actual
Python-only timeout/descendant cleanup. Independent read-only review finds
no remaining confirmed blocker in this bounded contract: 12 reader and six
dependency controls pass with no false accepts or source drift.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzfinal-cm4-20261104-e10/results.json` | `70C856C99AA5280716734C29F9670B55622347807BC564979413774E30233159` |
| `C:/fzfinal-cm4-20261104-e10/artifacts.json` | `3A8B360EE33009536C47F7274B34A62211AFC57E7264A14589DE9430970661A0` |
| `C:/fzfinal-cm4-20261104-e10/inputs.json` | `1063AD001D58E03113F5DDA0E466315EA40A1F5E006F13D242BC8512C566F56C` |
| `%TEMP%/classic-final-witness-parent-e10-20261104-e1/results.json` | `5B286A4F0B9C26DB9C17B21D60432878EC2DACF8FA2D38C3955271E527E6F14C` |
| `%TEMP%/final-pilot-command-controls-20261104-e7.json` | `BD2967E713247D5FBB3FBDE2255F1A1F1496EBA654FE682F1A9E9EA25D3E07E8` |
| `%TEMP%/freeze-final-runner-parent-20261104-e1/results.json` | `8DE1A9593FCD8B5DF4C0C881CA1133CA7AF047C464BD16779178F77CBCD7A2C0` |
| `C:/fzfinal-review-20261104-e1/results.json` | `2BB820E116D100F68C22547000AC61FCC930A13868249B664C444538ED1BF95C` |
| `C:/fzfinal-review-20261104-e1/audit.py` | `30E39952E93A36F7156E874EA8291FBE23329BF53BD764C5BB144CFE1E34D54E` |

Failed exploratory attempts remain distinct records, notably e1 interpreter
alias rejection, e2 C-only forced header on assembly, e3 read-only anchor
misclassified by a slot validator, e6 canonical dependency aliases, and e8/e9
over-strict duplicate-spelling rejection. e4/e5/e7 were earlier build-only
successes, not the final reader qualification. None is relabelled as e10.

This closes only prelink-bound preservation and symbol-origin proof for the
three native final-image roots. C-callee bodies/internal relocations,
constructor semantics, successful MMIO, exception routing/nonreturn, FP-policy
equivalence, pinned-reference final images, archive/LTO and the other modes
remain separate obligations. All required global parity keys remain
unsatisfied by this pilot. No target CPU or board ran; production C/assembly,
public/port ABI, default matrix, feature admission and hardware claims are
unchanged. Declared inputs are captured, not the whole host OS/stdlib. This
local source-capture evidence predates the receipt prose and is not hosted
exact-commit CI.

## Native Classic-FP Final Images At Five Optimizations

The next proof-only slice extends the native direct twin pilot to precisely
two hard/eager, no-MPU, VTOR1, p4/b16, ordinary-AAPCS cohorts:
`cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default` and
`cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default`.
O0/Og/O2/Os/O3 each use fresh copies of actual Context/port/expectation
providers, the typed consumer and startup. The exact cohort, private source
directory, storage identity, CPU/FPU flags and transcribed prelink protocols
are profile-bound. Unsupported profiles/modes fail before output creation.
CM7 retains its PRIMASK-preserving 837070 policy; no runtime source changes.

Startup no longer overrides the recorded compiler target with `.cpu cortex-m4`.
Both links use the same nine frozen objects, script, target and optimization
flags; only emit-relocs/output names differ. Strong vectors, owner identities,
private/storage expectations, actual compilation dependencies, seven object
checkpoints and closing input hashes remain mandatory. The O0-only post-island
NOP remains part of each complete root, not filtered as compiler noise.

CM7's longer PendSV requires one observed T32 BNE.W. Its displacement is
decoded directly from S/J2/J1/imm6/imm11 with the branch PC bias, following
[Arm's T3 encoding](https://documentation-service.arm.com/static/66054b941bc22b03bca913ed#page=55).
The reader admits only this wide condition; it still rejects unconditional
B.W, BLX and other unsupported transfers. Twenty-two focused tests cover
signed limits, J1/J2, PC alignment, malformed/reserved conditions, text/bit
disagreement, instruction-interior/data/out-of-root targets and unchanged
system instructions. Existing origin, full-byte and relocation checks stay
intact. The ET_REL reader and production assembly are unchanged.

The fresh parent sweep `C:/fzfinal-grid-20261104-e2` passes exactly ten pairs:

| Profile | Modes | Complete Roots | Root Bytes | Instructions | Applied References | Mutants |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| CM4 | O0/Og/O2/Os/O3 | 15 | 2,846 | 983 | 70 | 65 |
| CM7/r0p1 | O0/Og/O2/Os/O3 | 15 | 3,126 | 1,058 | 70 | 65 |
| Total | 10 pairs | 30 | 5,972 | 2,041 | 140 | 130 |

It records 730 native-tool commands, 90 TUs, 20 final links, 70 object
checkpoints, 8,180 artifact entries and 5,380 original/captured input bindings
(per-build counts, not globally unique files), with zero closing drift.
Each reader run passes 103 pure controls and all 13 actual-witness mutants.
The separate pure build-envelope suite passes 33 controls without launching
a native tool. The local sequential driver retains all commands and final
case receipt hashes; it is an external orchestration artifact, not a hosted
CI qualification or a new production runner.

A complementary parent post-run audit binds each reader result to that case's
exact thirteen unique inputs: nine provider objects and the final ELF,
ordinary ELF, disassembly and map (the prelink object is already a provider).
It recomputes list-derived counts and replays all 30 positive roots and twin
comparisons, requiring exact equality with the retained proof records.
Three in-memory negative receipts reject: a reader from another build,
empty roots with claimed counters, and empty mutants with claimed counters.
Its 305 watched files close without drift. This is receipt/positive-replay
validation, not a second execution of the native tools or 130 new mutation
classes; the retained suite contains thirteen classes applied to ten builds.

The first sweep `C:/fzfinal-grid-20261104-e1` is retained as FAIL: CM4/Og
positive roots passed, but its coherent-callee-retarget negative control
could not find incidental unowned NOP padding. The fixture now explicitly
retains two unowned Thumb NOPs outside Reset_Handler's function extent,
with a synthetic-linker KEEP. The destination is deliberately not a valid
callee origin. This fixes test reproducibility without weakening rejection
or changing a production linker script. The e1 partial success is not
counted as a complete sweep. Earlier standalone CM7/O2 exploration is also
not added to the ten-pair count.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzfinal-grid-20261104-e2/results.json` | `D651FBC5492B7252C14F0D1B30A71C54966AD1504798331FDCC94EDEFD0F4588` |
| `C:/fzfinal-grid-driver-20261104-e2/driver.py` | `F2E035445A9FC2C1A682E08B725EA7BA9A8FE6B195FD4C8ED7C783A436C4EC55` |
| `C:/fzfinal-grid-parent-review-20261104-e1/results.json` | `D64F6F7472CBF2638782A42C954AE97A2B2A8B4C4E86F5CC95F6FD6C52DC6E10` |
| `C:/fzfinal-grid-parent-review-20261104-e1/audit.py` | `092FE605B7716FD0847CC29F41F52007FEB75351138062729F6DA5B4609675BE` |
| `%TEMP%/final-native-grid-command-20261104-e2.json` | `741FACC8A3866D88AA29FCFF407AFFFDAFFF2F3D4CFA34039F907EE59A447FC9` |
| `tools/fixtures/classic_final_image/run.py` | `61AED9AE50CF7C0CE4D46E20479B1D0EB6174FF984B459B1C91E194FB021305A` |
| `tools/fixtures/classic_final_image/elf.py` | `EFFE9004560827EFECBEFFAA1451E4E70DE9D734048F42D5D7BC3B89640FBB83` |
| `tools/fixtures/classic_final_image/test_elf.py` | `3AE0136ECB6EED6F0DA660A8DE8B93C3003A59954739A89B27EA89794546AFAF` |
| `tools/fixtures/classic_final_image/test_run.py` | `CCCA94B295F7675216AB5C0CB5104AB21D2ACCE8A75B5DB050894AEBAEC0CFCB` |

Only native prelink-bound root preservation, applied root relocations and
entry provenance are closed by this sweep. C-callee bodies/internal
relocations, constructor semantics, successful MMIO, exception execution,
native/reference policy equivalence, pinned-reference final images, archive
and LTO remain separate obligations. All required global parity keys remain
unsatisfied. No CPU/board ran; no default matrix, ABI, feature admission,
hardware or hosted exact-commit CI claim changes. The earlier CM4/O2 pilot
record remains historical rather than being rewritten as this larger run.

## Native Classic Final Images Including CM0

This proof-only extension admits precisely three additional no-MPU,
soft/no-FPU, p2/b0, ordinary-AAPCS cohorts:
`cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default`,
`cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default` and
`cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default`.
They share the ARM_CM0 source/storage identity but retain distinct target
facts and exact inventory admission. CM4/CM7 hard/eager cohorts remain
unchanged. No processor family is inferred from an output path alone.

The fixture startup replaces Thumb-2 post-increment loops with explicit
Thumb-1 loads/stores and adds. Its build-owned `PILOT_HAS_VTOR` is derived
only from the admitted artifact's boolean target fact. VTOR0 omits the
VTOR write. A separate guard reads actual prelink Reset_Handler bytes and
checks the aligned `0xE000ED08` literal count against that predicate, with
`FullMMIOProof=False`. This is not a successful write/readback proof or a
general instruction-dataflow analysis. Only this synthetic startup changes;
production startup, linker scripts and port assembly do not.

The strict reader accepts declared soft or hard ELF float ABI, rejecting
neither/both/foreign forms. Four additional ordinary Thumb-1 operand forms
are bound to exact raw bytes. They do not broaden root, callee, relocation,
branch or symbol allowlists. The actual-padding mutant now accepts only
the two existing exact Thumb NOP encodings, including `46c0`; destination
ownership, mapping, executable-load and complete-root checks remain intact.
All previous hard-FP cases are rerun with the changed reader, not inherited.

The fresh parent sweep `C:/fzfinal-classic-grid-20261104-e1` passes:

| Profile | Modes | Complete Roots | Root Bytes | Instructions | Applied References | Mutants |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| CM0 / VTOR0 | O0/Og/O2/Os/O3 | 15 | 2,586 | 1,018 | 65 | 65 |
| CM0+ / VTOR0 | O0/Og/O2/Os/O3 | 15 | 2,586 | 1,018 | 65 | 65 |
| CM0+ / VTOR1 | O0/Og/O2/Os/O3 | 15 | 2,586 | 1,018 | 65 | 65 |
| CM4 | O0/Og/O2/Os/O3 | 15 | 2,846 | 983 | 70 | 65 |
| CM7/r0p1 | O0/Og/O2/Os/O3 | 15 | 3,126 | 1,058 | 70 | 65 |
| Total | 25 pairs | 75 | 13,730 | 5,095 | 335 | 325 |

The sweep retains 1,825 native-tool commands, 225 TUs, 50 final links,
175 object checkpoints, 20,480 artifact entries and 13,480 original/captured
input bindings (per-case counts, not globally unique files). Prelaunch,
actual compile dependencies, object checkpoints and closing artifact/input
memberships/hashes pass without drift. All 162 pure reader controls run
in each case. The separate pure build-envelope suite passes 48 controls
without launching a native tool. Thirteen actual mutation classes are
applied to all 25 builds; this is not 325 independent classes.

The complementary parent post-run audit binds each receipt to exactly nine
provider objects and four final artifacts (13 unique inputs), recomputes
list-derived counts, replays the startup literal predicate and reproduces
all 75 positive roots/twin comparisons exactly. It rejects a receipt from
another build, empty root records with counters and empty mutant records
with counters. Its 755 watched files close without drift. It launches no
native tool and does not independently rerun the entire mutation suite;
complete captured-input/mutant-file closure remains supplied by the sweep.
Read-only architect review found no new admission or receipt-delta blocker.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzfinal-classic-grid-20261104-e1/results.json` | `2816C4EB4C6C90EC0087C5728E6652710746098F3039CA654812A2A167E34369` |
| `C:/fzfinal-classic-grid-driver-20261104-e1/driver.py` | `5F3DB2BB1F58CB5227D30C1711C0EDE8C2C39A38049740E08FA147DD20ED4AE8` |
| `C:/fzfinal-classic-parent-review-20261104-e1/results.json` | `33E59CBC4E9BC13ED03E74CF303442D4F756F14B27525C922130825DF04B970F` |
| `C:/fzfinal-classic-parent-review-20261104-e1/audit.py` | `A84CE528B1B6A43A1CCA6A8574C68F4EF038089A4F2D966951E13B922B16F021` |
| `%TEMP%/classic-final-cm0-parent-envelope-20261104-e1.json` | `6A1239D7D52E87630151F8E9C93C3986B314F69409D35E1A85BB8BF35CCD33D5` |
| `tools/fixtures/classic_final_image/run.py` | `18CE8F44888B8E32F0B358201F95D4D9BB6A1426B24306AB5FCC388594E2EBEF` |
| `tools/fixtures/classic_final_image/elf.py` | `3A8F4E42B42189CDDAE44DE6AFA4468F24781B6EDFD13F02491C96C1E0729809` |
| `tools/fixtures/classic_final_image/startup.S` | `3448DA14A4D86033C9F8DA0C2FD82C4DA0D6DC5D9CA299C189B53E815B7A4D98` |
| `tools/fixtures/classic_final_image/test_run.py` | `6F7772F6D8D63553767DBD4E797F039892383198DCB40460BFADC0144798EFCA` |
| `tools/fixtures/classic_final_image/test_elf.py` | `3CBEEFE0DF4D5D0D13CF89C7458FF3E2B9959E8C89BD0AC4198D86BD1B120561` |

Processor coverage is not an exact device configuration claim. In particular,
the official STM32G071 CMSIS header declares MPU present; a synthetic
non-MPU M0+/VTOR1 image does not qualify its MPU profile. F0-style CM0
processor mechanics and separate CM0_MPU obligations must not be conflated.
No new hardware qualification is inferred from source/header inspection.

Only native direct-link prelink-bound root preservation and applied root
relocations/origins are closed. Pinned-reference final images, C-callee and
constructor semantics, whole-object ownership, successful MMIO/exception
execution, FP policy equivalence, archive extraction and LTO remain separate.
All required global parity keys remain unsatisfied by this bounded gate.
No CPU or board ran. Production C/assembly, public/port ABI, default matrix,
feature admission and hardware/hosted exact-commit CI claims are unchanged.
Earlier ten-pair and single-pair records remain historical.

## Native Witness Input Identity

Read-only architect review of the new reference companion found that the
shared twin comparator can self-compare if a standalone caller supplies
the same ELF as ordinary and emit-relocs. Native actual-witness admission
had the same boundary gap. This does not invalidate the historical 25-case
sweep, whose separate driver binds each receipt to distinct build-owned
artifact paths and actual link commands. It does invalidate treating an
arbitrary unguarded standalone invocation as independent-twin evidence.

Only `test_elf.py` changes: a pre-snapshot guard requires the exact five
roles, nine distinct providers, the intentional prelink/provider path
overlap and thirteen distinct physical files. Same-path, hard-link,
cross-role and provider aliases reject. Fourteen pure tests include the
valid same-bytes/different-files case, exact counts, prelink alias spelling
and a mocked proof that rejection precedes snapshots/capture/reader use.
All 176 pure controls pass. Shared `elf.py`, production code and protocols
are unchanged; patch utility APIs used by reference tests remain stable.

The parent read-only replay `C:/fzfinal-native-admission-replay-20261104-e1`
consumes the exact previously retained CM0, CM4 and CM7 O2 build receipts.
Each current runner invocation passes 176 pure controls and thirteen actual
mutants. The aggregate is nine roots, 1,708 root bytes, 610 instructions,
41 applied references and 39 mutant applications. The parent binds all
thirteen reader inputs to the corresponding original build, checks source
and captured-input hashes, rejects empty proof records and closes 90
watched files without drift. Three Python commands run; zero compiler,
linker, CPU or board executions occur.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzfinal-native-admission-replay-20261104-e1/results.json` | `C857CC97B5F68D34A392E818BEF0B92B285D05DDCB1E0D9C1F7AED282585646C` |
| `C:/fzfinal-native-admission-parent-20261104-e1/driver.py` | `6E3D546B6CAF8DFA2CCF50B9370972E6FD74AC2A89ADCB02421AEA703EDDA78E` |
| `tools/fixtures/classic_final_image/test_elf.py` | `5C8F8C17F86DBF9A95A455A817A172F1BAFB4E8113797A0D14499B308A803BDE` |

This closes standalone input admission only. It does not rerun or upgrade
the historical 25-case sweep, qualify other modes or satisfy global parity
keys. The scope remains prelink-bound native root preservation, not
callee/constructor semantics, pinned-reference final parity, archive/LTO,
CPU/board or hosted exact-commit CI qualification.

## Native Artifact Seal Failure Handling

Source review of the reference companion identified the inherited native
standalone finalization gap: it checked only already-enumerated artifact
bytes, missing a late addition, and could raise after saving PASS without
replacing that receipt with FAIL. Historical sweep evidence remains bound
to its independent outer membership/hash closure; it is not reclassified.

The native `finish()` now compares freshly enumerated complete artifact
path/hash dictionaries after manifest writing. Detected sealing failures
set FAIL and an explicit error, return false and refresh the failure
manifest where readable. Recovery write errors retain separate diagnostics.
Five pure controls cover normal closure, additions, modifications, deletions
and manifest-write failure. All 53 build-envelope controls pass without a
tool invocation. No compile/admission/protocol/ELF or production changes.

The parent fresh build `C:/fzfinal-native-seal-20261104-e1` passes CM7/O2
with nine actual TUs, two direct final links, seven object checkpoints and
73 native-tool commands. The read-only post-auditor verifies the full set
of 818 artifact entries, 538 original/captured input bindings and generated
inputs; its 1,358 watched files close without drift. The separate current
reader passes 176 pure controls and all thirteen actual mutants, preserving
three complete roots, 624 bytes, 211 instructions and fourteen references.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzfinal-native-seal-20261104-e1/results.json` | `A6A03CA7E8AA507513285272F11D7B08C2F1C41FEFFB2521B41E01064F4CA39C` |
| `C:/fzfinal-native-seal-parent-20261104-e1/results.json` | `7C49F55E8BF37C792EF7FC8CBDB8652B84161EF7B826AE3BA7251895BF21B7F8` |
| `C:/fzfinal-native-seal-parent-20261104-e1/audit.py` | `37A0F4C2621F7918DC6BBFBDAA165EA7A4AA009002ADEFF39E09AA7D1AE910A1` |
| `C:/fzfinal-native-seal-reader-20261104-e1/results.json` | `04FBAEED4AF69E41DB3BC7C535BC67748A9E264BE5D24F5D9D9D49EA0829CAE6` |
| `%TEMP%/native-final-parent-seal-20261104-e1.json` | `7CD753F814DC106A51C9E1FD9EEB257223C9BDA6BEDCE3AB2D2EE3E44B814D10` |
| `tools/fixtures/classic_final_image/run.py` | `254A28FA9E18DB7155164D5CA9FE2F1CBCB5160DF00D03247A497D15ECEEE813` |
| `tools/fixtures/classic_final_image/test_run.py` | `A8711444DFDF7A363C4B4FAC252E35376D9F48DA68D6B80E70B0413311D8BEAC` |

This is a focused standalone sealing repair and one fresh native CM7/O2
replay, not a new all-profile/optimization sweep or pinned-reference final
parity. C-callee, constructor, MMIO, archive/LTO, CPU/board, hosted CI and
global freeze obligations are unchanged. No target image runs.

## Pinned CM4 Reference Final-Image Pilot

The new opt-in companion builds unchanged
`portable/GCC/ARM_CM4F/port.c` from the clean local FreeRTOS pin
`a50edad08b29052631aa469d4df6e6ec7ff68878`. It initially admits only
CM4/O2 direct linkage, hard FP, VTOR1, no MPU, p4/b16 and ordinary AAPCS.
The native inventory cohort's eager name does not assert reference eager
policy: upstream ASPEN+LSPEN lazy setup remains unchanged and distinct.

Exactly four fresh TUs are used: pinned port, typed boundary providers,
typed consumer and fixture startup. `pxCurrentTCB` is NULL BSS; scheduler,
tick and assertion providers are explicit non-success fail-stop boundaries.
There is no actual TCB/task-stack/ready-list model and reset cannot start
the scheduler. Strong SVC/PendSV/SysTick vector placement is link evidence,
not active VTOR or exception execution. Two kept unowned Thumb NOPs are
solely deterministic invalid callee destinations for a negative control.

The builder captures actual clean-pin/blob comparisons for 23 upstream
headers/port files, exact config/portmacro dependency providers and current
tool/fixture bytes. Both thresholds are 16. Independently transcribed
prelink protocols close all three original roots before the twins link.
The same four frozen objects/script produce ordinary and emit-relocs images
with build-id disabled. Both final allocated/load geometries and complete
loader-visible bytes agree. No archive or LTO link is built, and no target
image executes.

The parent actual build `C:/fzfinal-reference-cm4-20261104-e1` passes with
71 host-tool commands (including Git pin/blob checks), four TUs, two final
links, seven object checkpoints, 741 artifact entries and 480 original/
captured bindings. Its output sealing uses full path/hash dictionaries;
late additions, modifications, deletions and manifest-write errors persist
FAIL and refresh failure evidence when writable. All 28 pure envelope
controls pass, including a fault after the tentative PASS publication.

`ReferenceCM4FinalImage` is a distinct fixed reader, not a caller-supplied
symbol allowlist. It requires local `prvPortStartFirstTask` (40 bytes),
global `vPortSVCHandler` (32) and global `xPortPendSVHandler` (92).
Complete source-transcribed instruction encodings and operands, exact
IT-EQ/high-FP pairs, original REL addends and final applied destinations
are retained. Actual provider symbols and separately captured input-section
map placements bind roots, `vTaskSwitchContext` and `pxCurrentTCB` origins.
No C-callee/internal-relocation or kernel semantic proof is claimed.

The initial reference reader and parent orchestration attempt remain FAIL
at `C:/fzfinal-reference-cm4-reader-20261104-e1` and
`C:/fzfinal-reference-cm4-parent-20261104-e1`. The real first root has two
adjacent data mappings, `[34,36)` padding and `[36,40)` literal pool; the
initial synthetic fixture incorrectly conflated them. Both real prelink and
final instructions/bytes agreed with the fixed protocol. The corrected
reader requires the exact two boundaries, records `DataMappings`, and
rejects missing/shifted boundaries. It does not merge or discard them.
Seven focused controls extend the pure reader suite from 68 to 75.

The corrected parent witness `C:/fzfinal-reference-cm4-reader-20261104-e2`
replays the unchanged actual build images: three complete roots, 164 bytes,
48 instructions and three references (one BL-4, two current-TCB ABS32+0).
All thirteen retained actual mutants reject at the intended stages/reasons.
Eleven preserve equal twin load images; the two malformed storage owners
reject at twin validation. Independent input admission requires eight
distinct physical files (four providers plus four final artifacts), with
only intentional prelink/provider overlap. Eleven pure identity controls
cover same-path/hard-link/cross-role aliases. Sources and original/captured/
mutant bytes close without drift.

The read-only post-audit
`C:/fzfinal-reference-cm4-parent-review-20261104-e2` binds the exact producer
receipt to the corrected reader, recomputes record counts, verifies every
artifact/input/mutant file and reproduces all three roots and twins exactly.
Its 1,300 watched files close without drift. It runs no native tool and is
not a second compiler run or thirteen additional mutation classes. The
failed initial combined orchestration is not relabelled as PASS.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzfinal-reference-cm4-20261104-e1/results.json` | `B3BB267B5D8E0A89F6A17D96B82DBF95DB2C440EAF76F1598D54CDE54FC5395F` |
| `C:/fzfinal-reference-cm4-reader-20261104-e2/results.json` | `332EEDAC3516F65F94A9E8100E9E34E9665FB42E4EFED0E935C1D80DFE4D2103` |
| `C:/fzfinal-reference-cm4-parent-review-20261104-e2/results.json` | `E58119D973EF7E668D23748438531ACD797BB677ABA46B2356CAFF473B31E32D` |
| `C:/fzfinal-reference-cm4-parent-review-20261104-e2/audit.py` | `083B12A4B1B40A49BF0E7463A9252287C8717AF6F9F2569C5A91C2F65995A245` |
| `C:/fzfinal-reference-reader-parent-pure-20261104-e2/results.json` | `F4929E3DD1B8726C417B0815C838E1610518617AC3039D0C47F4E30088B0DBB8` |
| `%TEMP%/reference-final-parent-envelope-20261104-e1.json` | `A56B149B480ED321CBAE0193E1ACDF694EC90B97DE8D327E99E8632DCBC8A07D` |
| `C:/fzfinal-reference-identity-20261104-e2/results.json` | `5CF46DED1130258BAC3ECE88DAF20146EEADEC68D9B1059D5886EE06A76ED058` |
| `tools/fixtures/classic_final_image/reference_run.py` | `62D48A93A47C50BA8D9BFD4C179B792C1FB2BED4F8461485D5BC1CB1E36595FE` |
| `tools/fixtures/classic_final_image/reference_elf.py` | `D37718B48BF8AFBE155E6F7F4F7B480AE49B2141C39F6B61CA5128CF6AD5FE04` |
| `tools/fixtures/classic_final_image/reference_witness.py` | `36B039B6BCEE3FDFB81C11D8E9783B9F994435115CE62F04E1B7A55EBF810AA9` |

This closes only one pinned-reference final-root preservation witness.
Native eager versus reference lazy FP policy remains in the difference
ledger, not silently equated. Constructor/C-callee/kernel semantics,
successful MMIO, handler execution, whole-object/final native-reference
parity, other modes/profiles, archives/LTO, CPU/board and global freeze
remain separate obligations. All required global parity keys remain
unsatisfied by this pilot. No production C/assembly, public/port ABI,
default matrix, feature admission or hardware qualification changes.
Local captured-source evidence is not hosted exact-commit CI evidence.

## Pinned Classic-FP Reference Final Images At Five Optimizations

The opt-in companion extends the historical CM4/O2 pilot to exactly
CM4 and CM7/r0p1 hard-FP, VTOR1, no-MPU, p4/b16 ordinary-AAPCS cohorts
at O0/Og/O2/Os/O3. Default invocation remains CM4/O2. The clean upstream
pin is still `a50edad08b29052631aa469d4df6e6ec7ff68878`; actual port C
and portmacro headers are captured unchanged and checked against Git blobs.
Both profiles use four actual TUs and identical-object ordinary/emit-relocs
twins. There is no native-runtime source, synthetic scheduler success,
archive, LTO, instruction execution or board access in these builds.

CM4 header facts require SP `__ARM_FP=4`; CM7 requires SP+DP `14`.
The exact per-profile CPU/FPU flags, attribute facts, config/portmacro
providers and ten-word consumer record remain separately checked. CM7's
manifest has the additional exact definition
`configENABLE_ERRATA_837070_WORKAROUND=1`. The pinned r0p1 source already
contains the erratum sequence unconditionally; preserving this metadata
define does not claim it controls the source sequence. Missing, changed,
non-string and extra definitions reject, including the alternate
`WORKAROUND_PMU_CM001=1` instruction path.

The initial sweep `C:/fzfinal-reference-grid-20261104-e1` remains FAIL.
Five CM4 pairs passed, but CM7/O0 admission rejected the real manifest
before any tool launch because the initial builder incorrectly required
CM4's three-definition dictionary for both profiles. The fix adds exact
profile-specific dictionaries and positive/negative regressions against
the actual inventory. No upstream source or protocol was changed to pass.
The failed sweep is not promoted or combined into the fresh result.

The fresh complete sweep `C:/fzfinal-reference-grid-20261104-e2` passes
all ten pairs: 710 host/native-tool commands including Git identity/blob
checks, 40 fresh TUs, 20 direct links and 70 object checkpoints. Complete
artifact sealing closes 7,410 entries and 4,800 original/captured input
bindings plus generated inputs with no closing drift. Each pair checks
three complete original prelink protocols before final-image replay.

`ReferenceCM4FinalImage` and `ReferenceCM7FinalImage` remain fixed classes,
not caller-supplied protocol/symbol allowlists. CM4's three roots total
164 bytes/48 instructions; CM7's total 168/50. O0 alone retains one exact
post-island `00bf` NOP and its Thumb mapping per root, adding six bytes and
three instructions per profile. CM7's exact PendSV is 96 bytes with BL
at 50 and ABS32 at 92, rather than CM4's 92/46/88. Its literal LDR uses
80, not 76. Neither the CPSID/CPSIE instructions nor O0 tails are dropped.
All ten pairs total 30 roots, 1,672 bytes, 496 instructions and thirty
applied references. Each pair retains one BL-4 to `vTaskSwitchContext`
and two ABS32+0 entries for `pxCurrentTCB` with actual provider/map origins.

All 191 pure reader controls run for every pair. The separate envelope
suite passes 37 controls, including actual-manifest selection across all
ten cases and exact define-mutation rejects. Seventeen standalone admission
controls include the existing physical-input alias checks, profile/mode
totals and four output controls. Resolved in-repository/ancestor/existing
outputs reject before mkdir, hashing, input capture or reader loading.
Every actual pair passes thirteen retained mutation classes: 130 mutant
applications, not 130 distinct classes. Eleven per pair preserve identical
twin loads but fail the intended root check; two fail structural twin
validation. No source, input, captured-input or mutant file drifts.

The separate read-only parent post-audit binds the exact sweep and per-case
receipts, replays all thirty complete root records and twin comparisons,
and checks the full artifact/input/generated/mutant memberships and bytes.
Exact four-file validator-source memberships and five-file mutant lists
reject empty closure records. Parsed receipts use the same watched byte
buffer that was hashed. Typed false/zero non-promotion fields are required.
One hundred malformed receipt controls reject: profile, mode, provider
binding, promoted scope and empty source/mutant closure variants. Its 8,668
watched files and build memberships close without drift. This audit
rehashes retained mutants; it does not re-execute them or compile again.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzfinal-reference-grid-20261104-e1/results.json` (FAIL) | `2DE4B8144844B54B04219883C79A70743C2093F06A4027489E8A96ACADEF0ABE` |
| `C:/fzfinal-reference-grid-20261104-e2/results.json` | `739F371EC9188187DE7B1DE72B7A9A36434B77C64F49A521E6D5A40C4B7E8AE5` |
| `C:/fzfinal-reference-grid-driver-20261104-e2/driver.py` | `8FB5967B9B91302F5CAB2A482678B0922C947DC4BBB4E63F4F07845F04C910B0` |
| `C:/fzfinal-reference-grid-parent-review-20261104-e1/results.json` | `C87D5F0963377B60B98E3BFF67E337B9EC82D4C02F212372375DAC00630629B5` |
| `C:/fzfinal-reference-grid-parent-review-20261104-e1/audit.py` | `5C74BDAE3561B7601293F7862F4BC4669B3460FED9529B3B72EEE9B9CD79FE4B` |
| `C:/fzfinal-reference-reader-parent-pure-20261104-e3/results.json` | `BE183E3D4A616BB9DACBF225E1CF067033FF9B21591E029D6D272D0A2C73F333` |
| `%TEMP%/reference-final-parent-envelope-20261104-e2.json` | `BD08D47BF00A301397BB62514BDFDEB482942DA1821580F67B02FA73E15B9DBE` |
| `C:/fzfinal-reference-identity-expanded-20261104-e3/results.json` | `9BADB52F1C5B23DD6B58B03F57000027FC98D918A42CA60FC06B1A61C317C135` |
| `tools/fixtures/classic_final_image/reference_run.py` | `FB5E1FA3CEE51E8069A15CDC6E3F31F47CA046EF0320960F9CA9C8809C2F1838` |
| `tools/fixtures/classic_final_image/reference_elf.py` | `CDE457FEB11A1DCC1D0F41D394C7E62C4B3AA0E109A3D70979CE320914215A4D` |
| `tools/fixtures/classic_final_image/reference_witness.py` | `FD53CFE4E135BAC269D810BFD66A56319B80DA90569EBA23EBE6D06DC4C2D750` |

This closes only the ten pinned-reference direct final-root witnesses.
`FAP-FP-SETUP-POLICY` (native eager versus reference lazy FP) and
`FAP-CM7-ERRATA-PRIMASK` (native preservation versus upstream unconditional
IRQ re-enable) remain explicit. Reader mode selection alone is not proof
of compiler mode or CPU profile; enclosing source/recipe receipts provide
that binding. No C-callee/kernel/constructor semantics, successful MMIO,
full native/reference final parity, other profiles/cohorts, archive/final
LTO, CPU/board or global freeze is qualified. All required global parity
keys remain unsatisfied by this bounded gate. Production C/assembly,
public/port ABI, default matrix and feature admission are unchanged.
These local receipts are not hosted exact-commit CI evidence.

## Classic-FP Final Mechanism Join

The new opt-in `tools/fixtures/classic_final_join` joins the exact CM4 and
CM7/r0p1 hard-FP, VTOR1, no-MPU, p4/b16 ordinary-AAPCS cohorts at
O0/Og/O2/Os/O3. It executes no compiler, linker or target instructions.
It consumes completed native and pinned-reference builds, not substitute
objects from older mechanism-only captures. Expected producer receipt and
artifact-manifest hashes are separate mandatory inputs. All four are
authenticated before any captured pyelftools code can be imported.

A fresh native build sweep at `C:/fzfinal-native-join-grid-20261104-e1`
passes ten pairs, 730 native-tool commands, 90 fresh TUs, 20 final links
and 70 object checkpoints. Its complete closure verifies 8,180 artifact
entries, 5,380 original/captured bindings and generated inputs without drift.
All 176 native reader controls run per pair, and all 130 actual mutant
applications pass. The 53 native build-envelope controls also pass. This
is a fresh build on current harness sources, not an upgrade of old records.
A read-only positive audit replays thirty native roots/twins, rejects three
receipt-shape substitutions and closes 305 watched files. Full build/input/
mutant closure belongs to the native sweep; that positive audit is not a
second compilation or a new mutant run. The reference input is the complete
ten-pair sweep recorded in the preceding section.

The join admits exact full cohort/target/ABI facts, source selections,
source/object hashes, actual compile dependencies, target/optimization
flags and their actual compiler command records. Native has nine TUs,
reference four; both require two ordered links and seven ordered successful
object checkpoints. Provider identities, final ELFs/maps and prelink
sidecars bind their sealed producer bytes. Same-path/hard-link/cross-role
aliases reject. The reference pin and all 23 source/blob bindings remain
closed, including exact CRLF-versus-Git comparison rules. Native's seal is
verified through its complete artifact closure, not a nonexistent
reference-only `ArtifactSealVerified` receipt field.

The parser is the authenticated native build's captured pyelftools 0.33
package. All package files are checked before import; cached ambient or
out-of-root module origins reject. A self-resealed manifest without the
expected external hash is not authority. Reused interpreters containing
arbitrary preexisting Python state are outside the fresh-command contract.
JSON hashes and parsing use the same read buffer. Complete original,
captured and generated-input memberships/hashes are checked at close.
Output copies, report and artifact manifest also form an exact path/hash
seal; late additions, deletions, report mutations and write failures cannot
leave a successful exit or retained PASS where recovery writes succeed.

The existing six-body checker runs on the final builds' own native index-3
and reference index-0 prelinks, with exact profile attributes and O0 tail
rules. Both strict final readers then bind those same captured objects to
three complete final roots each. Their own ordinary/emit-relocs twins must
agree; native and reference loader bytes are not compared for equality.
Three exact pairings retain the reviewed start/provenance, scheduler,
mask-restoration and FP-validation difference IDs. CM7 additionally retains
PRIMASK preservation versus upstream unconditional IRQ re-enable. Canonical
token-body hashes and raw final-byte hashes are recorded separately.

The retained inventory ledger predates `FAP-FP-SETUP-POLICY`; it still
supplies all transfer-mechanism rationales. The separately captured and
hashed `POLICY_DIFFERENCES.md` preserves the later eager-versus-lazy setup
rationale. This is an explicit supplement, not a silent missing-rationale
bypass or a claim that the two FP policies are equivalent.

Initial smoke attempts remain FAIL at
`C:/fzfinal-join-smoke-20261104-e1` (incorrect assumed inventory `Status`
field) and `...-e2` (later setup ID absent from the old inventory ledger).
Both defects were fixed before the complete sweep. `...-e3` was an initial
CM4/O2 success; it is not counted as an additional qualified cell.

All 24 metadata tests pass, including twenty actual producer receipt
positives and 200 metadata mutation applications. Seventeen Watch/seal
tests cover same-buffer snapshots, input/capture/membership drift, late
report mutation/deletion/addition and write-failure rollback. Eleven
contract tests cover all four hash gates before parser loading, exact
codegen-command binding, physical aliases, output/path containment,
duplicate JSON keys, exact mechanism/difference assignments and non-claims.
These total 52 test methods, not 52 real ELF builds or instruction proofs.

The complete actual sweep `C:/fzfinal-join-grid-20261104-e1` passes all ten
joins: sixty root/body witnesses, thirty mechanisms, 7,644 bytes, 2,537
instructions and 170 applied references. Four additional real invocations
reject cross-profile, cross-mode (including identical-layout Og/O2), wrong
receipt hash and wrong artifact-manifest hash. Exact expected error reasons
are required. The two hash failures stop before parser import, with zero
or one watched input respectively. Fourteen host Python invocations run;
no Arm tool or target runs during the join. Closing all ten cases verifies
21,360 input bindings in aggregate, not that many unique physical files.
All positive and negative output seals, source memberships and both pinned
producer-grid identities close without drift.

A separate read-only post-audit binds the exact aggregate/per-cell receipts,
replays all sixty final-root records and both sets of own-image twins, and
recomputes every six-body own-prelink proof and mechanism list. It rehashes
all retained input copies and outputs and confirms the four intended actual
admission failures. Its 17,432 unique watched files and output memberships
close without drift. No compiler, new mutation class or target instruction
is executed by this replay.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzfinal-native-join-grid-20261104-e1/results.json` | `18B55DC227A9AAD1DFA6F980CA15F7539608A23BD9FD505A039E47932E2B03C2` |
| `C:/fzfinal-native-join-grid-driver-20261104-e1/driver.py` | `BB245A53BFA18F89E5A9A59CE78752D9526082D67B1945268E0B43E2ECA19B64` |
| `C:/fzfinal-native-join-grid-parent-review-20261104-e1/results.json` | `D61E073C35627C468FE704219C5E75FBCAF05737594EA278C832331136FC360B` |
| `C:/fzfinal-join-grid-20261104-e1/results.json` | `FDCC4F7B18A68F1F671D9B6C918166B844258F392ABD80CE7A88527FF3BEBAED` |
| `C:/fzfinal-join-grid-driver-20261104-e1/driver.py` | `A55BC6DF6A9CC50B963D7EE1D2F53A4315676C9F4D9DB7E034A247BCAD4F02CD` |
| `C:/fzfinal-join-parent-review-20261104-e1/results.json` | `6920218984F3EDD27ABECA7B0197BC88B5604267A601859079C90322DA9D65A6` |
| `C:/fzfinal-join-parent-review-20261104-e1/audit.py` | `36FC060B4B53BB2F688200B377740BA215F4D526A347187B4BB22414A001D9BF` |
| `C:/fzfinal-join-admission-parent-20261104-e1/results.json` | `76CBB2B0B69CE636BB9C3E37A1FB0CC455D81B911C8E20A1E8F3E2878A276F30` |
| `C:/fzfinal-join-watch-parent-20261104-e1/results.json` | `46B31876AA064EE820560A18FF3EC0722BE930293903F4C836F990558D6AE3E7` |
| `C:/fzfinal-join-contract-parent-20261104-e2/results.json` | `E5843D73E611BE2C08D475314A80F80AE31D8AC6948C6CB7F50EE5CEFB2EA936` |
| `tools/fixtures/classic_final_join/join.py` | `2785F72E5F86257A403141EB856BB8D49F0A9A6CF4D005CC858D8D2B60EBF013` |
| `tools/fixtures/classic_final_join/admission.py` | `D860F31BAD2A8E2A9FD976FE90CD30D44C59B8FD915F7FF89F86BA004F4E80A4` |
| `tools/fixtures/classic_final_join/POLICY_DIFFERENCES.md` | `D5744662AF124C41709AF73E3DA3819B0C9797EEE0F597B27D572FFACDB509EB` |

This gate closes final mechanism composition only for those ten exact
ordinary-mode cells. It is not complete-object, constructor/C-callee/kernel
semantics, FP policy equivalence, successful MMIO/handler execution, whole
native/reference final equivalence, other profiles/cohorts, archive/final
LTO, CPU/board or global freeze. It satisfies zero required global parity
keys. Production C/assembly, public/port ABI, feature admission and default
matrix are unchanged. Local proof receipts are not hosted exact-commit CI.

## Pinned CM0 Reference Final-Twin Producers

Reviewed locally on 2026-11-04. This standalone proof-only slice introduces
`tools/fixtures/cm0_final_image` without changing the qualified classic-FP
readers, production context/Fiber code, port assembly, ABI or default matrix.
It admits exactly the three CM0-family p2/b0, ordinary-AAPCS, soft/no-FPU,
no-MPU cohorts already defined by the captured CM0 closed-root contract.
CPU and VTOR differences remain explicit receipt facts, not inferred from
potentially identical function bytes or claimed as STM32 device readback.

Every profile uses unchanged pinned
`a50edad08b29052631aa469d4df6e6ec7ff68878`
`portable/GCC/ARM_CM0/port.c` and `portasm.c`, real `portmacro.h` and
`portasm.h`, typed fail-stop providers, a seven-entry typed consumer and
Thumb-1 startup. There are exactly five TUs, not a reconstructed/combined
port object. All discovered dependencies must equal actual compilation
dependencies. MPU/FPU/TrustZone are zero; raw priority thresholds zero mean
BASEPRI is inapplicable. The baseline inline infinite-loop assertion is
preserved. The synthetic no-VTOR fixtures explicitly override the otherwise
VTOR-dereferencing scheduler installation check to zero; VTOR1 uses one.
This is fixture policy, not proof of runtime MMIO or routing.

The prelink checker matches five complete source-transcribed protocols:
four owned by `portasm.c` and the C SVC dispatcher owned by `port.c`.
Both upstream SVC dispatch stages and the separate first restore remain
real functions. Linker KEEP retains complete owning sections, including
literal pools beyond function extents. Metadata records full section
hashes, sizes, mappings and REL records without enlarging `st_size`.
The current-TCB provider has its real opaque pointer type and null BSS;
no fabricated kernel/TCB, scheduler or tick execution is supplied.

`C:/fzfinal-cm0-reference-grid-20261104-e1` passes all fifteen cells at
O0/Og/O2/Os/O3: 75 TUs, 30 direct final links, 105 object checkpoints and
1,185 host/native-tool commands. There is no intermediate relocatable
link. Every ordinary/emit-relocs pair uses the same exact five objects.
The producer checks strong vector definitions and slots 11/14/15, typed
consumer pointers, numeric header facts and absence of native code.
Load segments and allocated bytes match within each pair, not across
native/reference implementations. All 11,655 artifact entries and 7,245
original/captured input bindings close without detected drift.

The parent replay reproduces 75 owning-object body records, binds all five
whole sections to both map placements per case, and independently records
45 out-of-function pool words. It does not prove their applied relocation
semantics or full final instructions. The original sweep auditor lacked
explicit malformed-receipt defenses for twin aliases, empty input lists
and mixed-newline normalization. These were addressed in the separate
stronger replay before relying on its admission evidence, without changing
the already-built producer sources or ELFs.

Post-audit `...parent-review-20261104-e1` remains FAIL: its first uniqueness
guard incorrectly rejected legitimate content-addressed capture deduplication.
E2 passes the positive replay, 135 bounded in-memory receipt mutations and
five newline controls; it predates complete worker-binding and same-buffer
JSON admission. E3 closes both gaps and repeats the same actual grid. It
authenticates each case receipt/manifest/input JSON buffer before parsing,
requires consumed inputs, complete captured inventory, six resolved
toolchain workers, tool DLLs and parser bindings, and binds canonical
physically distinct twins to recorded hashes and link outputs. Only exact
same-hash/basename content-addressed capture sharing is accepted.

E3 passes thirteen deliberate in-memory metadata variants per case, 195
applications total: twin record/path aliases, wrong ELF/map hashes, empty
file/generated inventories, missing consumed source/config/tool/cc1 worker,
inventory manifest, parser and DLL binding. Each must reject for its intended
reason. Five additional controls distinguish exact LF or whole-file CRLF
from mixed/duplicated CR. These are auditor controls, not actual ELF byte
mutations or compiler invocations. All fifteen cases are replayed again
at closing. The separate producer suite passes 25 pure controls, including
scope/config/profile/protocol checks and artifact failure rollback. No
source or input drift is detected; historical attempts are not relabeled.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzfinal-cm0-reference-grid-20261104-e1/results.json` | `8D015F218F52FE2E71237E7AA75E93132A9E4D09A13A02D1182CC8A375FFAD91` |
| `C:/fzfinal-cm0-reference-grid-driver-20261104-e1/driver.py` | `FD62979FFFC6010CB8441C39ADB4070327D7147BF70091D1FC4AFD146F6C7D53` |
| `C:/fzfinal-cm0-reference-parent-review-20261104-e1/results.json` | `F6EE7C0C8DB1A3543C505B759F829E8661E3727601903E921FC5913656E32EBD` |
| `C:/fzfinal-cm0-reference-parent-review-20261104-e2/results.json` | `281775733DE809B853C32F12E106E8D8BAC427CB585C91284666C83F3EAE4E1A` |
| `C:/fzfinal-cm0-reference-parent-review-20261104-e3/results.json` | `1CB7C0CBDFE9D2F13788241B95998BF6BCB5FD14F32ECC7152F0DF7ADAA84C0B` |
| `C:/fzfinal-cm0-reference-parent-review-20261104-e3-driver/audit.py` | `56A9AEC5CE6AE16D4F1C0F0B14D01DE37DAFF0A9BE934B16718F16067C681F96` |
| `%TEMP%/cm0-final-parent-envelope-20261104-e1.json` | `C37CBAE2037008BFDAF18F4C18CD0DAF397A8170F37E3042B30D30A4F7EFE127` |
| `tools/fixtures/cm0_final_image/reference_run.py` | `6F1171044756C0F285E2B58B9DBC0D03B44B883B759241E6037A4CFAB53D0404` |
| `tools/fixtures/cm0_final_image/test_reference_run.py` | `FFB266D9B6993BC37AF1EB8345CF3B5D386011B53A37A1372BBB416B15C286F6` |

The next independent gate must close final five-root instruction/relocation
semantics, out-of-extent pool provenance and Thumb tags, actual retained-byte
negatives and the native/reference final mechanism join. Current evidence
is producer/twin preservation and owning-object protocols only, not that
final-root proof, constructor/C-callee/kernel semantics, successful CPU/MMIO
execution, other cohorts, archive/final LTO or global freeze. All required
global parity counters remain zero. No board was flashed/reset/run; local
receipts are not hosted exact-commit CI. The protected unrelated WIP remains
untouched.

## Pinned CM0 Reference Final Roots At Five Optimizations

Reviewed locally on 2026-11-04. The separate `cm0_final_roots` fixture
consumes the exact qualified fifteen-case CM0 producer and E3 parent
authentication record above. No new target, compiler, linker or objdump
executes. Two prelink owners and five direct provider objects bind five
complete reference roots to their final sections, symbols, map placements,
raw instructions, REL addends and applied relocation fields. Original and
captured input bytes, parser package and proof sources are authenticated
before use, then checked again at closing.

The strict reader reuses the unchanged structural/bit decoder without
patching its globals. It handles the actual O0 C dispatcher separately
from Og/O2/Os/O3, three out-of-function ABS32 pools, five bit-decoded literal
loads, two exact calls and their source/provider-bound destinations. Helper
Thumb tags, all NOPs, mapping boundaries, complete section extents and
O0 external padding remain evidence, not normalization. Four exact BX
sites are permitted by source-derived protocol; runtime stack contents,
EXC_RETURN and successful exception targets are not inferred.

The first actual CM0/O2 smoke retained FAIL because its root-size mutation
correctly rejected at ORIGIN while the witness expected PRESERVATION.
Only the expected reason was corrected; the reader was unchanged. The
CM0/O0 smoke then passes all nineteen real mutation classes. The initial
pure-reader run had four failed subtests due to test-layer expectations:
the O0 external NOP reason and pool-addend validation at the reference
layer rather than the section layer. Tests were corrected, not the reader.
The initial witness-pure run failed because a synthetic stat mock lacked
`st_mode`; fixing the mock does not change actual ELF admission.

The first complete fifteen-case E1 replay passes all actual roots and
mutations, but review identified a bounded admission gap: the aggregate
accepted pure PASS/count/source-drift facts without explicitly rejecting
nonzero Failures/Errors/Skipped or wrong pure scope/counters. All actual
E1 receipts had correct zero values. E1 remains historical; its claim is
not upgraded into malformed-receipt rejection evidence.

E2 requires exact typed zero counters, literal false non-claim flags,
fixed scope/pin/count, empty error/failure/drift records and nonempty source
bindings. Fifty-one deliberate in-memory receipt variants reject for the
intended admission reason. The complete actual sweep is repeated fresh
with unchanged reader/witness and unchanged input ELFs: fifteen cases,
75 roots, 2,586 bytes, 1,128 instructions, 75 applied references and
45 external pool words. All 261 actual byte-mutant applications reject.
Of these, 231 preserve equal mutant twins before exact root rejection;
30 reject load/storage structure in the twin reader. This distinguishes
real root validation from a same-image comparison.

All 85 pure reader controls run in each case; fourteen separate witness
controls pass. They remain synthetic controls, not additional real ELF
mutations. E2 invokes thirty Python children and zero Arm tools/targets.
Its closing replay reproduces every positive root, twin and actual mutant,
closes exact artifact/input/source memberships and watches 13,912 files
without detected drift. An independent read-only review confirms the E2
admission changes and the preserved producer/root/mutant closure.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzfinal-cm0-root-smoke-20261104-e1/results.json` | `2DEE05102B58FF84F8E5FD825B77374B7904251DE17FA7ABA912B644099B9338` |
| `C:/fzfinal-cm0-root-smoke-20261104-e2/results.json` | `5B758E5FC2364725F0DA618AA0FE297BF85D8ACE25F757003F3DD09FE2C14BC7` |
| `C:/fzfinal-cm0-reader-parent-pure-20261104-e1/results.json` | `9118ADB44C38D23A33C731F397DD6FD6D8F85C65CD5B27ECF628F60E254CBFB1` |
| `C:/fzfinal-cm0-reader-parent-pure-20261104-e2/results.json` | `D074375954D18CD3F574D3181B77D54F9438E80DC5BCC3869407A62A7415C51F` |
| `%TEMP%/cm0-final-witness-parent-pure-20261104-e1.json` | `DC04499FCD40B56F71A6666C616C2648FD20625F7D7260A9D72A3B4FA2F895FC` |
| `%TEMP%/cm0-final-witness-parent-pure-20261104-e3.json` | `9CB074B8B7F842C46BE89D465C67E9B11B21A7A53E9B4D083AE11A7CE457AF4F` |
| `C:/fzfinal-cm0-roots-grid-20261104-e1/results.json` | `89786757369ACCBCCCF51AAECFFC20C38F09D712D6F57109BCB9C8E99A03E9DF` |
| `C:/fzfinal-cm0-roots-grid-20261104-e2/results.json` | `4AB82488E96F003E71538DA414946FF79B351300FA24A4C3E7E346A5F05E7875` |
| `C:/fzfinal-cm0-roots-grid-driver-20261104-e2/driver.py` | `CEDB5019DDC8030F43F51B835AB15C6914B1B60E6C6A2B2C3EE99747CE28ACDA` |
| `tools/fixtures/cm0_final_roots/reference_elf.py` | `B4518296657268BBDCA59C87242D533D1BE43AA69A4FC6511456D75E015FB142` |
| `tools/fixtures/cm0_final_roots/test_reference_elf.py` | `9C8F74920F75E7349CA778BEE7B287998C5175B58B05BDAFC40EB27FFE524E1E` |
| `tools/fixtures/cm0_final_roots/reference_witness.py` | `E955AB9261EAA2B75DCF570187194315C18EE4CB4CDEE980BCD2C1E85029E1AD` |
| `tools/fixtures/cm0_final_roots/test_reference_witness.py` | `F90129F8F40AD963D6CC6EC58F797D056B3B8408A9E9B0A3F4A34A8452283B6C` |

This closes bounded reference final-root preservation only. The independent
native/reference final mechanism join is next. General C/callee/kernel
semantics, successful CPU/MMIO/handler execution, dynamic exception-target
values, other cohorts, MPU/FP/security, archives/final LTO and global freeze
are not proved. All required global counters remain integer zero. Runtime
sources, assembly, ABI, feature admission and default matrix are unchanged.
No board is flashed/reset/run; local receipts are not hosted exact-commit
CI. The four protected unrelated WIP entries remain untouched.

## CM0-Family Final Mechanism Join

Reviewed locally on 2026-11-04. The opt-in `cm0_final_join` gate consumes
independently qualified producer hashes for the exact three CM0-family
p2/b0, ordinary-AAPCS, soft/no-FPU/no-MPU cohorts at all five ordinary
optimizations. Four caller-bound receipt/manifest hashes precede captured
parser import. Complete source/dependency, generated configuration,
inventory, six resolved worker, interpreter/tool/DLL and parser coverage
is mandatory. Exact ordered compile and twin-link commands bind target,
mode, source, provider objects, dependency output, script, map and emit flag.
The executed shared-helper buffer is bound to its later captured hash.

There are three native and five reference roots, not a falsely symmetric
three-root comparison. Native owns all three in its index-3 runtime object.
Reference C owns `vPortSVCHandler_C`; its separate assembly object owns
first-start, SVC dispatch, first-restore and PendSV. The fixed ownership
adapter routes only these five roots. The same actual owning objects feed
the eight-body source-derived protocol checker and relocation-aware final
readers; final map/provider origins, complete sections, pools, padding and
applied references remain independent evidence. Token-body and raw-byte
hashes are not conflated. Only twins within one implementation must match.

The three mechanism assignments and their captured immutable ledger IDs
are exact. In particular, reference first restore loads EXC_RETURN into r2,
writes CONTROL=2 and skips initial r4-r11 slots, while native restores the
complete nine-word staged software frame. `FAP-CM0-STAGED-FRAME` preserves
that difference; initial register-value equivalence is not claimed. The
reference C dispatcher and its assertion loop are real, not stubbed away.
BASEPRI is inapplicable; PRIMASK, scheduler-policy, validation and provenance
differences remain explicit. CPU/VTOR/mode identity is not inferred from
potentially identical instruction bytes.

The fresh native fifteen-case sweep passes 135 TUs, 30 direct final links,
105 object checkpoints and 1,095 builder commands. Its reader passes 45
roots, 7,758 bytes, 3,054 instructions, 195 references and 195 actual ELF
mutant applications, with 176 pure reader controls per case. All 12,300
artifact entries and 8,100 original/captured input bindings close. A
separate fresh native build-envelope run passes 53 controls.

The first contract run retained FAIL: five subtests exposed acceptance of
an extra actual compiler override after the recorded flag prefix. Actual
command matching now requires the full exact dependency/source/object tail.
The second contract run passes all 27 controls. The first actual O0 smoke
retains FAIL because the new check expected emit-relocs after the map flag,
where both real producers place it before the map. The expected full recipe
was corrected, not the ELFs. Smoke E2 retains FAIL because the metadata
validator counted Git `-c` configuration options as compiler calls. Compiler
identity now comes from the bound source commands; separate Git/mixed-tool
and extra-compile controls cover it. E3 passes the complete actual O0 join.
These are proof-code corrections, not runtime defects or relaxed root checks.

The complete join sweep passes all fifteen cases: 120 roots/bodies,
45 mechanisms, 10,344 bytes, 4,182 instructions and 270 applied references.
Four actual CLI negatives reject cross-profile, cross-mode, wrong receipt
hash and wrong artifact-manifest hash for the intended reasons; wrong
hashes reject before parser import. Seventy-one pure controls pass across
22 admission, 27 contract and 22 helper methods. The actual-admission mode
adds two methods: thirty authenticated producer receipt buffers pass and
ninety in-memory metadata mutations reject. These are not additional real
ELF mutations. The sweep executes twenty Python children and zero Arm tools.

Review distinguished the child joins' authentication-before-import proof
from the preliminary aggregate parent, which selected its first parser
before explicitly applying the grid-bound manifest hash. That aggregate
does not establish the stronger parent ordering. A separate fresh parent
audit applies all four first-case receipt/manifest hashes before parser
import, then independently replays all thirty producer groups and fifteen
eight-body joins. It closes the generated expected-case JSON and all pure
control source hashes, reproduces all four intended negative reasons and
the same root/twin/protocol totals, and seals 26,409 watched files without
detected drift. Its own auditor source is captured and watched too. Read-only
cross-reviews find no remaining confirmed blocker in this bounded gate.

Before commit, whitespace checking found two extra LF bytes at the end of
`join.py`. They were removed without changing any preceding byte; the E1
captured source remains retained. Rather than substituting a new hash into
the old execution record, the complete fifteen-case sweep and independent
parent replay are repeated as E2. Contract E4 and helper E3 pass against
the final source; unchanged admission controls still pass. E2 reproduces
the same 120 roots, 45 mechanisms and byte/instruction/reference totals,
four CLI negatives and thirty-receipt/ninety-mutation admission controls.
Its aggregate now also authenticates the four initial hashes before parser
import and watches the control source hashes directly. The independent E2
parent again closes 26,409 files without drift. Final staged whitespace
and ASCII checks pass; this is the source used by the commit.

| Retained Record | SHA-256 |
| --- | --- |
| `C:/fzfinal-native-cm0-join-grid-20261104-e1/results.json` | `EC120B4B47DC1FC328316DFB62182DCB033B8691621E5C47BC48EB5F19554F94` |
| `C:/fzfinal-native-cm0-join-grid-driver-20261104-e1/driver.py` | `7AC00BC148CF2211D16E4833F9C1C8C43E5968EEA0938D191CACE42C588FC389` |
| `%TEMP%/cm0-native-join-envelope-20261104-e1.json` | `7CD753F814DC106A51C9E1FD9EEB257223C9BDA6BEDCE3AB2D2EE3E44B814D10` |
| `%TEMP%/cm0-final-join-contract-20261104-e1.json` | `DE55A4D66C72C0C2E04EE771856C48F9010B315C932A1B722A3B577DB2EB0F96` |
| `%TEMP%/cm0-final-join-contract-20261104-e2.json` | `C9E7045E7C10884FED79552FE5D1DDC758A66B49E968333A6FEABE901CCD299D` |
| `%TEMP%/cm0-final-join-admission-20261104-e2.json` | `950D2DB8C4597ED6102C3E6FAF2D4A4119BF7FC595A4DE08E565B1A88D576216` |
| `%TEMP%/cm0-final-join-helper-20261104-e1.json` | `A2E0012D4EE5BAAFA1B438C8F62344AD3B49038D97EDBC191D5AAEF313908E34` |
| `C:/fzfinal-cm0-join-smoke-20261104-e1/results.json` | `2B7FBC70B93A65F3217C694E639D0BA0C4991CCF03B32C92730FC14956D9D783` |
| `C:/fzfinal-cm0-join-smoke-20261104-e2/results.json` | `8E6BB869313A44D8CA1976EFF2B88D39E75991926DF78D55797EE764FF001212` |
| `C:/fzfinal-cm0-join-smoke-20261104-e3/results.json` | `78C0B00BA5B5790815484039C64513A5B1C58ED69D15C67F7A9CD111EB047129` |
| `C:/fzfinal-cm0-join-grid-20261104-e1/results.json` | `1C5AA6EE7DCF9B45D252F8C9102ACCAFDC61140BC5CDAE0EF8C2FF7FDB26D60C` |
| `C:/fzfinal-cm0-join-grid-driver-20261104-e1/driver.py` | `B685935D96DB10E55F002064E21A87494B88EF2546BAAF921169084270DF8705` |
| `C:/fzfinal-cm0-join-parent-review-20261104-e1/results.json` | `D6A7AC783613BE831EB5A6A2EA27677C50187832F4B28653C8DA3C9ED021035C` |
| `C:/fzfinal-cm0-join-parent-review-20261104-e1-driver/audit.py` | `22345C8FD8EB3CE239D4E8B4E8776D3AECCFE40E6C6F9DE326149FA941DB07EE` |
| `C:/fzfinal-cm0-join-grid-20261104-e1/CM0-O0/inputs/0057-join.py` | `5CB688A377E7539CC09BB5583151E74EA814D20107FF95A85907E5979E525FFB` |
| `%TEMP%/cm0-final-join-contract-20261104-e4.json` | `B27873B8F0966FEB814F8CD3D0183A51F14D22560583E685A465990118A0F416` |
| `%TEMP%/cm0-final-join-helper-20261104-e3.json` | `E0050AE5A4BCBD13C3A47D972627E1C609F515DCD3BF3659E7032B16E7025AD9` |
| `C:/fzfinal-cm0-join-grid-20261104-e2/results.json` | `9E9B8245E2354CF699743C90F478D9264789D733F8A6586633389FEFD9AD6C35` |
| `C:/fzfinal-cm0-join-grid-driver-20261104-e2/driver.py` | `820BEEA4A062B988590AC8A429E0BE2AEA5720A67FD83535D4F5300B5BA58EA0` |
| `C:/fzfinal-cm0-join-parent-review-20261104-e2/results.json` | `755E0C705A3D71B1C68E67BE6E6A7EB997E2A33DA0239112444524646B1A25D5` |
| `C:/fzfinal-cm0-join-parent-review-20261104-e2-driver/audit.py` | `2CC1E89028FA9D59BCEEAB8C63D478F0CBC7C53BE57C8CBA02B3FEDD3A5B01CD` |
| `tools/fixtures/cm0_final_join/join.py` | `88EBCDB9F8E12670F2FEC199011FA764DCAA4BEDC8F71516D4CD1BD57CF57ACD` |
| `tools/fixtures/cm0_final_join/admission.py` | `3F0A400183195102B98543A519CAC2D6D86414A1B5411760EB75F19F94CDE81E` |
| `tools/fixtures/cm0_final_join/test_admission.py` | `63077878C18D322106FF838E468C8C66027847657C8C7D8FD20D409054EC9425` |
| `tools/fixtures/cm0_final_join/test_contract.py` | `D6666705C71C57E297C77FB63E15E80120C767D8431D446525F5DB190D01811D` |
| `tools/fixtures/cm0_final_join/test_join.py` | `FF7DEA5DDE773BDD89EF4A0210F2B8F24B202C94647A22F1CC830CCFD15EAC1A` |

This qualifies bounded final mechanism composition, not semantic equivalence,
constructor/C-callee/kernel closure, successful MMIO or handler routing,
dynamic exception targets, complete objects, other cohorts, archives/final
LTO, CPU/board or global freeze. Required global parity keys stay unsatisfied.
Production runtime/assembly, public/port ABI, feature admission and default
matrix are unchanged. No board is flashed/reset/run. Local receipts are not
hosted exact-commit CI. The protected unrelated WIP remains untouched.

## Native CM3 Final Images At Five Optimizations

Reviewed locally on 2026-11-04. The existing native final-image envelope
adds exactly `cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default`
at O0/Og/O2/Os/O3. CM3 is an explicit helper route, not a fallthrough to
CM4/CM7 FP admission. Its new pure model consumes the authoritative
captured inventory, requires the exact source group, ARMv7-M, VTOR1,
priority bits4, BASEPRI16 and soft/no-FPU/no-MPU target, and rejects extra
or mistyped fields. ELF attributes require 7-M/v7/Microcontroller/Thumb-2
and reject FP/VFP/MVE/PAC/BTI claims, including ABI_HardFP_use.
Final soft-float ABI bits are exactly `0x200`.

The source order remains three Context units, three concrete selected-port
units, the application-owned cohort expectation, application and startup.
All three roots belong to index-3 `fiber_port.c`; boot and exception code
retain their separate providers. The source-derived CM3 checker remains
unchanged. The final reader and shared instruction decoder also remain
unchanged: this is not an allowlist expansion to admit unrelated C opcodes.
O0 has exactly one in-symbol tail NOP per transfer root, other modes zero;
following section padding is not absorbed into function `st_size`.

The parent executes 65 build-envelope controls, including twelve new CM3
methods, and twenty exact-manifest/attribute controls. Both suites pass
without failures/errors/skips. The admission run authenticates the retained
E8 inventory manifest before parsing it. The envelope receipt itself does
not claim to contain source hashes; the parent separately checks the
executed builder/test bytes before and after qualification.

A real CM3/O2 smoke compiles and links successfully. The unchanged final
reader passes 176 pure controls, three roots, 492 bytes, 170 instructions,
thirteen applied references and thirteen actual retained ELF mutants.
Eleven THM_CALL references preserve original addend -4 and two current-slot
ABS32 references preserve addend zero. The native frame still stores its
per-context EXC_RETURN; no comparison with reference first restore is
inferred from this native-only result.

The fresh grid contains exactly fifteen independent cases: CM3's five
ordinary modes and O0/O2 regressions for CM0, CM0PLUS, CM0PLUSVTOR, CM4 and
CM7. It passes 135 actual TUs, thirty direct final links, 105 ordered
object checkpoints and 1,095 builder commands. Thirty Python children are
separate from those builder commands. The actual final readers pass 45
roots, 7,976 root bytes, 2,900 instructions, 199 applied references and
195 retained ELF mutation applications. CM3 contributes 45 TUs, ten links,
fifteen roots, 2,466 bytes, 853 instructions, 65 references and 65 mutants.
Each case runs the same 176 pure controls, not 2,640 distinct test methods.
All 12,292 artifact entries and 8,092 original/captured input bindings close;
these are aggregate records, not counts of globally unique files.

The first independent parent audit retains FAIL after the six CM0-family
cases: it incorrectly applied the C hard-FP VFP_args requirement to the
CM4 assembler startup object. The real producer's strict admission scope
is the port object and both final images. A fresh E2 auditor matches that
scope; all nine attribute files are still hash-bound and every compile
command retains its exact CPU/ABI flags. No producer, ELF, protocol or
runtime source changes were made for this auditor correction.

E2 authenticates the grid and all grid-bound producer receipt/manifest
buffers before captured parser import, independently reproduces all
own-prelink protocols, positive final roots and load-image twins, and
checks exact reader-directory membership. Each reader has 79 files:
results, thirteen witness captures and 65 actual mutant files. All 1,185
reader files are accounted for; all 975 mutant-file hashes close. The
replay seals 14,073 watched files without drift. Pure controls and actual
mutant rejection outcomes are authenticated retained evidence, explicitly
not reexecuted by this independent audit. The original grid executed them.
The auditor's own source is captured and watched too.

| Retained Record | SHA-256 |
| --- | --- |
| `%TEMP%/cm3-native-envelope-20261104-e1.json` | `326755364A125B3100F328398E42B242096F91329A9F0E9F5B73F7B33C7695D9` |
| `%TEMP%/cm3-native-admission-20261104-e1.json` | `E069949FB33EA3CE845B2FCC9AC08701A9EADF36B50C57542D148C7EE028053E` |
| `C:/fzfinal-native-cm3-smoke-20261104-e1/results.json` | `3A419DC71861C556FB79A4ED2CD5337CF2F1603791390532C57A3C2C05DFD396` |
| `C:/fzfinal-native-cm3-smoke-reader-20261104-e1/results.json` | `A78419F297FECB7179EF39C5BAE20D523399A82677FBA70020679D2E5CB8D046` |
| `C:/fzfinal-native-cm3-grid-20261104-e1/results.json` | `31FBAD0FC73103C60E013105BAAFBFB8213AB326D1F923092C3FDBA45EBE2AB5` |
| `C:/fzfinal-native-cm3-grid-driver-20261104-e1/driver.py` | `1C1DCC2027E4112E3CD735CAFB39C77081E1A90CD465EC501F2BF87CF390FB55` |
| `C:/fzfinal-native-cm3-parent-review-20261104-e1/results.json` | `E9B0B955DBDD3D47EE7AD5252862029DA8F022C828A65EFB4D5A0AADFA92127B` |
| `C:/fzfinal-native-cm3-parent-review-20261104-e1-driver/audit.py` | `3F9C376C98E00274EBD1CC47FFE44214AD63BE21081E85C7BEC99F95EB1D0B74` |
| `C:/fzfinal-native-cm3-parent-review-20261104-e2/results.json` | `144E009F4CBD0033BA6C61BF632D79E86E0CA92A1631DDA55709D1DE664BE270` |
| `C:/fzfinal-native-cm3-parent-review-20261104-e2-driver/audit.py` | `DFA5FBB07564E2C01A13CE70FA49893B3E50D51E449C504377B58C7F0FECB025` |
| `tools/fixtures/classic_final_image/run.py` | `FBCBA0C4FF480E139ADE401ECFA90822E9EA01A6AB554CEF157036EC9DE7F014` |
| `tools/fixtures/classic_final_image/test_run.py` | `72F9200AA342F8E651E87A0F2410A92340B923F3498E84D875892F677B093C7A` |
| `tools/fixtures/cm3_final_image/admission.py` | `2D1DA1B87129438717666E669B347A0E91F998F5A75BEB961CA9FDDE44F1D87D` |
| `tools/fixtures/cm3_final_image/test_admission.py` | `82379904DBC34778A2286903F8760E1C60B3E772D3042FB1091A1D5F56A43EFC` |

This qualifies bounded native final-image production and root preservation,
not the separate pinned CM3 reference producer or 3+3-root final mechanism
join. The upstream eight-word frame and synthesized EXC_RETURN must remain
explicit differences when those later gates are implemented. General
C/callee/kernel semantics, complete objects, dynamic exception targets,
successful MMIO/handler execution, other cohorts, archives/final LTO and
global freeze remain unproved. Required global counters stay integer zero.
Runtime/assembly, public/port ABI, feature admission and default matrix are
unchanged. No board is flashed/reset/run; local evidence is not hosted
exact-commit CI. The four protected unrelated WIP entries remain untouched.

## Pinned CM3 Reference Final Images At Five Optimizations

Reviewed locally on 2026-11-04. The separate CM3 reference producer admits
only the exact p4/b16, ordinary-AAPCS, VTOR1, soft/no-FPU/no-MPU cohort
already qualified by the native producer. It captures unchanged pinned
`portable/GCC/ARM_CM3/port.c` and `portmacro.h` at
`a50edad08b29052631aa469d4df6e6ec7ff68878`; there is no `portasm.c` and
no separate CM0-style C SVC dispatcher. The actual port object owns the
local `prvPortStartFirstTask` and strong global SVC/PendSV roots. Typed
fail-stop kernel providers, consumer and startup complete exactly four TUs.
No synthetic root replaces an upstream function and no image is executed.

The generated/base config retains enabled inline assertions, shifted
threshold16 for both interrupt APIs, priority bits4 and handler installation
check1. Ten retained header facts are exactly
`(1,4,4,4,8,0,0,16,16,4)`. There are no CMSIS/FP fixture dependencies or
FPCCR policy claims. All original/captured pinned/header/config/system
dependencies, compiler/resolved workers/DLLs, parser and interpreter inputs,
actual compile commands, seven object checkpoints and both final maps are
retained. Full owning-section hashes/mappings/REL records remain distinct
from root symbol extents and token-body hashes.

The parent runs 29 pure producer controls using the authenticated actual
inventory, then a successful real O2 producer smoke. The new independent
fixed reader passes 108 synthetic controls. Its instruction encodings are
source-transcribed, not learned hashes. SVC restores exactly r4-r11 and
uses ORR LR,#13; PendSV saves/restores eight core slots, preserves r3/LR
around its scheduler call and raises BASEPRI16 before clearing it to zero.
The native nine-word EXC_RETURN frame is not silently substituted.

Reader ownership binds exactly four physical provider files and their
actual final map placements. All three roots have the same real port
provider; the callee/current slot have one other shared provider. Exact
input sections are `.text.<root>`, with zero root offset, separate padding
and literal mappings, and unchanged permitted O0 alignment NOPs outside
`st_size`. Original addends are -4 for the PendSV THM_CALL at28 and zero
for SVC ABS32 at32 and PendSV ABS32 at64. Final destinations and symbol
bindings must match independent provider/map origins. Root/section bytes
outside these validated relocation fields are preserved.

Initial witness admission controls pass nineteen methods. Read-only review
then finds two pre-qualification gaps: physical identity was admitted after
output creation, and helper loaders reread files after initial hashing.
Before any actual ELF replay, admission moves before writes and a closed
source-buffer loader is added, also serving nested legacy file-spec imports.
It executes the exact hashed immutable bytes, rejects unknown local source
loads and bypasses local bytecode caches without modifying reader/model
globals. The expanded 24-control suite passes CLI alias/no-write, hard-link,
A-to-B-to-A replacement, nested-buffer, unknown-load and mutable-buffer
negatives. The first nineteen-control receipt remains historical, not
evidence for the final strengthened source. Executed helper-buffer identities
are recorded in every actual witness receipt.

The actual O2 witness passes three roots, 136 bytes, 39 instructions,
three references and thirteen real ELF mutants. A fresh five-mode sweep
then passes twenty TUs, ten direct final links, 35 checkpoints and 355
builder commands. It preserves fifteen roots, 686 bytes, 198 instructions
and fifteen applied references. O0 contributes 142 bytes/42 instructions;
each other mode contributes 136/39. All 65 actual mutation applications
reject at the expected stage/reason: 55 retain equal mutant twins before
root rejection, ten reject twin geometry/permissions. All 325 actual
mutant files are retained. Producer seals contain 3,715 artifact entries
and 2,410 original/captured input bindings; these are aggregate record
counts, not globally unique files. The ten Python builder/witness children
are separate from the 355 recorded builder commands.

Before sealing documentation, the reader contract's implementation-only
history wording is replaced by evergreen evidence boundaries and the actual
witness/loader contract. The reader implementation is unchanged. The 108
synthetic controls are repeated as E2 to bind the final document hash;
the actual producer/witness inputs do not consume that document, so their
unchanged real ELF receipts are not relabelled as rerun builds.

The fresh independent parent replay authenticates the caller-bound expected
table and all twenty case receipt/manifest buffers before parser import.
Exact ordered compile/link recipes, inventory/pin/blob/newline bindings,
generated configuration, full consumed/tool/worker/DLL/parser inputs and
producer imported-module origins are checked. All five parser artifact
dictionaries are identical before the first captured parser is imported.
The same actual port objects feed independent prelink-protocol/owning-section
and final structural replays, then all fifteen fixed final roots and twins.
The local helper closure executes bound source buffers, not substituted
models or patched protocol globals.

Each actual reader has exactly 74 files: results, eight witness captures
and 65 mutant files. The audit closes all 370 reader files, including all
325 mutant-file hashes, and authenticates the separate 29/108/24 pure
receipts and their exact source memberships. Pure tests and mutant rejection
outcomes are retained evidence, explicitly not reexecuted by this auditor.
It captures its own source and seals 4,589 watched files without drift;
the first executed reference parent audit passes. Read-only cross-reviews
find no confirmed reader/witness blocker.

| Retained Record | SHA-256 |
| --- | --- |
| `%TEMP%/cm3-reference-envelope-20261104-e1.json` | `D2D55022E281D377F369D030B249AEB0EDCD4EEACFF2AF23D9D285C30AE7A8E7` |
| `C:/fzfinal-cm3-reference-smoke-20261104-e1/results.json` | `22C89793885F4A92399927DB5B1E893455C09B3F8A14DF7269715E7B2AA2DC17` |
| `C:/fzfinal-cm3-reference-reader-pure-20261104-e1/results.json` | `592C20F6B2782CE70E57ABD0FF0EFB1BCFAC31CC51879C827B651DF0CB9B7702` |
| `C:/fzfinal-cm3-reference-reader-pure-20261104-e2/results.json` | `C9EF2F48614965F36AB336E986AF7ECE4E8FFC4B9404094929F6FB5AC6A45871` |
| `%TEMP%/cm3-final-witness-pure-20261104-e1.json` | `131EA6FB5C3773B05CAD6FA31ACAF81DF1F6406B37C6704B97B9F90478D5FC59` |
| `%TEMP%/cm3-final-witness-pure-20261104-e2.json` | `DE435318D89F00B0F74311DC820943B9223308F94A0270DFD76901E164D26D46` |
| `C:/fzfinal-cm3-reference-root-smoke-20261104-e1/results.json` | `B0367F77A3AFD5275E8E975D26DFF2AF07F0C432057327A930FB0D6FACEF8AE6` |
| `C:/fzfinal-cm3-reference-grid-20261104-e1/expected-e2.json` | `DE9B79BAEFEBCA07490E839F1FDE46C47901B49427316FB0BC741997864C3B58` |
| `C:/fzfinal-cm3-reference-parent-review-20261104-e1/results.json` | `87D81D804F6C1EFEEDF0D9ECF86AE965CE8E580E90C70744813A23983832B9C3` |
| `C:/fzfinal-cm3-reference-parent-review-20261104-e1-driver/audit.py` | `AC670F2EEA9A37D168AFAD27B13979EE738DA6C2D6284A54C417EB194085FF68` |
| `tools/fixtures/cm3_final_image/reference_run.py` | `0091CA8ECCEE8B34C25B290BEE46C0BE3A3BF0656B2689EC664EF15F35776CBA` |
| `tools/fixtures/cm3_final_image/test_reference_run.py` | `5652F906CAFF27FE249C8B86BB14FB4E14D358A16CC4121027E8579C1C588813` |
| `tools/fixtures/cm3_final_roots/reference_elf.py` | `1F62F514EE90F1A0051F4C6028FE8AA74134A66573C64CFD88FB7BCA9DE80F28` |
| `tools/fixtures/cm3_final_roots/test_reference_elf.py` | `12D014EC6975A4874DDC1348D1B56B720A657BD4D925ECCA6D11C28BAE2E1922` |
| `tools/fixtures/cm3_final_roots/reference_witness.py` | `AED0DBAC11EB8644EED71F9FAF36C67B2854DE19262A78CC7EA601FA7A3DD99C` |
| `tools/fixtures/cm3_final_roots/test_reference_witness.py` | `ADB04836FA5BF8963447396F238B07C87F0D453DFCB4D8FFCE9B562F83334E98` |

This qualifies bounded reference producer/root preservation, not the separate
native/reference CM3 final mechanism join. General C/callee/kernel semantics,
successful MMIO/vector/handler execution, dynamic EXC_RETURN values, complete
objects, other cohorts, archives/final LTO, CPU/board and global freeze remain
unproved. Required global counters stay integer zero. No production runtime,
assembly, public/port ABI, feature admission or default matrix changes. No
board is flashed/reset/run. Local evidence is not hosted exact-commit CI.
The four protected unrelated WIP entries remain untouched.

## CM3 Final Mechanism Composition At Five Optimizations

Qualified locally on 2026-11-05. The opt-in `cm3_final_join` gate admits only
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default` at the five
ordinary modes O0/Og/O2/Os/O3. It composes the preceding native and pinned
reference producer/root checkpoints; it neither rebuilds their images nor
extends the target or proof scope. The native source group has nine TUs;
the reference group has four, with actual pinned `ARM_CM3/port.c` owning all
three reference roots. The same two owning prelinks feed the complete
canonical protocol checker and their respective unchanged final readers.

The fixed six-root/three-mechanism mapping preserves the existing IDs
`FAP-COMMON-START`, `FAP-COMMON-PROVENANCE`, `FAP-COMMON-SCHEDULER`,
`FAP-COMMON-MASK-RESTORE`, `FAP-CM3-EXC-RETURN` and
`FAP-CM3-LOCAL-LITERAL-POOLS`. Every ID must have one nonempty rationale in
the admitted inventory's captured ledger. Native's nine-word core frame and
reference's eight-word/ORR-LR-13 frame remain different contracts. Ordinary
instructions, local pools, original REL addends, full owning-section extents,
provider identities and applied final bytes are not normalized away.

Both caller-bound results hashes and both artifact-manifest hashes close
before any parser import. CLI `prepare_output` additionally authenticates
the four buffers and manifest-bound `inputs.json` before `mkdir`, computes
denied output roots from those same buffers and closes them before returning.
It denies original/reference/config/tool/inventory input trees. Invalid
pre-output hashes or overlapping outputs create no directory; the outer
driver retains their failure evidence. Later replay/closure failures retain
sealed FAIL receipts. The three-argument synthetic output helper is only a
conservative declaration-based deny gate, never CLI admission authority.

Source review closed four confirmed proof-level gaps: heading-only rationale
admission, missing cross-implementation physical-alias rejection, missing
base-config original-provider identity, and output overlap with original
input trees. The final source executes authenticated immutable local helper
buffers, including nested loaders. It replays complete source/dependency,
generated config/recipe, pinned Git blob, command, worker/DLL, parser,
inventory and source-ownership bindings. Closing validation observes real
files after the buffered helper-read scope ends. No protocol/model globals
are patched and no target, compiler or child process is executed by the join.

Final results are PASS:

- Five actual native/reference pairs plus separate full replay of each pair.
- Six roots and three mechanisms per pair: 30 roots/bodies, 15 mechanisms,
  3152 raw root bytes, 1051 instructions and 80 applied references in total.
- 10760 closing-file observations in the five joins and 12250 in their five
  parent replays; these are per-run observations, not distinct global files.
- Four actual CLI negatives: wrong profile/mode produce sealed FAIL before
  replay; wrong receipt/manifest hashes reject before output creation.
- 25 pure admission, 40 pure contract and 16 pure closure/seal controls.
  The separate 27-control actual admission run reuses the 25 pure controls
  and adds ten authenticated receipt buffers plus thirty metadata mutations.
- Fifteen host-interpreter commands in the final sweep: one actual admission
  suite, five joins, five parent replays and four negatives. No Arm execution.

Parent replay checks protocol/root/twin/owner records, rationale text and hash
domains, executed source buffers, original/captured inputs, exact output
membership and all output hashes. Tuple/list values are compared in their
JSON receipt representation. It re-executes the fixed readers, not a second
independent ELF model. Prior producer ELF mutation evidence remains separate
and was not re-executed by this join checkpoint.

Retained failed attempts are not relabeled. The 2026-11-04 seal E1 failure
was a parent-test mistake: an already-failed receipt can have a valid output
seal without becoming PASS. Corrected E2 passes. Sweep E1 stopped at parent
tuple-versus-JSON-list comparison after actual O0 success. Sweep E2 passed
all five pairs/replays but stopped because the driver's expected cross-profile
diagnostic differed from the earlier helper-closure rejection. Final source
now rejects profile/mode explicitly before helper selection and includes the
authenticated output-isolation fix. The complete 2026-11-05 sweep reruns all
five pairs/replays and negatives against that final source.

| Evidence Or Source | SHA256 |
| --- | --- |
| `%TEMP%/cm3-final-join-admission-20261104-e1.json` | `BBE21A5390ABBF3F3DDE55E942A138A688F381364D53A1E75E7187B04E4A8954` |
| `%TEMP%/cm3-final-join-contract-20261105-e1.json` | `BAA2C41C662335B9114A295B244B17BB18D1287B3129254DC982A926E8B57AF3` |
| `%TEMP%/cm3-final-join-seal-20261104-e1.json` | `ADE75265678181847ADDF0E9C3C04D21D795FD7A3E3AF6FA6EA92190C9249977` |
| `%TEMP%/cm3-final-join-seal-20261104-e2.json` | `B1CFF4F8F548FBE9A1DD67E28AA02F2C21A30E2EB82AF5CD4D4C7B78F1446993` |
| `%TEMP%/cm3-final-join-seal-20261105-e1.json` | `E9F9969B11B8E64D7520BBAD3DCC9FEF918769FE6E198F987FD36527D301A867` |
| `C:/fzfinal-cm3-join-grid-20261104-e1/results.json` | `FAE36393038AE1B1D727D7357E82BBF7F16B92DF707872C4C102DF15E72AAD22` |
| `C:/fzfinal-cm3-join-grid-driver-20261104-e1/driver.py` | `9F0583FFB2D1BD0AE6769CE5F0D5B92FA622604C747A086CE23DF9CB8924CE76` |
| `C:/fzfinal-cm3-join-grid-20261104-e2/results.json` | `8735562681DA1484E7AD1FBFA24B95874407F2FA64AA8E52D635D8B6FC20FC5E` |
| `C:/fzfinal-cm3-join-grid-driver-20261104-e2/driver.py` | `FDFA172D6414A82AA90BE55329E922B9900030C1C6EFC010B5E898AEE149A0A7` |
| `C:/fzfinal-cm3-join-grid-20261105-e1/results.json` | `1CCECCAE70F9116D26BFDE86045D9718B732B696E0FEE69C623B6C11934EE54A` |
| `C:/fzfinal-cm3-join-grid-driver-20261105-e1/driver.py` | `785E7022CD9259E4A100C2404811D8CBB14CCEEB20C698986B2F435C3FFA8D0F` |
| `C:/fzfinal-cm3-join-grid-20261105-e1/actual-admission-controls.json` | `6A2C18A6F645DC75330BF14798A11BACBCD3930154BAA9F122BE07C20E0FD456` |
| `tools/fixtures/cm3_final_join/join.py` | `E53CDD177EF04124B766AD54301D58AA2B73D0C67AE9FBA43C979DC557C5A012` |
| `tools/fixtures/cm3_final_join/admission.py` | `D3E4DF449B91218BC7EF7C479B9665F2ACD861A9CB815DDA193ECFF2AFBDDFE1` |
| `tools/fixtures/cm3_final_join/test_admission.py` | `679C04E91F4EADDCB7E29DE87BF7C40CA7243C3A7973C374D4937E5420EB9107` |
| `tools/fixtures/cm3_final_join/test_contract.py` | `CE314D6F3FEDA7329E13995968C68F50995B0F5F317FB4D08170048AB640B653` |
| `tools/fixtures/cm3_final_join/test_join.py` | `C9DE9E3544830223B9ED3664015E33B848B459BF1A873DF0C1938365D4ED4EE3` |
| `tools/fixtures/cm3_final_join/CONTRACT.md` | `95EE87A6DC31B1B9EAEAC0B5A6BDF3E6EAFA973FAF02CA6D0708DC22DEA79F24` |
| `tools/fixtures/cm3_final_join/POLICY_DIFFERENCES.md` | `778B098F80EAE5EE641B323B4F8D60441C2F725921B506AEDA90B487D3EB5019` |

This closes bounded CM3 ordinary final-mechanism composition only. General
C/callee/kernel semantics, other cohorts, full ABI obligations, archive routes,
genuine final LTO, actual MMIO/exception execution, CPU/board qualification,
hosted exact-SHA CI and global software freeze remain outstanding. Required
global counters remain integer zero. The next bounded gate is CM3 genuine
direct final-LTO machine-owner/provenance transport, initially O2-lto, without
weakening the frozen ordinary reader. No production runtime/assembly, ABI,
feature admission, default matrix, firmware or board changes. Protected
unrelated WIP entries remain untouched.

## CM3 Slim-LTO Capture Transport

This opt-in slice is limited to the fixed native
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default` at O2-lto,
direct linkage and one explicit LTO partition. It uses the independently
qualified native ordinary-O2 producer as source/configuration authority, not
an arbitrary current checkout or an existing native object as a substitute
for newly generated IR. Caller SHA256 values authenticate the seed receipt and
complete artifact manifest before output creation or helper execution.

The probe rebuilds the same ordered eight C TUs as slim GIMPLE objects and the
same startup assembly TU as native code. It denies executable fat fallback.
The two final links independently invoke actual LTO on those nine inputs in
separate directories. The second link adds `--emit-relocs`; it does not relink
the first link's saved machine object. Captured compiler/worker/plugin/DLL
inputs, the sanitized contained process runner and private temporary files
remain part of the exact closing evidence.

The GCC driver and linker plugin have distinct temporary-file retention
policies. A preliminary external layout sketch without explicit plugin
retention lost the real machine object. Adding
`-Wl,-plugin-opt=-save-temps` retained it. The probe therefore requires that
explicit option alongside driver `-save-temps=obj`. The WPA partition
`image.elf.ltrans0.o` is IR and is never admitted as machine authority.
Only the actual saved `image.elf.ltrans0.ltrans.o` can serve that role.
No assembler reconstruction or separate LTRANS replay substitutes for it.

Transport capture retains raw plugin resolution and response records, actual
worker invocations, generated assembly, complete post-LTO machine objects,
final ELFs, full link maps and inspection output. Symbol observations preserve
their real binding/type/section/value/size rather than imposing the ordinary
non-LTO global/weak predicates. This is not per-original-TU provenance or a
claim that all machine definitions were individually placed and verified.

The first actual probe attempt, E1, retained two real machine objects and
closed its output seal, but did not yet compare twin load images. Review also
found permissive unmatched section-row handling and missing explicit
ELF32/little-endian admission. E1 is preserved as historical capture evidence,
not qualification of the corrected contract. The first pure test attempt had
three synthetic-fixture errors because its admitted seed omitted `Sources`;
those fixtures were completed without weakening seed admission.

Final E3 capture feasibility qualified locally on 2026-11-05:

- Nine actual TUs: eight slim IR inputs and one native startup input.
- Two independently executed direct LTO links and two retained ARM ELF32-LE
  machine objects. Both machine files hash to
  `D8659F1E94949D4F2411F6334FF24A12CF016304BE03AAE96EF4C3156A3E6516`.
- Fifty-seven contained tool commands; complete object and dependency closure.
- The unchanged twin reader compares load geometry/bytes, entry/flags,
  allocated sections and vector bytes. Its parser executes authenticated
  captured buffers; physical closing checks run outside buffered-read hooks.
- 1463 sealed artifacts and 1401 watched-file closing observations, independently
  rehashed by the parent control driver. Eight machine symbol facts per link
  preserve actual bindings, including the local four-byte current slot.
- Seventy-nine pure controls pass, including pre-initial-seal twin-file
  change/deletion, fixed path/hash/value binding, late seal failures, complete
  section-row inventory and raw ELF class/endian controls. Mocked envelopes
  are not compiler, ELF-provenance or execution evidence.
- Four actual CLI negatives pass: wrong receipt hash, wrong manifest hash,
  seed-overlapping output and repository-overlapping output. All reject before
  output creation. Seed receipts and the complete positive capture stay unchanged.

E2 had already passed actual builds, twins and parent controls, but final review
found that the saved `load-image.json` could be changed or deleted before the
first seal without a source guard. E3 binds its fixed path, raw SHA256 and
parsed receipt value in closing checks before PASS and again after sealing.
The earlier files are not alleged to be corrupted and are not relabeled as
qualification of that guard. The parent control driver also had one pre-output
failure while hashing a Windows App Execution Alias from `sys.executable`.
Its retained wrapper resolves the actual interpreter through
`GetModuleFileNameW`; it does not change child probe code or target artifacts.

The fixed canonical argv excludes caller-supplied plugin-bypass options.
Verbose tool-path membership is checked, while complete worker/response
argument semantics and per-TU IR-to-machine source mapping are not proved.
This distinction is normative capture scope, not a relaxed final-root rule.

| Evidence Or Source | SHA256 |
| --- | --- |
| `tools/fixtures/cm3_lto_transport/probe.py` | `F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626` |
| `tools/fixtures/cm3_lto_transport/test_probe.py` | `2405CCB522F851D73992906ED8B63E69F2ECCAD642D9DC9DCE9922F274AAF3F2` |
| `tools/fixtures/cm3_lto_transport/CONTRACT.md` | `DCB904F5A73C09187E2AABDCDE8E7459B233270A014A05A6CA60BFDF092F1DF4` |
| `%TEMP%/cm3-lto-transport-pure-20261105-e1.json` | `32A8EBF143B0CBBE51BBB39E7AD844D59B58A182A7834282BFD19E270D5DA127` |
| `%TEMP%/cm3-lto-transport-pure-20261105-e2.json` | `AA30C0632D560DAF5B5870DA06101DEEC3B8D1CCEC21D2198F92F5AB8F4DF184` |
| `%TEMP%/cm3-lto-transport-pure-20261105-e3.json` | `6FDA6CA2EF25ED80AECED2EBBC972226621C5DBA05487E25DDC32E94D34C0970` |
| `%TEMP%/cm3-lto-transport-pure-20261105-e4.json` | `DAD304A15F02BB760D4629B2A0BC5DA4FB39D682E8CCE965A92C495FAB59E9D5` |
| `C:/fz-cm3-lto-layout-sketch-20261105-e1/results.json` | `40B4E83CBA5CC3DF66E4EE99C795D477205AFD565F2D6B5232FCE86D9051B47F` |
| `C:/fz-cm3-lto-layout-sketch-20261105-e2/results.json` | `FB83705A1EBE251DAAE00588B9A6A526644E9086BF5722D26A444C526F005619` |
| `C:/fz-cm3-lto-transport-20261105-e1/results.json` | `0D6A993A4C2D482C9F4D02BF1E9C19DED4FA6EA402BFCD10426A48549363EF80` |
| `C:/fz-cm3-lto-transport-20261105-e1/artifacts.json` | `4BFF2D6520ED79078880B06AEEA4DFBD6383B565A1E0B4ECE1EDAF017C62F275` |
| `C:/fz-cm3-lto-transport-20261105-e2/results.json` | `48A405EF189FF4619BEA85F7B5E2594E14A5B35CF51CC6E5B9A6CAD7AF402B7E` |
| `C:/fz-cm3-lto-transport-20261105-e2/artifacts.json` | `E529C40217B39BC53AA603597F03F5E57E399A298B3B3F9FCD4EC6BA142D15B4` |
| `C:/fz-cm3-lto-transport-20261105-e3/results.json` | `88862AC7C665BAB91D52248ECBF0D407B19FE198C75DA9758ED0507D9B6F864C` |
| `C:/fz-cm3-lto-transport-20261105-e3/artifacts.json` | `4B6A8F6E316188DF788E3A309473592BFC77EC44FDE06247CCA624845F29ED66` |
| `C:/fz-cm3-lto-transport-20261105-e3/load-image.json` | `7E15E2C4C89B237D38FF444338256677D19DF5BF5241A7E4E9BFB9E9293EB077` |
| `C:/fz-cm3-lto-transport-controls-driver-20261105-e1/driver.py` | `473B054C0E5723E0263A628C34764E64DA4C9E12963FAF27799253F56CA4ED42` |
| `C:/fz-cm3-lto-transport-controls-driver-20261105-e1/initial-driver-failure.json` | `C33F0D209F4C9653A9FF52B81184FF69DA56871AA5F6642A59B9F50F028B96DA` |
| `C:/fz-cm3-lto-transport-controls-driver-20261105-e2/driver.py` | `4D66B2433457F05262A757FA77EE7BD00568F9DB2F7EEE958AE70A8B7BD50739` |
| `C:/fz-cm3-lto-transport-controls-20261105-e2/results.json` | `C4F10A057F062DBEE3515968FCE5C1F5CF9354A52A74D2CD16BA488E9D177D86` |
| `C:/fz-cm3-lto-transport-controls-20261105-e3/results.json` | `B754A3407D87080B89516AEF568016F3EF8D993CF0BB316766C786102F59E515` |
| `C:/fz-cm3-lto-transport-controls-20261105-e3/parent-driver-context.json` | `3E746E2462F1C52A779524866350D7B7F9C5446C07628DD71DDBB5EB86C49848` |

The next final-root adapter must remain separate from the frozen ordinary
reader. The observed native roots retain eleven named THM_CALL references and
two current-slot ABS32 references; no generic unrelocated-call exception is
needed. The named slot is a local object in a dedicated section, and the
machine ABS32 records address that section. The adapter must prove the exact
section/offset relationship through the complete machine-section placement,
then validate original addends and final applied bytes. It must retain every
root instruction, mapping boundary and literal/padding byte, not normalize
away the LTO difference or claim original nine-TU machine ownership.

This is capture/build feasibility only. Native/reference mechanism joins,
full post-LTO ABI/override/cohort proofs, final-root relocation preservation,
other modes/cohorts, archives, CPU/board validation, hosted exact-SHA CI and
global software freeze remain outstanding. Required global counters remain
typed integer zero. No production runtime, assembly, ABI, feature admission,
default matrix or hardware changes. Protected unrelated WIP remains untouched.

## CM3 LTO Machine-To-Final Root Witness

The opt-in `tools/fixtures/cm3_lto_roots/` adapter consumes the authenticated
E3 slim-LTO capture above, without rebuilding it or changing the frozen ordinary
reader. Scope is exactly native CM3 p4/BASEPRI16, soft/no-FPU, O2-lto, direct
linkage and one LTO partition. It is machine-root preservation, not a canonical
protocol, source-to-machine, complete-ABI or FreeRTOS LTO equivalence claim.

The final E7 actual witness passed locally on 2026-11-05:

- Three complete roots: SVC 184 bytes/64 instructions, PendSV 204/72 and
  first-start 104/34; total 492 bytes, 170 instructions and 13 references.
- All eleven THM_CALL sites retain original addend -4 and resolve to exact
  callee entries independently bound to full machine-section map placements.
- Both ABS32 sites retain original addend zero. Raw STT_SECTION names are
  empty, not readelf's displayed section labels. Their dedicated four-byte
  local slot maps to output BSS offset `0x480`; the applied words must resolve
  to that exact object, not merely another plausible BSS address.
- Complete non-relocation bytes, mapping boundaries, literal/padding bytes,
  executable load permissions, Thumb entries, positive symbol extents and
  cross-name function/object overlap controls remain mandatory.
- Six distinct positive file roles are manifest-bound and consumed from
  immutable buffers. All 16 actual private ELF/map mutants reject at their
  declared guards. Their five input hashes are bound before parsing and
  physically closed afterwards; coherent callee/slot projections are checked
  from the exact parsed buffers before the origin guard is exercised.
- Those two coherent cases are origin-guard controls, not fully coherent
  protocol/twin mutations: their disassembly is deliberately unchanged and
  origin must reject them first. No stronger mutation claim is made.
- The unchanged twin reader separately checks ordinary/emit-relocs load
  geometry/bytes, entry, allocated sections and vectors.
- The parent independently verifies all 251 predetermined output artifacts,
  all 3081 watched input hashes, six positive roles, 16 private cases and
  absence of unexpected/missing output members.
- Thirty-one pure adapter controls and 33 pure witness-envelope controls pass.
  Pure controls are not actual ELF or tool execution evidence.
- Four real CLI negatives reject before output creation: wrong capture
  receipt, wrong manifest, repository overlap and capture overlap. No compiler,
  firmware, emulator, target or board was executed by the witness/controls.

Historical attempts remain separate. E1 lacked actual mutants; E2 added them.
E3 added coherent projections and actual interpreter identity; E4 bound positive
and private immutable inputs; E5 added predetermined output membership. Review
and the first pure envelope run then reproduced one manifest-value gap: a
write-time replacement JSON dictionary could be hashed without comparison to
the intended artifact dictionary. The final implementation parses the written
manifest with unique-key enforcement and compares its value before sealing.
E6 and pure E2 cover that guard; earlier receipts are not relabeled. Final review
then found a resolve-then-disk-fallback buffer lookup that could consume transient
unbound bytes during a symlink/junction retarget. E7 uses stable lexical keys:
immutable source/positive buffers always win, and only the exact 80 declared
private mutation files may be read live during their construction. Each private
reader then admits only its five snapshots, without any disk fallback. Unknown
paths reject. Five new callback controls cover this boundary; physical closure
runs after unpatching. No retarget is alleged to have occurred in E6. The first
parent CLI driver expected the wrong diagnostic text, failed its own assertion,
and is preserved; its second wrapper corrects parent-only expected text without
changing the witness, inputs or target files.

| Evidence Or Source | SHA256 |
| --- | --- |
| `tools/fixtures/cm3_lto_roots/native.py` | `D4BA0378FA50E11A570D40180149794B16EB0807E36DC902C19840E32D1AF05D` |
| `tools/fixtures/cm3_lto_roots/witness.py` | `5BFA66061B9BFAC9B7C6AF872AB831E69613DDDA03C0FA40E439E36273963713` |
| `tools/fixtures/cm3_lto_roots/mutations.py` | `32BDE6CA67B12EEC9975D24D6628C5576EA29F33121CD60310F1F010CF272353` |
| `tools/fixtures/cm3_lto_roots/test_native.py` | `F34288304AD12FE6ADCD4FF6D25358425877A2C5750B1E955A27C556D0E838FF` |
| `tools/fixtures/cm3_lto_roots/test_witness.py` | `4372A4D128A7DCAA31DCF3CB63FBE7DED9805E2A8FCD8E33FE6A86942E794AA2` |
| `tools/fixtures/cm3_lto_roots/CONTRACT.md` | `8FC7E36658DB212E671E2AFC63C7D897BF43DD8835A9B1CB4BAE3D165A169E49` |
| `%TEMP%/cm3-lto-native-pure-20261105-e1/results.json` | `B25910BD294CDE3F7E86768F7623D7C42E2ADECF60FC27AECBB5163097D019D3` |
| `%TEMP%/cm3-lto-native-pure-20261105-e2/results.json` | `B25910BD294CDE3F7E86768F7623D7C42E2ADECF60FC27AECBB5163097D019D3` |
| `%TEMP%/cm3-lto-witness-pure-20261105-e1/results.json` | `357802A6309D235BBA96D4040EE750D5ADF731266EF67683084A22EB325F6166` |
| `%TEMP%/cm3-lto-witness-pure-20261105-e2/results.json` | `FBD57025842AF8D8E82FA4EC62E83AF0ADD5BEC843E56C1E3C6EA4D5034DC5CD` |
| `%TEMP%/cm3-lto-witness-pure-20261105-e3/results.json` | `CA8B78D3E12D9083AA983C4C4F1C90FDA02694FDD2F8CC951374541F85667242` |
| `C:/fz-cm3-lto-roots-witness-20261105-e1/results.json` | `B485E4B16A6B4C442F27135C6C33103CB735A7FFCA3CD6F630E75B20B5D929FD` |
| `C:/fz-cm3-lto-roots-witness-20261105-e2/results.json` | `B62099152550011BE5B7C0B7A0E77594C5A4C3F8BE66A0519C5C0B58824736AF` |
| `C:/fz-cm3-lto-roots-witness-20261105-e3/results.json` | `670043E9587DBA5108231EF301E10257158BF3AD5F8BF806549B4BD46779C6E8` |
| `C:/fz-cm3-lto-roots-witness-20261105-e4/results.json` | `1EE9DE6943A8A936601D1A523524901851276AE27789498024FF6E7C28FAF9A1` |
| `C:/fz-cm3-lto-roots-witness-20261105-e5/results.json` | `F63D540266C0BC79F301C950C5AF31C55ACD91BFD5623DAEC0D2EE354FF72F58` |
| `C:/fz-cm3-lto-roots-witness-20261105-e6/results.json` | `CE6368055FC7B3EDCC05A689AED9AC88ED4201298D280A9E759D9CB6C7A1697F` |
| `C:/fz-cm3-lto-roots-witness-20261105-e6/artifacts.json` | `5D4B04816B3C3002FA56D7AFF6E2457F2D95E98CCDDB7CBD7E1058E40AED5075` |
| `C:/fz-cm3-lto-roots-witness-20261105-e7/results.json` | `FF3399F28A115953834BA0E9ACBF13DD5B64CD975E072C7513FD95223A1E6B6C` |
| `C:/fz-cm3-lto-roots-witness-20261105-e7/artifacts.json` | `2024B20DC1AC52CC687B18B6AE51F0B8E3D2B732737EA9264B137377673FCD12` |
| `C:/fz-cm3-lto-roots-controls-driver-20261105-e1/driver.py` | `E887C23307017EAC5C163157AF72E71BEC481C122987C1567C1C6BC4EF5CDC95` |
| `C:/fz-cm3-lto-roots-controls-driver-20261105-e2/driver.py` | `71CAF427BC93D1EDB71C2724539A2B2A8F531D2E45B27070DC0DADC73C154605` |
| `C:/fz-cm3-lto-roots-controls-driver-20261105-e3/driver.py` | `D30C9A89CC6DD35EFBA94215BEEC33CCEB258279E12A3649DFC5A3BF0B5A73F9` |
| `C:/fz-cm3-lto-roots-controls-20261105-e1/results.json` | `3F777D436F24B22235D9E9FB3A60E27432AD3F47B9725287C33AAADE1A1C9146` |
| `C:/fz-cm3-lto-roots-controls-20261105-e2/results.json` | `D54C0FD5C15B08707173CC7B24CC0F9F9D0413AD19D2F36104BB0A1AC6DD4156` |
| `C:/fz-cm3-lto-roots-controls-20261105-e3/results.json` | `07B4784F372822E40478CE3C4F017F24C308C1F00BBB04385EED42B596185724` |

The report intentionally says `MACHINE-ROOT-WITNESS-PASS-NOT-QUALIFIED`.
Canonical first-start/SVC/PendSV protocol composition, the separately built
pinned FreeRTOS LTO side, full post-LTO ABI/override/cohort obligations, other
optimization/cohort/archive routes, CPU/board qualification, hosted exact-SHA
CI and global freeze remain pending. Every required-cell counter stays typed
integer zero. Next is the canonical native protocol composition, followed by
independent reference LTO capture/roots and a bounded mechanism join. Production
runtime/assembly/ABI, default matrix and protected unrelated WIP are unchanged.

## CM3 Native LTO Canonical Protocol Composition

The separate `tools/fixtures/cm3_lto_protocol/` composition now connects the
unchanged canonical machine decoder and CM3 checker to the machine-to-final
root evidence above. It admits only the same native O2-lto, direct,
single-partition CM3 p4/BASEPRI16 soft/no-FPU cohort. It does not supply a
reference object to the six-body checker or claim paired mechanisms.

The actual saved machine and its separately authenticated machine disassembly
feed `decoder.Object`; final disassembly is not substituted for ET_REL input.
The complete machine bytes and each decoded root's section/offset/extent/hash
must bind the independently recomputed preservation record. The three complete
native protocol matches use the unchanged `checker._match` and `_NATIVE` tables,
with an additional literal zero-tail-NOP requirement for O2-lto.

Only the two origin-proven section-symbol slot references may project to the
logical current-slot name, once in the appropriate LDR operand and once in its
literal descriptor. Raw tokens, projected tokens, raw empty ELF symbol names,
full transport records and projection evidence are all retained. Machine and
final byte hashes remain distinct from token-JSON hashes. The old transport
records still say `CanonicalProtocolValidated=False`; only the separately
computed composition reports its new native canonical result.

Final E2 passed locally on 2026-11-05:

- Three full native canonical roots and exactly two slot-role projections,
  bound by name to all 492 bytes, 170 instructions and 13 preserved references.
- All inherited 16 actual transport-mutant controls still reject.
- One additional actual private coherent SVC70-to-SVC71 mutation changes both
  machine/final instruction fields and both corresponding disassemblies.
  All three root-preservation checks accept that changed constant, but the
  frozen canonical checker rejects first-start token 27. This control proves
  the canonical guard is independent; it makes no mutated-source authority or
  mutant twin-image claim. Its six immutable files are closed after parsing.
- Twenty-eight pure protocol methods pass. The first attempt reproduced two
  boolean-zero alias failures (`Addend=False`, raw symbol `size=False`);
  literal integer guards now cover consumed symbol/origin/reference/descriptor
  fields. E1 remains historical; E2 reruns the complete actual witness.
- An independent parent driver verifies all 260 artifacts, all 3092 watched
  hashes, raw/projected token hashes, unchanged transport records, zero tail
  layout, exact projections and the actual constant-control bytes.
- Four real CLI refusal controls pass before output creation; full watched
  closure is rechecked afterwards. Neither witness nor controls execute a
  compiler, firmware, emulator, target or board.

| Evidence Or Source | SHA256 |
| --- | --- |
| `tools/fixtures/cm3_lto_protocol/protocol.py` | `BA3B630BB1FEA67C81D2EE18C84F6D2A47DE9802E8763F52EE55DB34CD65F419` |
| `tools/fixtures/cm3_lto_protocol/witness.py` | `39E1994A74DB225CD3BB2010AE07C49FD1DB2EE2006BCAD2FC59BD3092E6CF51` |
| `tools/fixtures/cm3_lto_protocol/test_protocol.py` | `45E6FB30124502769A8D6A60E2FC9E5590C0E18C325C971B0EFB6F8A8E628106` |
| `tools/fixtures/cm3_lto_protocol/CONTRACT.md` | `5FF302721B4D078E167A9DB0EF1B4AB8D192FA837B45D85D9612607BBDC41F82` |
| `%TEMP%/cm3-lto-protocol-pure-20261105-e1/results.json` | `40174885E4DE3BEE0CA35616C1B39FF16C5DC2AC3F3DECE88D6C2530F940358B` |
| `%TEMP%/cm3-lto-protocol-pure-20261105-e2/results.json` | `A6B4ED5500208D7853C51EFAE1E63B39B304EBC8B1CF3CBCA78FF8EE098319FD` |
| `C:/fz-cm3-lto-protocol-witness-20261105-e1/results.json` | `689DF137102C202A5C6E9B4A18368709B3F163C39D2CED29D6737BE94CC0F779` |
| `C:/fz-cm3-lto-protocol-witness-20261105-e2/results.json` | `7E86F186531959E09D08F175EB5AF054FBFFFEFAD5296C4D30E726C1C86DD3D3` |
| `C:/fz-cm3-lto-protocol-witness-20261105-e2/artifacts.json` | `1482340A085A57454B1FFCE8D6D72BCAA7920E23401027D5D3B76419117E57EB` |
| `C:/fz-cm3-lto-protocol-controls-driver-20261105-e1/driver.py` | `3D9A8A84B900AAF7B1D980F560584528CA9A3060D4A7554D782C32415FAFEDD6` |
| `C:/fz-cm3-lto-protocol-controls-driver-20261105-e2/driver.py` | `CB41C61DB628563385F7162CD689EB863A4954F9187411E264DAAF4D6F4971B9` |
| `C:/fz-cm3-lto-protocol-controls-20261105-e1/results.json` | `5E64491692191ABE6CE34A46A683EA4E58FD62E6B6835F8EBE3A5FF1AF29192B` |
| `C:/fz-cm3-lto-protocol-controls-20261105-e2/results.json` | `6FAFDF4AF8BF5C667A3D44F3ABCA77B5E27F9F79ED8D6883327309068ED226A9` |

The new protocol status is `NATIVE-CANONICAL-PASS-NOT-REFERENCE-QUALIFIED`;
the containing root witness retains its deliberately non-qualified status.
Source/IR-to-machine semantics, full post-LTO ABI/override/cohort proof,
independent FreeRTOS LTO capture/roots and its paired mechanism/difference join,
other modes/cohorts/archives, CPU/board validation, hosted exact-SHA CI and
global software freeze remain pending. Required-cell counters stay typed
integer zero. Next is independently captured reference LTO, not a fabricated
reference view or promotion of the ordinary five-mode reference record.
No production mechanics, frozen readers/checker, default matrix or protected
unrelated WIP were changed.

## Pinned CM3 Reference Slim-LTO Capture

The opt-in `tools/fixtures/cm3_reference_lto_transport/` is a separate fixed
reference producer, not a broader native admission mode. It authenticates the
qualified ordinary reference CM3 O2 seed, pinned FreeRTOS commit
`a50edad08b29052631aa469d4df6e6ec7ff68878`, 23 worktree/captured/Git-blob file
bindings, generated threshold/assertion configuration, complete source inventory,
71 seed command records, dependencies and tool/interpreter closure before mkdir.
Helpers execute captured immutable buffers. Upstream/fixture source, fail-stop
providers, NULL current TCB and enabled handler-installation checks are unchanged.

The actual E3 capture/build passed locally on 2026-11-05:

- Four ordered TUs: upstream ARM_CM3 `port.c`, typed providers, typed consumer
  and unchanged startup assembly. The first three are freshly compiled slim IR
  with no executable fat fallback; the fourth remains native.
- Two independent direct O2-lto links, one explicit LTO partition each, with
  driver and explicit plugin save-temps. Complete actual workers, resolutions,
  arguments/responses, generated assembly, maps, inspections and genuine
  `image.elf.ltrans0.ltrans.o` files remain captured. WPA IR is not substituted.
- Both saved machine objects hash to
  `2B9AD20DE46929F15662FF8EE278A8FFB8CD2CC4C2587DF9FDAE8C0312CC630F`.
  The unchanged twin reader verifies complete loader-visible geometry/bytes,
  entry, allocated sections and vectors; its saved path/hash/value is closed
  before and after sealing.
- Thirty-seven contained actual tool commands; an independent parent driver
  rehashes all 1349 artifacts, 1268 watched inputs and 1231 retained input copies,
  actual object/dependency/link roles and the saved twin record.
- Seven actual machine symbol observations preserve raw bindings. First-start
  remains LOCAL (32 bytes), SVC/PendSV GLOBAL (36/68 bytes), and `pxCurrentTCB`
  is a GLOBAL four-byte object at machine BSS offset 8. Complete readelf/map
  records show named slot ABS32 references, unlike the native section-symbol
  form. These are observations, not origin/addend/applied-reference proofs.
- Four real CLI negatives reject before output creation: wrong seed receipt,
  wrong manifest, repository overlap and seed overlap. Complete positive input
  and output closure is independently rechecked after those refusals.
- Twenty-two pure probe controls pass, including missing/changed input objects,
  exact source/link/IR counters, command/twin prerequisites and late seal faults.
- Fifteen separate pure admission methods pass over mocked helper/filesystem
  boundaries, including source/blob/config/command/dependency mutations,
  lexical immutable helper reads and the ordinary sidecar naming regression.
  They do not execute the captured parser, compiler or target.

The first pure run exposed a missing independent TranslationUnits counter
check; it is now required alongside four source rows, three IR inputs and two
links. The first actual runner failed before mkdir because seed-sidecar lookup
incorrectly appended `.dis` after `.o`/`.elf`; ordinary seed sidecars replace the
suffix. The second runner admitted the seed, then stopped after its first C
compile because the reused dependency parser requires `pilot-source-N` rather
than the new wrapper's `reference-lto-source-N` target marker. The two fixes
only correct wrapper/receipt conventions; source, flags and parsers are unchanged.
All failed receipts/logs remain historical and are not relabeled as E3.

| Evidence Or Source | SHA256 |
| --- | --- |
| `tools/fixtures/cm3_reference_lto_transport/probe.py` | `1D1FDC0D644123FEF1E182107A8062A0BA9BCCB385DA0C2D13BDFD741290F2C3` |
| `tools/fixtures/cm3_reference_lto_transport/admission.py` | `27C192C12E30BD4F1A872D6A8586B85C303AF6D6873A85A26238BE7DD4962ECC` |
| `tools/fixtures/cm3_reference_lto_transport/test_probe.py` | `C0C653286B670262B8809B97D27B3F82C5A361B1D24BAAAF27F860030955E83C` |
| `tools/fixtures/cm3_reference_lto_transport/test_admission.py` | `D645E0314CD799B473E012F719AAF8AE7615C0C5BB143297C6F5DAE81857B597` |
| `tools/fixtures/cm3_reference_lto_transport/CONTRACT.md` | `4368A1C64DFBC7649E23CCBB7840F9AC716BE41F837527E5193C0AAAE89C24F4` |
| `%TEMP%/cm3-reference-lto-probe-pure-20261105-e1/results.json` | `1A180BC9BF38D0C42773D7A7B028ADD1956A45FB8BED9E73E48A0A4627ABC29D` |
| `%TEMP%/cm3-reference-lto-probe-pure-20261105-e2/results.json` | `57B67569D2EF13A2B02A32B70E6A2DA7D068E797CCF8C6AE9E945B98B68C496C` |
| `%TEMP%/cm3-reference-lto-probe-pure-20261105-e3/results.json` | `173EB2EBC4CA049A6668158E7C5CC46D5BD3A61D269BCE75D876FA6EA1C07118` |
| `%TEMP%/cm3-reference-lto-admission-pure-20261105-e1/results.json` | `B9344303AF5D84A9AE51B1FEC3D2B3BD6284AA21FCE3A208145354D8A34AB6A7` |
| `C:/fz-cm3-reference-lto-runner-driver-20261105-e1/driver.py` | `F5D50B4C626992C6C08165F18D942677A6E16E393EEFEBB0DB6A44E9B0672434` |
| `C:/fz-cm3-reference-lto-runner-driver-20261105-e2/driver.py` | `6E0898D120477E983A5156A7F8ACD74D6211B73697CDE1993CACB025AA09ECD9` |
| `C:/fz-cm3-reference-lto-runner-driver-20261105-e3/driver.py` | `A37CB8E28E39DFAD797F0C7931118FC7B5E68369A04A1B857A46C136AD651814` |
| `C:/fz-cm3-reference-lto-runner-20261105-e1/results.json` | `5EA1369BFC8042867AA99F64EE157102D0844D0C0C3AFAFB64898DD96D033E20` |
| `C:/fz-cm3-reference-lto-runner-20261105-e2/results.json` | `BAB5C8766E7363B127CA3139F54655358C80FE0CB5FD69FDDD4963F3F2D5AA28` |
| `C:/fz-cm3-reference-lto-runner-20261105-e3/results.json` | `DE922996E32541A91E518AB91689DFC0EDD43126F414B12DCA8767D6A080B4A3` |
| `C:/fz-cm3-reference-lto-transport-20261105-e2/results.json` | `01699941C00893315F74F24C7EFD06CA24F707BC2C755B0BF3E5EF4C46643B51` |
| `C:/fz-cm3-reference-lto-transport-20261105-e3/results.json` | `F4576A894CE06EB275A956C93441DF8F1B9D7850D9F3A7B9BEA905845A47B455` |
| `C:/fz-cm3-reference-lto-transport-20261105-e3/artifacts.json` | `54F7C7E773BF4CDAC9B4A645F3DC472FF9EFD48F079E30A4C695405DE181D470` |
| `C:/fz-cm3-reference-lto-transport-20261105-e3/load-image.json` | `514F8CC40D604F14696361829014B8B0E64170D1BC34901D451D9119582433E2` |
| `C:/fz-cm3-reference-lto-controls-driver-20261105-e1/driver.py` | `30414022650E18FBB687887BB3B6C6F5D4A5A11376F129F31644C22590C4D1C8` |
| `C:/fz-cm3-reference-lto-controls-20261105-e1/results.json` | `0EE8998ECFFE5F3F7FB73AFF893C9F533C89D50E53F50F8F6F76AB1B2BC3447C` |

This closes capture feasibility only. The next reference root adapter must
independently bind the local first-start and named `pxCurrentTCB` through whole
machine-section map placements, prove original/applied REL semantics and consume
complete mapping/pool/tail bytes. Canonical reference LTO protocols and the
native/reference mechanism join remain separate subsequent gates. Full ABI,
source/IR semantics, policy/kernel execution, archives/other modes/cohorts,
CPU/board validation, hosted exact-SHA CI and global software freeze remain
unproved. Required-cell counters stay typed integer zero. No production runtime,
ordinary reader, public/port ABI, default matrix or protected WIP was changed.

## Pinned CM3 Reference LTO Root Preservation

The separate `tools/fixtures/cm3_reference_lto_roots/` adapter and enclosing
witness consume the authenticated reference E3 capture above. The scope is
only O2-lto, direct, single-partition CM3 p4/BASEPRI16 soft/no-FPU. The unchanged
ordinary core supplies generic ELF/map/disassembly construction and bounded
utilities; its ordinary symbol/function policies and the native adapter are
neither changed nor patched. The new reference predicates preserve actual
LOCAL first-start and GLOBAL handler/callee/slot bindings.

Final E2 passed locally on 2026-11-05:

- All three complete machine-to-final roots preserve 136 bytes, 39 instructions,
  exact mapping boundaries and all pool/padding bytes. Full original machine
  sections, provider identities, symbol offsets/extents and containing output
  sections independently bind every root, slot and root BL destination.
- Three named references retain original and applied metadata: two ABS32
  `pxCurrentTCB` addends zero and one THM_CALL `vTaskSwitchContext` addend minus
  four. Final words/BL bits independently match mapped definitions; addends
  come from unapplied bytes, not final readelf values. The four-byte global
  slot is at original `.bss+8` within 12 bytes and final `0x20000010`.
- Six positive roles are copied and consumed from immutable buffers. All 16
  actual private ELF/map controls reject at their declared guard. Each case
  binds five distinct regular single-link physical files before parsing,
  admits only those strict immutable snapshots, and closes physical identity,
  bytes and exact membership afterwards.
- The coherent slot control swaps final `ulMaxPRIGROUPValue`/`pxCurrentTCB`
  object locations and edits both applied words and disassembly. All BSS
  objects remain aligned, bounded and nonoverlapping; the rejection is exactly
  `REF-LTO-ORIGIN`, not an accidental alias check. The coherent callee control
  changes final callee entry/extent, actual BL bits and disassembly and also
  fails exactly origin. Neither control claims unchanged provider semantics
  or a mutated twin comparison.
- Eighteen pure reader methods and 26 separate pure envelope methods pass.
  These use explicit synthetic/mocked boundaries and execute no qualified
  captured parser or compiler. Review found one diagnostic-only gap: the
  frozen generic parser can retain a malformed literal-data record as `None`.
  An explicit guard now returns typed `REF-LTO-DECODE` instead of `TypeError`;
  regression coverage passes. No false-acceptance claim is made.
- The enclosing witness authenticates producer receipts/manifests, input/source
  cohort and all captured helpers before use. Frozen parser/helper code executes
  retained buffers; positive and private reader lookups have no unknown-file
  disk fallback. The written manifest is semantically compared with the intended
  dictionary; predetermined outputs, late byte hashes and memberships close.
- Independent controls rehash all 251 artifacts and 2834 watched files, raw
  named-reference records, captured/original bindings and actual private inputs.
  Four real CLI negatives (wrong receipt, wrong manifest, repository overlap,
  capture overlap) refuse before output creation. Full closure is rechecked
  afterwards. These stages execute Python only, never compiler/target/board code.

E1 is retained as positive-only history: it passed three roots but executed no
actual mutation controls, before the explicit malformed-record guard. Its
receipt is not relabeled as final E2 or canonical qualification.

| Evidence Or Source | SHA256 |
| --- | --- |
| `tools/fixtures/cm3_reference_lto_roots/reference.py` | `3E53C4C0C5030B973A599FBDD0CB0B7FDECC625DEFD8C204A8C9691C5F6A616D` |
| `tools/fixtures/cm3_reference_lto_roots/witness.py` | `3B9168D52F7AA63339264A8E7B655DF94FF1AC644FF08D20E4B617CED5699B54` |
| `tools/fixtures/cm3_reference_lto_roots/mutations.py` | `E20E55734138E5F9AE76019D3C3EF1260EE708FDF222DC72E5C8B5552E02029C` |
| `tools/fixtures/cm3_reference_lto_roots/test_reference.py` | `6DEB17086F07862C1CAADA8FA2982CC4A6A57F73D4D55E7FA0A11EF6E0F4943E` |
| `tools/fixtures/cm3_reference_lto_roots/test_witness.py` | `0BE87F106405E6195F181843699BA2FE4D9747F73E00F9A273E8BF227CE18CEF` |
| `tools/fixtures/cm3_reference_lto_roots/CONTRACT.md` | `379DC16C29847D681926A478CA101E8DCECAB40FB0BA759EBEA741D1981533FA` |
| `%TEMP%/cm3-reference-lto-reader-pure-20261105-e1/results.json` | `CCF145161B23692BD534FB973AE1689BEE6DBEE3D9E3F17CA053CDBC006FEE65` |
| `%TEMP%/cm3-reference-lto-witness-pure-20261105-e1/results.json` | `6664BADF12F2922F4AADB68F5B102B3BE4B138685C2BC86646A702CC03523C95` |
| `C:/fz-cm3-reference-lto-roots-witness-20261105-e1/results.json` | `59BFE630B621B1D757FF5F00FD5DBAE0E1F44E3AC5B42C1A99DE5EBF81F1BBCA` |
| `C:/fz-cm3-reference-lto-roots-witness-20261105-e1/artifacts.json` | `28EAD0FD4E27BC458403A70E68CBA02D4406AC1A040DFE0C6E18D533FBD865C1` |
| `C:/fz-cm3-reference-lto-roots-witness-20261105-e2/results.json` | `C43BBFC363BAAF204ECC1DCD9A44445F568B6E73E0E7CE2A64A2FBBD0E2B6A17` |
| `C:/fz-cm3-reference-lto-roots-witness-20261105-e2/artifacts.json` | `9C0E2618B30010AEFE24C18B63873CD975469A3FA8EE1A0375E81E751E577CC6` |
| `C:/fz-cm3-reference-lto-roots-controls-driver-20261105-e1/driver.py` | `805A8A3D87FB2D4253E826E8CAA257681FBD547BB9E118D8C8B6E90D5E2E566C` |
| `C:/fz-cm3-reference-lto-roots-controls-20261105-e1/results.json` | `4C532B882438800E2F75767F36161A2C39114E96CE7DD8F95A0BF20264521F26` |

The status is deliberately `REFERENCE-MACHINE-ROOT-PASS-NOT-QUALIFIED`.
Canonical reference protocols and the real native/reference LTO mechanism join
remain separate subsequent gates, not fabricated opposite-side views. Original
TU/source/IR semantics, complete ABI/object proof, policy/kernel execution,
other modes/cohorts/archives, CPU/board, hosted exact-SHA CI and global software
freeze remain unproved. Required-cell counters stay typed integer zero. No
production mechanics, frozen helpers, public/port ABI, default matrix or
protected unrelated WIP was changed.

## CM3 Reference LTO Canonical Protocol Composition

The opt-in `tools/fixtures/cm3_reference_lto_protocol/` composes the fixed
reference root envelope with the unchanged canonical machine decoder and CM3
checker. Only the same direct, single-partition reference CM3 O2-lto soft/no-FPU
p4/BASEPRI16 cohort is admitted. The actual saved machine and its separately
authenticated machine disassembly feed the decoder; final text is not reused
as ET_REL disassembly. Full machine/root bytes, raw LOCAL first-start/GLOBAL
handler metadata and mapped origins bind every canonical root.

Final E2 passed locally on 2026-11-05:

- All three complete raw reference token sequences match unchanged `_REFERENCE`
  through the frozen `_match`, with literal integer zero post-island tail NOPs.
  First-start's real in-body NOP and complete pool/padding descriptors remain.
  Named `pxCurrentTCB` references require no projection; raw tokens are neither
  filtered nor replaced. This does not fabricate an opposite-side object.
- Machine byte, final byte and canonical token-JSON hash domains are separately
  retained. Each old transport record remains unchanged, including its false
  canonical flag; only the independent composition reports the new result.
- All inherited 16 actual transport controls still reject at their expected
  guards. An additional actual private coherent SVC0-to-SVC1 control changes
  both ELF instruction fields and both corresponding disassembly records.
  Three complete root-preservation checks accept, then the frozen reference
  checker rejects first-start token 8. Its six immutable inputs, file offsets,
  actual instruction addresses, root-relative offsets and closing bytes are
  retained. It claims neither mutated-source authority nor twin-image equality.
- Eighteen pure protocol methods pass using synthetic decoder/transport
  boundaries and the unchanged source-captured canonical checker. They cover
  local/global roles, machine/body/origin binding, duplicate/undefined symbols,
  malformed token shapes, boolean integer aliases, complete tails and absence
  of native/paired credit. They execute no qualified captured ELF parser or tool.
- Independent controls verify all 260 artifacts and 2845 watched inputs, exact
  old/new record binding, raw token/checker hashes, zero projections and actual
  SVC1 bytes/addresses. Four real CLI negatives refuse before output creation;
  whole input/output closure is rechecked afterwards. No compiler, target,
  emulator, firmware or board execution occurs in these stages.

E1 also passed; E2 only adds explicit Address/RootRelativeOffset annotations
beside the existing binary FileOffset edits to meet the written evidence
contract. The entire actual witness and independent controls were rerun on
fresh directories. E1 files remain historical and are not relabeled as E2.

| Evidence Or Source | SHA256 |
| --- | --- |
| `tools/fixtures/cm3_reference_lto_protocol/protocol.py` | `200B277D03DF4236FE887907F732BC2A26898D8C15C1544D917B3DC3CF6BF798` |
| `tools/fixtures/cm3_reference_lto_protocol/witness.py` | `B3968C5C51BCB7DFF13425B6656715DB4FA9674C18503AA04FDE7EA0A0F89D5F` |
| `tools/fixtures/cm3_reference_lto_protocol/test_protocol.py` | `C2DCF5B61394DC87110D959348857FB283F75F39669457F6229944DA76F77915` |
| `tools/fixtures/cm3_reference_lto_protocol/CONTRACT.md` | `35888916C59FACA3A8DFB71AFF258012420F465CC64A514A7B473D4CFC39482C` |
| `%TEMP%/cm3-reference-lto-protocol-pure-20261105-e1/results.json` | `B659F54A4FBE9458ACDC3D490AFC5EE61780076E21C023F3B475F9B747742D17` |
| `C:/fz-cm3-reference-lto-protocol-witness-20261105-e1/results.json` | `3A38F9EE07BDCE6CC0BE69967C384EFC87F6C8DC327D0ED7F60336A3959B979D` |
| `C:/fz-cm3-reference-lto-protocol-witness-20261105-e1/artifacts.json` | `9582AC12D6DE01BE3E903F0024C6EB0650C8EDE373F519158FECB18F3BA4AAF2` |
| `C:/fz-cm3-reference-lto-protocol-witness-20261105-e2/results.json` | `FD8E1C1934A517C956BC948863B608A954570376C46BF26D67D6477941910D20` |
| `C:/fz-cm3-reference-lto-protocol-witness-20261105-e2/artifacts.json` | `AD3E3FDD235004F535B66ED42B1EDDC4F65A0F54C74BE69D2477C089118E53BD` |
| `C:/fz-cm3-reference-lto-protocol-controls-driver-20261105-e1/driver.py` | `72D54B9FBA44C4C14052B0E11509774FE24C3E3993CC9C7E6F103C85DFD5B045` |
| `C:/fz-cm3-reference-lto-protocol-controls-driver-20261105-e2/driver.py` | `270FB0DAB04ACBF91C2C134326A24EAD907E44C95D3B904117874D6E43450A18` |
| `C:/fz-cm3-reference-lto-protocol-controls-20261105-e1/results.json` | `E654960122CFB0DB9B52A2E4638FFFA3ED0FE9B64E49AEEE63A83EDB5A3D1A08` |
| `C:/fz-cm3-reference-lto-protocol-controls-20261105-e2/results.json` | `B98593F7514F414CC06959249022AA1B9BD01BD10FE481B52489BBA1F71EC64D` |

The component status is `REFERENCE-CANONICAL-PASS-NOT-PAIRED-QUALIFIED`; the
containing root envelope keeps its deliberately non-qualified status. The next
gate is the real native/reference LTO six-body mechanism/difference join, using
both independently preserved machines, not a substitute view. Source/IR-to-
machine semantics, original TU ownership, complete ABI/object proof, policy or
kernel execution, other modes/cohorts/archives, CPU/board, hosted exact-SHA CI
and global software freeze remain pending. Required-cell counters stay typed
integer zero. No production runtime, frozen reader/decoder/checker, public/port
ABI, default matrix or protected unrelated WIP was changed.

## CM3 LTO Six-Body Mechanism Join

The opt-in `tools/fixtures/cm3_lto_join/` composes the independently captured
native and pinned FreeRTOS CM3 O2-lto, direct, single-partition p4/BASEPRI16
soft/no-FPU cohorts. It does not broaden ordinary-mode admission, fabricate an
opposite-side view, patch frozen helpers or infer full post-LTO API/ABI proof.

Final E3 passed locally on 2026-11-05:

- Both caller-bound protocol receipts/manifests, producer input closures,
  capture/ordinary-seed/inventory trees and fixed helper source cohorts are
  authenticated before qualified imports or mkdir. Fourteen binary/provider
  roles are physically distinct across the two sides. Shared source buffers
  must agree; both captured parser packages must have identical file/hash sets.
- From immutable source/binary buffers, the witness independently recomputes
  each actual machine-to-final adapter, all canonical evidence and both genuine
  ordinary/emit-relocs twins. Complete new records bind the unchanged prior
  records by name. Then the unchanged `check_pair()` receives the real native
  and reference protocol views and matches all six complete bodies, zero tails.
- The six roots retain 628 bytes including literal/padding spans, 209 machine
  instructions, 16 original/applied references and 215 canonical tokens. Native
  retains its two origin-proven slot-role projections; reference retains raw
  named `pxCurrentTCB` tokens with no projection. Old raw transport records keep
  their false canonical flags and separate raw-byte/token-JSON hash domains.
- The exact first-start, first-restore and PendSV assignments use six existing
  difference IDs. Both the admitted inventory's immutable master ledger and
  fixed `cm3_final_join/POLICY_DIFFERENCES.md` provide unique nonempty rationales.
  Nine native software words/saved EXC_RETURN and eight reference words with
  actual ORR-LR-13 remain distinct, not normalized or declared equivalent.
- Prior 32 transport and two canonical controls are authenticated, not rerun.
  After source pins pass, AST literal evaluation reads exact catalogs without
  executing mutation sources. Exact case names/families/diagnostics, coherent
  markers, expected five/six private file roles/paths/hashes, artifact bindings,
  directory memberships and recorded reference physical IDs must match.
  Both original/private SVC fields and both disassembly edit hashes bind the
  canonical controls. Count-only PASS labels do not suffice.
- Eighteen pure join methods pass over synthetic views and unchanged captured
  checker source. Twenty-six pure envelope methods separately cover strict
  prior records, catalog/file/edit bindings, immutable readers, nested trees,
  predetermined output membership, semantic manifest comparison and FAIL-only
  late drift recovery. Neither pure suite executes qualified ELF parsing or
  compilers/targets; the actual witness supplies the real ELF proof above.
- Independent controls rehash 274 artifacts, 5767 watched files and seven full
  nested trees before/after eight real CLI negatives: each side's wrong receipt
  and wrong manifest, repository/native/reference overlap, and native-as-reference
  substitution. Each rejects at its expected admission guard before output
  creation. No compiler, firmware, emulator, target or board executes here.

E1's actual six-body replay passed, but review found two weaker admission
checks: arbitrary prior control names/files were accepted at a count-only layer,
and duplicate top-level root names could collapse during dictionary conversion.
E2 adds exact control/file authentication and unique ordered root membership.
The first 26-method envelope run then reproduces four closing-float subcase
failures: Python accepted 5.0/6.0 as equal to integer 5/6 on both sides. Explicit
literal integer guards fix both counters; the second pure run and full fresh E3
actual/independent runs pass. E1/E2 and the failed pure receipt remain historical,
not relabeled as final E3. These are evidence-schema gaps, not a demonstrated
failure of E1's independently recomputed six-body protocol coverage.

| Evidence Or Source | SHA256 |
| --- | --- |
| `tools/fixtures/cm3_lto_join/join.py` | `F4EF2402495FF90C6D781762EC2B85A458F7DA702F14B2C6A1581D9E09343CE3` |
| `tools/fixtures/cm3_lto_join/witness.py` | `413089068C1C42ED1B9BE3E0E67E8E56BB6ABDF55CA3E3D866AC657C74B7EA97` |
| `tools/fixtures/cm3_lto_join/test_join.py` | `79761EF94D936B950F84A55EEAC4C0D600CBF66ABB451993A40F69356EAA6D69` |
| `tools/fixtures/cm3_lto_join/test_witness.py` | `0553C6189AAA22754C95032B1F27AB5062981693A913219186E25DB1465A10A1` |
| `tools/fixtures/cm3_lto_join/CONTRACT.md` | `CB61811B70D6CE5F18B40191402037BD4996B1EB63FF4BA12AEA42678BA7F69A` |
| `tools/fixtures/cm3_final_join/POLICY_DIFFERENCES.md` | `778B098F80EAE5EE641B323B4F8D60441C2F725921B506AEDA90B487D3EB5019` |
| `%TEMP%/cm3-lto-join-pure-20261105-e1/results.json` | `B1C4BBAA6B5ECAA88A3AA05E4E4BF9916316A9E8301DF73C52B336AE7A0D40D8` |
| `%TEMP%/cm3-lto-join-witness-pure-20261105-e1/results.json` | `63C16B54096D782F178F165E7CA10AD479E7E5E240C0ACC3CA1B02D3640AEED4` |
| `%TEMP%/cm3-lto-join-witness-pure-20261105-e2/results.json` | `905CA1F28D91D8C2DEB949638DC99A5EEB41CFE05E3AD013A3AECF6E816D8E14` |
| `C:/fz-cm3-lto-join-witness-20261105-e1/results.json` | `15B8EF36C7FEE3DF31EF356B7BDBA9C71167F8371F296D150FE8EDA2CE97B75B` |
| `C:/fz-cm3-lto-join-witness-20261105-e2/results.json` | `26759D54D31F4113A319FE21F8D169170EABD3D4B1F679547F18D8122ACDB358` |
| `C:/fz-cm3-lto-join-witness-20261105-e3/results.json` | `CDE1D4B6451D088496795DD08C0D97158E48E0C233F54BF8293A2BC7877908B5` |
| `C:/fz-cm3-lto-join-witness-20261105-e3/artifacts.json` | `E9ECBF630F1F5798AEB6B869D68CC91B4F952CCF720E0C475E1B132A05AF2781` |
| `C:/fz-cm3-lto-join-runner-driver-20261105-e1/driver.py` | `0F5895CBAA1B9A780724E44624BE4882689980625F83891DC1FBCD8E2294FA7B` |
| `C:/fz-cm3-lto-join-runner-driver-20261105-e2/driver.py` | `A36F25E9F9085F90D97BCED8C85886E3B87C711E73C982C97B40033C12B29667` |
| `C:/fz-cm3-lto-join-runner-driver-20261105-e3/driver.py` | `1C41B85BDB015DDCCAB66E722257590E64F0B2EB6F22B9A991930B629DA594A1` |
| `C:/fz-cm3-lto-join-runner-20261105-e1/results.json` | `F2E743AC4519C51E83833154BA2B08F296C8E3D215718CEB84F40964904502F6` |
| `C:/fz-cm3-lto-join-runner-20261105-e2/results.json` | `009239629B7F04F9C1E2CC4245F7FAB6F5587E558129F2C7BFCB115F7CBEA187` |
| `C:/fz-cm3-lto-join-runner-20261105-e3/results.json` | `4A8D3178CCA1A9FF0DE742BAE72A055199EC56B26683423FA99C43FA28E07234` |
| `C:/fz-cm3-lto-join-controls-driver-20261105-e1/driver.py` | `E7D1449A5C1583D1F26C39E773D1D1047DC0B1C31C0EA407922CD7156B2B3919` |
| `C:/fz-cm3-lto-join-controls-driver-20261105-e2/driver.py` | `23C8FE86BE625191BD53AF085E4BB2DD37F6FD64A5A6B21B9EE37F0045FA6494` |
| `C:/fz-cm3-lto-join-controls-driver-20261105-e3/driver.py` | `33CDE68D8E6D13893C4AD562FB4955C8E16784CE84B0596E809F7DD153A21DEB` |
| `C:/fz-cm3-lto-join-controls-20261105-e1/results.json` | `B6867393B752B51B00178FF2C6DA6E29D5AC06E6AF8869F49DCA5DEF752DF27D` |
| `C:/fz-cm3-lto-join-controls-20261105-e2/results.json` | `0C7DC3BA2B2D8C2EB6B8C42A2050669A8F2E422BF9428C74205287CEC50D420D` |
| `C:/fz-cm3-lto-join-controls-20261105-e3/results.json` | `3B425F636872F49938B136C3DF108B0070845F9F3A3077C439401E2C4F7665F9` |

The component status is `CM3-LTO-SIX-BODY-JOIN-PASS-NOT-QUALIFIED`; the outer
receipt is `CM3-LTO-JOIN-PASS-NOT-QUALIFIED`. This closes only the six-root
mechanism/difference composition for this cohort. Full post-LTO API/ABI,
override/cohort, source/IR semantics, original TU ownership, complete-object or
kernel/policy correctness, archives/other modes/cohorts, CPU/board, hosted
exact-SHA CI and global software freeze remain pending. Required-cell counters
stay typed integer zero. No production mechanics, frozen reader/decoder/checker,
public/port ABI, default matrix or protected unrelated WIP was changed.

## Native CM3 LTO Direct-Link Contract

The separate opt-in `tools/fixtures/cm3_lto_link_contract/` statically audits
the retained native CM3 O2-lto direct-link cohort. Both existing ordinary and
emit-relocs images use their own actual saved machine, map, final attributes
and startup provider. The unchanged generic ELF/map reader constructs them;
ordinary-mode global-anchor/current-slot predicates are not relaxed.

Local evidence on 2026-11-05 passes:

- Exactly 26 prescribed definitions per twin bind complete input-section
  placements, offsets, extents, types and bindings. These include the public
  five, forward eight, reset/strong handlers, default panic, reverse-v1 anchor,
  current slot, both cohort identities and consumer pointer objects.
- Both machine and final CM3 attributes and EABI5/soft flags are checked. The
  fixed post-LTO anchor/current slot are LOCAL; default panic is GLOBAL.
  Invalid aliases, overlapping extents, undefined/legacy/foreign cohort symbols,
  wrong providers and contradictory architecture attributes fail closed.
- The five API roots and two cohort expectations have seven exact named original
  ABS32+0 references. Actual applied words bind exact map-backed definitions,
  including Thumb entries. The emitted final also retains seven matching REL
  records; the ordinary image correctly has none. All 256 final vector words,
  entry/MSP, slots 11/14 and read-only/load geometry are checked.
- The frozen twin reader independently compares both real load images. All
  parsing consumes immutable source/binary buffers. Full capture, ordinary-seed
  and inventory trees close alongside source hashes, physical identities,
  predetermined output membership and semantic artifact-manifest comparison.
- Twenty pure synthetic audit methods pass, including missing/extra/wrong ABI
  symbols, binding/type/Thumb/extent/provider/alias failures, vector changes,
  original/applied pointer membership/kind/target/addend changes, storage/load
  violations, contradictory attributes and bool/float numeric aliases. They
  explicitly claim no real ELF parsing or toolchain/target execution.
- Four separate pure controls pass for repeated/late sealing failures, physical
  identity drift and output-path refusal. Review found a failure-only manifest
  gap: after repeated sealing failure, the final FAIL receipt could outgrow its
  old manifest hash. The fallback now refreshes that manifest; tests reproduce
  both failure paths without creating false PASS.
- Independent host controls close 182 artifacts and 3013 watched hashes before
  and after seven real CLI refusals: wrong receipt, wrong manifest, repository,
  capture and seed overlap, existing output, and reference-as-native substitution.
  Every refusal has the intended diagnostic and creates no rejected output.

The first smoke replay and final runner both use the same frozen audit/witness
source hashes. Neither invokes a compiler, linker, emulator, firmware or board.
Source review also tightened an admission mismatch before the actual runs:
GLOBAL anchor/current-slot metadata can no longer satisfy the fixed LOCAL role.

| Evidence Or Source | SHA256 |
| --- | --- |
| `tools/fixtures/cm3_lto_link_contract/audit.py` | `9D6B4E1694A8C0A2D7F2E1C7B6D108B58B103131DD7C19D45CD08238E4CED759` |
| `tools/fixtures/cm3_lto_link_contract/witness.py` | `599D384B53F45093F01949A4E95A9DF8A15BC4EABE9EA5E12A1C2E7138F3297E` |
| `tools/fixtures/cm3_lto_link_contract/test_audit.py` | `3E215D413CC4ADBA6DE85901B394EE1550804EA0A714604AF0269C64D6B68B9D` |
| `tools/fixtures/cm3_lto_link_contract/test_witness.py` | `E7568CA67888CB12FDCFAE0C1B8818FB786F8E8FA0D7C2215D78ADB5C1ECB8B2` |
| `tools/fixtures/cm3_lto_link_contract/CONTRACT.md` | `3FBB88B2895C9BC63F9F400E669E0DEFD22CC6CE80B21A03E343C3C0C5F59A83` |
| `C:/fz-cm3-lto-link-smoke-20261105-e1/results.json` | `200448314D306929F5AA1B67460ACDC3DA8D9A0E35BC37BB8AE40860AD0A82D1` |
| `C:/fz-cm3-lto-link-smoke-20261105-e1/artifacts.json` | `2B7E7EFFFE93D4DEFDA0D436785C1AA902F7597298B28F471F501699A47AAFB7` |
| `%TEMP%/cm3-lto-link-pure-20261105-e1/results.json` | `D47A69ABB6DBBC8558FE4396DB0A24C074279999F570171A64D8E94C1103A419` |
| `C:/fz-cm3-lto-link-witness-20261105-e1/results.json` | `776F355C53ACD1A8F8E575316379A8DD457C4E1EB29F7890AE4C036E460B953D` |
| `C:/fz-cm3-lto-link-witness-20261105-e1/artifacts.json` | `7396B0AEFF24D1C05EE01CF2837C6A8259091575DC86FC77CD485E6EB6DBC344` |
| `C:/fz-cm3-lto-link-runner-driver-20261105-e1/driver.py` | `700A2E342BD5F9A737C3986AF695D70F2BD0ACFC49ED47878F2EADC183AFCC02` |
| `C:/fz-cm3-lto-link-runner-20261105-e1/results.json` | `004D95AF1C1B5C9B7DB8D980AB8E6EBA4193F5A91AFD19D609000E51653EF4BC` |

Status is `CM3-LTO-DIRECT-LINK-CONTRACT-PASS-NOT-QUALIFIED`. This closes static
surface/placement/pointer evidence only. Full callable ABI, source/IR semantics,
original-TU ownership and whole-kernel correctness are not inferred. Strong
application panic override, duplicate-handler and valid-but-mismatched identity
fresh links remain pending, independently of archive extraction, other modes/
cohorts, CPU/board, hosted exact-SHA CI and global freeze. Required-cell counters
stay typed integer zero. No production code, frozen helpers, public/port ABI,
default matrix or protected unrelated WIP was changed.

## Fresh CM3 LTO Link-Control Capture

The opt-in `tools/fixtures/cm3_lto_link_controls/` starts the next independent
link-control cohort without changing production code. It reuses the authenticated
CM3 O2-lto eight slim IR inputs and explicit non-LTO startup. Three small added
TUs provide a canonical attributed strong application panic and isolated strong
SVC/PendSV conflicts. Positive twins represent ten TUs/nine IR/one startup;
neither their labels nor receipts reuse the old nine-TU qualification scope.

Final local E3 on 2026-11-05 passes the bounded capture:

- Twenty-eight actual captured host-tool commands comprise three added slim-IR
  compiles, four links and 21 inspections. Ordinary/emit-relocs override links
  retain actual machine, map, resolution, response and verbose tool identities.
  Both conflict commands remain FAIL/exit 1; separate control records require
  their intended duplicate strong symbol, no timeout and no final ELF.
- Source/header/object/tool bindings, process environment and command streams
  are frozen before consumption. Completed command JSON matches its actual
  in-memory record, and the final command catalog is bound. Consumed IR, .d,
  final/machine/map/resolution and diagnostic bytes remain watched through seal.
  Full inherited trees, physical identities and source hashes close. Artifact
  membership/hash comparison and semantic/late manifest checks fail closed.
- An independent observer closes 334 artifacts and 3131 watched hashes, parses
  both actual .res files through immutable parser source, and retains every
  ordered provider/symbol row. Both have nine providers and 108 rows. The exact
  fallback provider reports PREEMPTED_IR; the application provider reports
  PREVAILING_DEF_IRONLY for panic and its marker; the exact six other panic
  providers report RESOLVED_IR. Global final panic alone is not the proof.
- Twelve pure grammar methods pass for complete provider/row counts/order,
  duplicate/truncated/trailing records, statuses, IDs, text types and purity.
  Six pure recorder methods pass for consumed-byte/physical drift, output escape,
  closing drift during intended failure, late manifest corruption and consistent
  successful sealing. These fake-tool tests execute no compiler/ELF/target.

Earlier E1/E2 remain historical. E1 did not freeze consumed generated outputs
or verify the written manifest, and its broad exception catch could confuse
closing drift with an expected tool failure. E2 fixes those paths; review then
finds the generated process-environment file was not pinned. E3 pins and checks
that file too and reruns all 28 commands. Neither earlier run is relabeled final.
The two pure grammar receipts are byte-identical deterministic independent runs.

| Evidence Or Source | SHA256 |
| --- | --- |
| `tools/fixtures/cm3_lto_link_controls/CONTRACT.md` | `4BC136D1894057B8E9EBDAA1E0A993BBBD7CCED2B0E9D51EB6977FBBEF262C8B` |
| `tools/fixtures/cm3_lto_link_controls/panic_override.c` | `4A47E0E59115F70B283AAFB39E1286330D931C592C63DBEDB6B067946E73F0E5` |
| `tools/fixtures/cm3_lto_link_controls/duplicate_svc.c` | `FD294BC5A7E458B7A463725AA2F00A2E2CD74C7C6ADF4B199412768326B87E14` |
| `tools/fixtures/cm3_lto_link_controls/duplicate_pendsv.c` | `E0B70C157F5D52C132B98B6DF5BB76150BBF759B932B0A2AF0BABB52BFB466E0` |
| `tools/fixtures/cm3_lto_link_controls/probe.py` | `CE2C86F8FB1A391977ED385636108CC24307F495D22FAE495FBD2B449DA9F99F` |
| `tools/fixtures/cm3_lto_link_controls/resolution.py` | `9EEFBB859BF703950FEF7CD1507CDE79942AE671648B5A5D73AB77C2016BD62A` |
| `tools/fixtures/cm3_lto_link_controls/test_probe.py` | `D29883E86B160BC5DDCF0B36A90918679743C66342B3462C1956FBF9B074FB7B` |
| `tools/fixtures/cm3_lto_link_controls/test_resolution.py` | `DC3FB156CC4521B4396BF57A066AFB54DAA06161B32DD4C375ABC96A44EE8E86` |
| `C:/fz-cm3-lto-link-controls-capture-20261105-e1/results.json` | `28E159661C67BF1E4D26F357127D43E5805970419333AF195FC9E53B3264821A` |
| `C:/fz-cm3-lto-link-controls-capture-20261105-e2/results.json` | `D882E8ADDB91406117FE78C4FF4F2C0239EE3A3813B5ECD7A52C80BD4D83BACC` |
| `C:/fz-cm3-lto-link-controls-capture-20261105-e3/results.json` | `957BD1BE82266C81AC09A68A1011EA1835595C2AB85B766911C90DDAC328E38B` |
| `C:/fz-cm3-lto-link-controls-capture-20261105-e3/artifacts.json` | `58CA519D5B7AD131E3A3CD57001FD7A550DB4660D1FB05F7F18DE3BB9AAACA90` |
| `%TEMP%/cm3-lto-resolution-pure-20261105-e1/results.json` | `16A33DFDF85C484587540357F392F0637633D75D5AC380230DCAF94AF2BF6B55` |
| `%TEMP%/cm3-lto-resolution-pure-20261105-e2/results.json` | `16A33DFDF85C484587540357F392F0637633D75D5AC380230DCAF94AF2BF6B55` |
| `C:/fz-cm3-lto-link-controls-observer-driver-20261105-e1/driver.py` | `E693167810A6C08D4414BBE1CBEF329EFDB831F1A484DABB3CE0824DD6030E4E` |
| `C:/fz-cm3-lto-link-controls-observer-20261105-e1/results.json` | `588D407AAA016A3AA5EFB4A6F08EBF2405C543D4EF5919F77655799838BC5380` |

Status is `CM3-LTO-FRESH-LINK-CAPTURE-PASS-NOT-QUALIFIED`. This does not yet
qualify complete strong-panic override: definition placement, final applied
call destinations, new twins/root protocols and their negative witnesses must
be independently recomposed from these new machine objects. Valid-but-mismatched
ABI/cohort/storage links remain future controls. Full ABI, source/IR semantics,
archive/other cohort/mode, CPU/board, hosted exact-SHA CI and global credits stay
unproved, with required-cell counters typed zero. No production source, frozen
helper, public/port ABI, default matrix or protected unrelated WIP was changed.

## CM3 LTO Strong-Panic Link Composition

The opt-in `tools/fixtures/cm3_lto_override/` admits the exact E3 fresh-link
capture above. It reuses authenticated immutable readers/checkers, not old
default-only PASS records, and executes no compiler, linker, emulator or target.
The scope remains native CM3 O2-lto direct linkage, ten represented TUs with
nine slim IR objects and one explicit non-LTO startup.

Final local E5 on 2026-11-05 passes:

- Both own-machine twins independently pass all 26 fixed definition roles,
  seven original named ABS32/zero-addend pointer bindings, complete vectors,
  machine/final target attributes, soft ABI flags and unique section origins.
- Both complete actual .res files retain nine ordered providers and 108 rows.
  All eight panic resolution roles are exact: original fallback PREEMPTED_IR,
  added application PREVAILING_DEF_IRONLY, six referencing providers RESOLVED_IR.
  Original weak and added strong IR symbol records are independently checked.
- Every named machine panic relocation is checked, not just calls in three
  assembly roots: 153 BL sites across 43 functions per twin. Each has an exact
  original target, addend -4, containing Thumb instruction and full kept caller
  section/map origin. Applied instruction bits and disassembly independently
  target the unique mapped strong panic definition. The emitted final has exact
  matching REL metadata; the ordinary final correctly has no residual REL.
- The frozen native transport/canonical composition runs only on the emitted
  twin: three complete first-start/SVC/PendSV bodies, 492 bytes, 170 instructions,
  13 references and zero tail NOPs. Both genuine load images compare identically.
  Ordinary canonical evidence is absent; byte equality is not relabeled as an
  independent ordinary-machine/root-REL proof.
- All 170 fresh captured-source copies bind their original buffered bytes and
  exact ordered catalog. The 28 actual command records bind argv, cwd, statuses,
  exits, errors, streams, complete catalog and environment. Each inspection
  sidecar equals its actual command stdout. Only explicit startup may physically
  alias across twin roles. Both isolated duplicate-handler controls retain exact
  added/original providers, intended diagnostic, exit 1 and absent final image.
- Closing checks cover 3364 watched hashes, physical identities, full inherited
  trees and 190 output artifacts plus the manifest. Eighteen pure synthetic
  call-audit methods pass, including non-root C callers, raw-bit/addend/target
  mutations, unsupported transfers, missing/extra REL, metadata types, aliases,
  complete map extents, mappings, purity and nonclaim preservation. Four inherited
  failure-record and six recorder methods also pass in this continuation.
- Seven guarded real CLI refusals pass: wrong receipt/manifest hashes, output
  overlap with repository/control-capture/base-capture/seed roots, and existing
  output. Every case has the intended diagnostic before any output write; the
  existing output remains unchanged. A Python audit guard rejects writes,
  descendant/tool processes, protected WIP reads and qualified parser execution.
  These admission-negative runs do not replace the separate positive ELF replay
  and do not claim semantic mutation coverage of captured command/source rows.

Earlier E1 failed before mkdir on a dependency Path/string comparison; E2 failed
closed because the emitted-only native adapter was incorrectly applied to the
ordinary ELF. E3 fixes those paths. E4 additionally binds every captured-source
row. Review then identifies missing explicit inspection-stdout equality and
cross-twin alias checks; E5 adds both and recomputes the complete result. No
earlier receipt is relabeled as the final qualification source.

| Evidence Or Source | SHA256 |
| --- | --- |
| `tools/fixtures/cm3_lto_override/calls.py` | `B7D66EFEEFB1AF48F236D80F6E03A690B73369A451C39A061BF5B75B6AEF890B` |
| `tools/fixtures/cm3_lto_override/witness.py` | `6B43C4BABE7093B06F9694490A3CFF522D599EDC1829A550D9CA3AADC680ACA9` |
| `tools/fixtures/cm3_lto_override/test_calls.py` | `75C81F0777FBC1CED215A1CF2B11A476C30AE89901DFFF653801A4C0340B7816` |
| `tools/fixtures/cm3_lto_override/CONTRACT.md` | `D7A8BBDB000412CB7058919EB3CA95C9D7BCE591FC3BEAE9B26EE6B95AD74E3E` |
| `tools/fixtures/cm3_lto_override/test_witness.py` | `986157BF7161E29BCAB605B7EB73EF7C882978EADDB855BED328B8D55B4EE2DC` |
| `%TEMP%/cm3-lto-override-calls-pure-20261105-e1/results.json` | `EF826B5536614575A53D89DB7AB2D47D2432D3B15BCECFACF5A5D07CC715E220` |
| `%TEMP%/cm3-lto-override-refusals-20261105-e1/results.json` | `B52C02AA1AD455C2350D223FAC800E3241AC09B3B2A69E9CBDEC1236EC748BFD` |
| `C:/fz-cm3-lto-override-witness-20261105-e5/results.json` | `5431E8BF0DB4C54228FCD8E8AABEA8A87E382EE82802611FD7E1B031C3F7EBEF` |
| `C:/fz-cm3-lto-override-witness-20261105-e5/artifacts.json` | `7F9EB6C3ACE3B5FF555251CBEE040C2099F08CFDE8D201F15F1DBDFBA6A93E66` |

Status is `CM3-LTO-OVERRIDE-LINK-PASS-NOT-FULL-ABI-QUALIFIED`. It closes bounded
strong-panic selection/applied-call and duplicate-handler link evidence only.
Full callable ABI, C-panic body/IR/source-to-machine semantics, original-TU machine
ownership, all unrelocated transfers and whole-object/kernel behavior are not
inferred. Valid-but-mismatched ABI/cohort/storage links, archive extraction,
other modes/cohorts, fresh reference parity, CPU/board, hosted exact-SHA CI and
global freeze remain independent gates. Required-cell counters stay typed zero.
No production source, frozen helper, public/port ABI, default matrix or protected
unrelated WIP was changed.

## CM3 LTO Private-Policy Cohort Controls

The opt-in `tools/fixtures/cm3_lto_cohort_controls/` starts a separate exact
private-policy mismatch cohort, not another architecture or storage revision.
CM3 P4 permits both raw BASEPRI16 and BASEPRI32. Four selected providers are
recompiled from the admitted C/header bytes: runtime, boot, exception and build
expectation. The single legacy compile definition changes 16 to 32 in place;
duplicate or separate canonical counterdefinitions are rejected. Every other
compile flag and actual dependency/path/hash set is preserved.

Actual dependencies of the three common TUs and public application contain no
private port macro/header/cohort dependency. They are reused unchanged with
their original recorded recipe, as is the explicit native startup. Each link
still represents nine TUs/eight slim IR/one native startup. No panic override,
duplicate-handler fixture, invented anchor or production source edit is added.
Private key bits change `_u00010000_` to `_u00100000_`; all other key fields and
`fiber_port_storage_cohort_arm_cm3_v1_r0` remain unchanged. The grammar binds
all 15 actual runtime IR definitions in each policy, not a substring alone.

Local E1 on 2026-11-05 passes the bounded capture:

- Fifty-two host-tool commands comprise four compiles, 36 inspections and
  twelve links. Four matching positives cover both policies and both ordinary/
  emit-relocs variants. All use actual slim IR and captured native startup.
- Eight isolated negatives replace runtime/boot/exception/expectation one at a
  time in both directions. Every failure has exactly the expected full missing
  private key, exit 1, no timeout and no final ELF. The strict complete diagnostic
  grammar rejects extra undefined names, compiler/tool errors and unrelated
  linker text. Recorded commands remain FAIL while intended controls pass.
- Positives retain verbose worker traces. Negative link argv differs only by
  removal of `-v`; semantic target/O2/LTO/GC flags and provider order are kept.
  This is explicit diagnostic isolation, not a claim of per-negative verbose
  worker tracing or of equal final bytes between different scheduler policies.
- Raw dependencies, sources, slim objects, generated maps/machines/finals/.res,
  environment, JSON/stdout/stderr and catalog are pinned through closing checks.
  Independent operator checks verify all 512 artifacts plus manifest, 3227
  watched hashes, all 52 command rows and inspection-sidecar/stdout equality.
- Fourteen pure synthetic methods pass: eight identity/diagnostic grammar and
  six recorder/control methods. Coverage includes exact row/order/key/storage
  facts, all eight swap directions, missing/extra diagnostics, counterdefinitions,
  source/record/stream failures, closing-failure propagation and compile-failure
  nonpromotion. The first pure run exposed Path argv serialization in the fake
  tool; the fixture now matches the real runner's string argv behavior. E2 passes
  without weakening the error assertion or changing the actual capture source.

| Evidence Or Source | SHA256 |
| --- | --- |
| `tools/fixtures/cm3_lto_cohort_controls/CONTRACT.md` | `3F2A78F4F3CEA062B8A6898C65560F75AF9DFAEC7CAA2D385C074CF3453206EF` |
| `tools/fixtures/cm3_lto_cohort_controls/identity.py` | `360485D634AC85AF37B78AAB45E622E568063CDE32F45250037F4C718F13732B` |
| `tools/fixtures/cm3_lto_cohort_controls/probe.py` | `E3FD2717BF7524EE433578E18903748932B8F602A79B7C6FD9B7E34105F9CC8F` |
| `tools/fixtures/cm3_lto_cohort_controls/test_probe.py` | `0140142D97CFAB8D6F44C72C6B02F9634EA37963D6AD544CDFE58D4A563686FF` |
| `%TEMP%/cm3-lto-cohort-controls-pure-20261105-e2/results.json` | `6C9CDB897F515001E9CC8462EC12B414ADEFF40D2EE05432E38EEA87697221CD` |
| `C:/fz-cm3-lto-cohort-controls-capture-20261105-e1/results.json` | `60B6C34BCDF4FB19D0A4F33ACC203722D92FBBF6837A7819EE5BA48B88E82F56` |
| `C:/fz-cm3-lto-cohort-controls-capture-20261105-e1/artifacts.json` | `2D40396C0B809FDB1B4BD24C9F22B795855D393C3F6CF79C3803133BC8D1346C` |

Status is `CM3-LTO-COHORT-CONTROL-CAPTURE-PASS-NOT-QUALIFIED`. It captures valid
matching links and intended private-policy mismatch refusals. Positive complete
resolution, final-map/ELF/root/callable ABI and parity qualification are not
inferred from this capture; the old fixed-b16 readers/checkers are not widened
to accept b32. Storage-revision and reverse-version mismatch, archives, other
modes/cohorts, priority/kernel behavior, CPU/board, hosted exact-SHA CI and global
freeze remain independent. Required-cell credit stays typed integer zero.
Production, frozen helpers, default matrix and protected unrelated WIP remain
unchanged.

## CM3 LTO Private-Cohort Independent Replay

The opt-in `tools/fixtures/cm3_lto_cohort/` independently composes the bounded
policy16/32 capture above. Caller-supplied hashes bind the complete capture,
artifacts, native/seed/inventory trees, recorded source/tool inputs and physical
identities before any output creation. The retained commands are authenticated,
not rerun; no compiler, linker, emulator or target executes in this replay.

Local E1 on 2026-11-05 passes:

- The complete ordered captured-source catalog and recompiled source copies
  equal admitted immutable bytes. Each of four changed recipes replaces only
  the single legacy BASEPRI16 definition with 32; actual raw `.d` membership and
  hashes remain exact. Recompiled ELF section metadata proves slim IR without
  a native fallback. Both real runtime NM buffers bind the 15 exact definitions,
  policy-specific private key and unchanged storage key.
- Four final audits each bind 26 exact definitions, full original machine/startup
  section placements and extents, soft CM3 attributes/ELF flags, LOCAL reverse-v1
  anchor/current slot, read-only identities/tables and the complete strong-vector
  template. Seven original named ABS32/zero-addend pointers target the exact
  mapped definitions. Emitted finals require seven matching applied RELs; both
  ordinary finals require their absence and the correct applied pointer words.
- Policy16 calls the unchanged fixed audit. Policy32 has an explicit local
  composition of the same immutable predicates with only its private identity
  selection changed. Neither frozen globals nor core objects are mutated.
  This does not silently extend the old b16 canonical or instruction checker.
- Four complete raw `.res` files retain eight ordered source-bound providers and
  106 rows each. A separate eight-provider grammar enforces unique symbol/unit
  identities and exact private roles: runtime prevailing, boot/exception/build
  expectation resolved. Storage remains runtime prevailing/public consumer
  resolved. Foreign identities, truncation and extra rows fail closed.
- All 52 raw command records/catalog rows bind exact argv, cwd, status, exit,
  timeout/error family, streams and environment. Each inspection sidecar equals
  actual stdout. Eight isolated swaps bind their one changed provider, precise
  missing full private key, raw diagnostic and absent final ELF. The negative
  recipe removes only `-v`; command FAIL remains distinct from control PASS.
- Both within-policy ordinary/emit load-image pairs compare identically. The
  shared native startup is the only permitted physical alias among binary roles.
  Closing checks cover 205 artifacts plus manifest, 3556 watched hashes, 172
  copied immutable source buffers and 32 binary roles. An independent operator
  audit rehashes the complete receipt/artifact/input closure and result shape.
- Twenty pure static-audit methods pass for both policies, typed selectors,
  exact public/port surfaces, aliases/providers/maps/extents, headers/attributes,
  slot/identity storage, original/applied pointer roles and vectors. Twelve pure
  resolution methods pass for counts/order/grammar, parameter types, duplicates,
  distinct units, both private/storage role sets, line endings and foreign keys.

Review confirms no omitted b32 static predicates or admission blocker. Failure
handling explicitly clears the top-level mismatch/final-link claims on any
closing failure; partial details may remain only in a FAIL receipt. This replay
does not manufacture ordinary RELs or transfer b16 canonical evidence to b32.

| Evidence Or Source | SHA256 |
| --- | --- |
| `tools/fixtures/cm3_lto_cohort/CONTRACT.md` | `0A3C320B1BA300F6F6AD8DFBCDBC37F3BF9E3538CF3F6F46CF85FB38B1556F19` |
| `tools/fixtures/cm3_lto_cohort/audit.py` | `B661490EB975271FBBCD883CE8C8FE43D974D07A26FDB5E65DF5156CCEEA0AEE` |
| `tools/fixtures/cm3_lto_cohort/resolution.py` | `A7A0956C61C2E164C9823EECEBF1A22401C4294046975B5FB791C2E17432BB55` |
| `tools/fixtures/cm3_lto_cohort/witness.py` | `78F0FB9B82DA16DBA13EB2AD50A5616666AA2D731A5151631A919E86442F4BBF` |
| `tools/fixtures/cm3_lto_cohort/test_audit.py` | `6F6807AE2112CBC6F74ADDED6F3BEAC481339C8E28BCA2E2D7C8CB6D47CA3FD9` |
| `tools/fixtures/cm3_lto_cohort/test_resolution.py` | `B8B9AA084F248A556E91F7BA0EC2943FAB7A6F9844B7A246C91184A800F2539D` |
| `%TEMP%/cm3-lto-cohort-link-pure-20261105-e1/results.json` | `7D2476387C9949B62B39C81A2355CFF50B429BE989F95FB40C35F0CE719D3E58` |
| `%TEMP%/cm3-lto-cohort-resolution-pure-20261105-e1/results.json` | `411C61221B3F96FF9CF9BC3B1E69B9047B25299AFAAE3632B3178D953A930D36` |
| `C:/fz-cm3-lto-policy-witness-20261105-e1/results.json` | `B4D77319C081000A52228431B2FEAB1FA402AE1A280F366D5095E17C47A06049` |
| `C:/fz-cm3-lto-policy-witness-20261105-e1/artifacts.json` | `22A2C159406EC7444886D86A7C7C67AE66D8AB6983BFA5E52B7B9282AAD0B783` |

Status is `CM3-LTO-POLICY-COHORT-LINK-PASS-NOT-FULL-ABI-QUALIFIED`. Only the
bounded static/private-policy link proof is closed. Full callable ABI, source/
IR semantics, original-TU machine ownership, storage-revision and reverse-version
mismatch, b32 root/REL/canonical and fresh native/reference parity remain
unproved. Archives, other modes/cohorts, runtime priority/kernel behavior,
CPU/board, hosted exact-SHA CI and global freeze remain independent gates.
Required-cell credit stays typed integer zero. No production, frozen-helper,
public/port ABI, default-matrix or protected unrelated WIP change is made.

## CM3 Os-LTO Capture

The additive `tools/fixtures/cm3_os_lto_transport/` captures the next missing
optimization transport for the fixed CM3 soft p4/BASEPRI16 direct cohort. Its
factory reuses the frozen native tool/source/seed closure and the separately
pinned reference admission/capture plumbing. No frozen module globals, expected
symbols, root predicates or production sources are changed.

Each source, including startup, replaces the sole admitted `-O2` token with
`-Os` in place. The C sources add `-flto -fno-fat-lto-objects`; native startup
does not. Both fresh final link recipes independently make the same optimization
replacement while retaining single-partition LTO, explicit plugin retention,
verbose worker capture, exact provider order, section GC, script and target ABI.
Actual dependency sets must match the admitted seed; all section-header records
are accounted for, and slim IR must contain no executable fat fallback.

Local E1 on 2026-11-05 passes:

- Native: nine newly compiled TUs, eight slim IR objects plus one startup,
  two final executable links and two real saved machine objects. There are 57
  successful commands, 1,464 artifacts plus manifest and 1,402 watched inputs.
- Pinned FreeRTOS reference: four newly compiled TUs, three slim IR objects plus
  one startup, two final executable links and two real saved machine objects.
  There are 37 successful commands, 1,350 artifacts plus manifest and 1,269
  watched inputs. The upstream pin remains
  `a50edad08b29052631aa469d4df6e6ec7ff68878`.
- Each side independently compares its ordinary and emitted-relocation final
  load images using the authenticated unchanged reader. Both pairs are identical;
  no native/reference or O2/Os byte-equivalence claim follows.
- An independent operator audit rehashes every artifact and watched input,
  compares full raw command JSON to the catalog, requires successful outcomes,
  binds inspection sidecars to stdout, and checks all compile/link Os flags,
  per-source seed transforms, counts and non-promoting result flags.

The read-only architecture review finds no confirmed main/seed blocker. The
fixed helper hashes match; the producer is frozen before both actual captures.
Status `PASS` is explicitly scoped to native/reference Os-LTO capture
feasibility, not qualified root, protocol, callable ABI or parity evidence.
The retained post-LTO symbols and layouts must still be independently checked
against the actual Os machine-to-final origins and complete canonical bodies;
the O2 checker's fixed scope is not widened or relabeled.

Fourteen pure synthetic control methods also pass without launching processes.
They cover exact flag/side transforms, both complete source groups, compile
dependencies, slim/startup distinctions, object hashes/counts, two independent
link invocations, extra-partition and command failures, incomplete results and
late closing-failure nonpromotion. Synthetic objects/metadata are not genuine
ELF or IR evidence; the two actual capture receipts above are separate.

| Evidence Or Source | SHA256 |
| --- | --- |
| `tools/fixtures/cm3_os_lto_transport/CONTRACT.md` | `BB82C9C700A34D99C102A6B248DA3BC388C51249241BA5E7C7471114AE7376D5` |
| `tools/fixtures/cm3_os_lto_transport/probe.py` | `F5F75D7439B97049B5440695CB78862AA0815D7E1E69224BDBDC2B9AADE2AD01` |
| `tools/fixtures/cm3_os_lto_transport/test_probe.py` | `498CADE649621A7C83DBE14B85E350D46261D4037200B85C1EEBFEE28FCA82DA` |
| `%TEMP%/cm3-os-lto-transport-pure-20261105-e1/results.json` | `B3FB66862D968291A5ADDA367DE6BD267DBA29B8EA0FB3B5F4DFB7A8DECA10B8` |
| `C:/fz-cm3-os-lto-native-20261105-e1/results.json` | `E4B756AD671D51E4505ABB381031891C79765D5A8F5E5064EB63A2D33AD1916D` |
| `C:/fz-cm3-os-lto-native-20261105-e1/artifacts.json` | `D1B3823ABBA3610D3C6701F31C66E38F1040B96481D317592431AD685FAF5F79` |
| `C:/fz-cm3-os-lto-reference-20261105-e1/results.json` | `DF57936A48EAF1AD9AB2F8CD56B4EF14839697CAA85E78C278CDB830921E43B8` |
| `C:/fz-cm3-os-lto-reference-20261105-e1/artifacts.json` | `B22441D816BE8E3AD5C4A8127B5282643196FDF851A48FF4283DDE045F0EF900` |

Full ABI, source/IR semantics, policy/kernel equivalence, whole-object proof,
archives, CPU/board execution, exact-SHA hosted CI and global freeze remain
separate. Required-cell credit remains typed integer zero. No production,
frozen helper, default matrix or protected unrelated WIP is changed.

## CM3 Os-LTO Six-Body Replay

The separate `tools/fixtures/cm3_os_lto_join/` admits the two fresh Os captures
above, including their complete artifact trees, original O2 seeds/inventory,
source/dependency/configuration authority, tools and recorded commands. Before
creating output, it authenticates the capture producer and all frozen helpers.
It reconstructs all 57 native and 37 reference argv/cwd/stream bindings, exact
Os transforms, slim/startup inputs, section records and cloned-tool identities.
Both original seed closures remain live through final closing so membership
watches are not lost when hashes are merged. Nested Seed loader execution uses
the already authenticated immutable source buffers, not a transient live file.

Local E4 on 2026-11-05 passes:

- Native emitted final: three complete roots, 492 bytes, 170 instructions,
  thirteen original/applied REL references. Reference emitted final: three
  complete roots, 136 bytes, 39 instructions and three REL references. The
  unchanged adapters check raw symbols, bounds, mappings, full provider/map
  section placement, addends, decoded destinations and every non-relocated byte.
- The same actual machines feed the unchanged decoder and protocol views, then
  the unchanged six-body checker. All six bodies, three mechanism assignments,
  zero tail NOPs and six captured master-ledger rationales pass. The separately
  pinned CM3 policy ledger is authenticated too; it is specialization, not a
  substitute for the captured master ledger. Native keeps its two origin-proved
  slot projections and nine-word saved-LR frame; reference keeps its raw named
  slot tokens, eight-word frame and `orr lr,lr,#13` first return.
- Sixteen actual private transport controls per side reject at their expected
  families. One coherent SVC-immediate mutation per side changes real machine
  and final bytes plus disassemblies: all three transport roots still preserve,
  but the complete canonical protocol rejects the intended changed constant.
  These 34 controls run anew; old receipts are not substituted for execution.
- Both within-side ordinary/emitted load images are recomputed as identical.
  The ordinary images have no independent root-relocation proof; equality does
  not transfer emitted metadata or source/IR authority to them.
- Closing covers 634 artifacts plus manifest, 5,609 watched hashes, 445 source
  copies and fourteen physically distinct positive binary roles. An independent
  operator audit rehashes all artifacts/inputs/copies and checks the result,
  command-binding counts, controls, identities and nonpromotion flags.
- Ten pure composition, five pure physical-identity and five pure
  sealing/control-binding methods pass.
  They are synthetic evidence, separate from the actual Os ELF replay above.

E1 refused before output creation because installed
`C:/Program Files/Git/cmd/git.exe` has two hard links. This file is already
authenticated as the reference seed's external Git tool and is never executed
or used as an ELF provider in the replay. The corrected guard admits multiple
links only for that exact seed-validated Git identity; it still closes hash,
device, file ID and link count. All other inputs/outputs remain single-link,
and the fourteen-role alias check is unchanged. The five pure tests reject
non-Git multi-links, lookalikes, zero links, regular-file failures and closing
identity drift. E1 left no output directory and has no successful receipt.

E2 is a retained preliminary PASS at an earlier witness revision, not the
current closing proof. Review then required direct binding of each control's
returned hashes/physical identities and of the intended serialized receipt.
E3 remains FAIL: that new receipt comparison used LF while the frozen writer
uses Windows CRLF. E4 corrects the representation using the writer's platform
newline semantics. Its manifest hashes the intended receipt bytes, excludes
the actual receipt from the learned file map, and rechecks actual output
after manifest writing and at late closing. The failed E3 run is not relabeled.
The five sealing methods exercise platform-default serialization, immediate
and post-write receipt substitution, recorded control hash/path/identity drift,
and matching closure with generated temporary files. They do not execute the
witness constructor, compiler, linker or retained ELF.

| Source or local evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_os_lto_join/CONTRACT.md` | `7FF9B2EF1896268DC5415DDA33396A5800FB2137D744B02830F64ACC2EDD64C7` |
| `tools/fixtures/cm3_os_lto_join/compose.py` | `359BB0E7463F4514F5964529702DDC07CCED773927970AC3C246A1B7E845367E` |
| `tools/fixtures/cm3_os_lto_join/witness.py` | `BEC9C699F8C62A69CB2BF35B24CF51D8815329517F83A11517BF9657D294D7AB` |
| `tools/fixtures/cm3_os_lto_join/test_compose.py` | `5F07F9F944E6B7DC2DED82C3BC4B4D12EF99BA30BF0EF3F86E6A6E7C97DA2896` |
| `tools/fixtures/cm3_os_lto_join/test_identity.py` | `CA6EDE2A5D81F51898041C6A9D92998B6B0E0C7C685DC25D9FF27DE407649C12` |
| `tools/fixtures/cm3_os_lto_join/test_seal.py` | `A99058C826929760B860F010801DD79C198D800A8412C1CE5C5C70DEF02B2078` |
| `%TEMP%/cm3-os-lto-join-pure-20261105-e1/results.json` | `2BC6BA58340D3FA5FFCA1D658A2CBC6809166BDCED25CB464363A55B99C81B8E` |
| `%TEMP%/cm3-os-lto-identity-pure-20261105-e3/results.json` | `5CDE9578272CBC012D6B80154689596DA187B06CFD20D77F1E7CA889FF5B2F1F` |
| `%TEMP%/cm3-os-lto-join-seal-pure-20261105-e1/results.json` | `514BA6FAF850CF960D49EC5E000804ECFBCB9EA4AA8ADB2A0EE03F3BA88C16AF` |
| `C:/fz-cm3-os-lto-join-witness-20261105-e3/results.json` (FAIL) | `D9BC26FF22EC20968C5E994BE79557EC0EBBEA3931EA401EB722465F37C30B7F` |
| `C:/fz-cm3-os-lto-join-witness-20261105-e3/artifacts.json` (FAIL) | `8E2DDF7BE78C0B83C3D4FDC567F3D26C809BCE345F4F73757416DEB72B4E6CF3` |
| `C:/fz-cm3-os-lto-join-witness-20261105-e4/results.json` | `EE5229483754CB3A6F485DB24F0E7201029ABAE1B869AA4C6FF660CDCD4E4626` |
| `C:/fz-cm3-os-lto-join-witness-20261105-e4/artifacts.json` | `FAE1DC08D04099128477501018693E89EA7735F63607F78261B0A2A6F0B46F3C` |

The independent replay is not a compiler, linker, emulator or target execution.
It closes only the bounded Os-LTO six-body transport/canonical/difference
composition. Full API/callable ABI, C/IR semantics, original per-TU machine
ownership, whole-object/kernel/policy equivalence, archive/other-cohort coverage,
global seven-mode qualification, board and hosted exact-SHA CI remain separate.
Required-cell credit is typed integer zero. No production, frozen helper,
default-matrix or protected unrelated WIP change is made.

## CM3 O2-LTO Indexed Archive Capture

The opt-in `tools/fixtures/cm3_lto_archive/probe.py` captures the actual native
static-library route for the fixed soft CM3 p4/BASEPRI16 cohort. The unchanged
ordinary-O2 seed receipt and manifest are caller-authenticated before capture.
All nine translation units compile afresh; eight C inputs are genuine slim IR
and startup remains native assembly. The indexed archive contains exactly
Context core/state/panic and CM3 runtime/boot/exception (seed indices 0..5).
Explicit startup, application and cohort expectation (8/7/6) precede it.
No whole-archive, forced undefined symbols, extra anchors, rescue providers or
production/linker-script changes are used.

The archiver is an explicit extension to the seed's tool inventory, not a
silently accepted ambient executable: its caller-supplied SHA-256 is
`F90685490B207A237A5BD0D32CDC35A8653E682D9313BBE12907712D128299A5`.
It must be the admitted GCC sibling, is copied into the private toolchain,
and uses the same captured LTO plugin explicitly. Hash and physical identities
of the original and cloned archiver close. Helper execution uses the single
authenticated source buffers; the receipt seals intended platform-serialized
bytes rather than relearning its expected hash from the written file.

Local E2 on 2026-11-05 passes capture:

- Nine fresh units, eight slim IR objects, one deterministic-header indexed
  archive and two successful actual final executable links. Repeated-build
  byte determinism is not claimed.
- The archive is 107,394 bytes with six members and 48 raw index entries.
  Member order, headers, complete payloads, raw index offsets, actual `ar t`
  listing and plugin-aware `nm` index output are retained. Each raw payload
  equals both its newly compiled object and its private `ar x` extraction.
- Both ordinary and emit-relocs maps record six actual inclusion reasons:
  application -> Context core/panic; core -> state; state -> port runtime;
  runtime -> boot/exception. This is extraction evidence for the fixed consumer,
  not independent full provider-resolution or callable-ABI qualification.
- Both links retain their own generated LTRANS machine, map, resolution file,
  verbose worker traces and machine/final inspections. The authenticated
  unchanged comparator reports identical within-side load images. No old
  direct-link machine substitutes for these new artifacts.
- Independent operator audit rehashes all 1,505 artifacts plus manifest, 1,415
  watched inputs and 1,367 input copies; independently parses member/index
  bytes, rechecks the exact four link inputs, 66 successful command records,
  both raw map inclusion tables and both final PT_LOAD images.
- Eleven pure methods pass: raw GNU archive grammar/index, required index NUL
  alignment, exact object roles/recipe, capture-only flags, and file-based
  extraction despite altered stdout. Synthetic controls do not execute tools.

E1 remains FAIL at the first extraction byte comparison. The raw archive and
object were equal (9,304 bytes), but Windows `ar p` text stdout expanded LF to
CRLF (9,325 bytes). E2 uses files produced by `ar x` in a fresh private
directory; it never repairs or normalizes binary stdout. That platform defect
was in this new capture harness, not production assembly or member contents.
The original ten-method E1 pure result is historical; the current eleven-method
E2 result covers the corrected producer. An earlier malformed hash argument
was refused before output creation and did not produce a capture receipt.

| Source or local evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_lto_archive/CONTRACT.md` | `7022A32FFB7987D11D89A71AFBE4A83167953A1807C44E7E3AB214589EE918E7` |
| `tools/fixtures/cm3_lto_archive/probe.py` | `E2E068AEBEE77E344EA924B08CCE61E0B57D0B5B2F04652D9391680351655FF7` |
| `tools/fixtures/cm3_lto_archive/test_probe.py` | `753CBA2319A65B0A6E8EA7E7F9EE11E369E7188DC8B3EFB83C69938B88FA5D3A` |
| `%TEMP%/cm3-lto-archive-pure-20261105-e2/results.json` | `4F6A93379FED189DE8BFD3D4797D7E3F94B2FE557CC5D825F8E5F41322EF7D75` |
| `C:/fz-cm3-lto-archive-20261105-e1/results.json` (FAIL) | `2A2A15C4C86C3456E711F13872A2BE35C19E21BD4100279D4FA6CAE6E532EEEF` |
| `C:/fz-cm3-lto-archive-20261105-e1/artifacts.json` (FAIL) | `2099F1356B0571AE9685C30D4899C96B9B95AD175180E034D2FB63BF0AC3665C` |
| `C:/fz-cm3-lto-archive-20261105-e2/results.json` | `2811E3BB558BE7C6E93D20D1B24CE68AA6EB607630D74235B4219C0644AFF34E` |
| `C:/fz-cm3-lto-archive-20261105-e2/artifacts.json` | `A5C5028132CB91216A0CDAF9C7A2B3569FAF26992DD838A17802FF1BD7C2D954` |
| `C:/fz-cm3-lto-archive-20261105-e2/archive/libcm3_context.a` | `7467B1D6FBE0EDD8559097BD72503D742D52039AFB036F5492F125481A7A6117` |

The receipt deliberately keeps `ArchiveExtraction` and
`ArchiveExtractionQualified` false: `ArchiveCaptureComplete` is not a substitute
for independent qualification. Root preservation, canonical protocols and
pinned-reference composition must replay these actual archive-link machines.
Full API/ABI, source/IR equivalence, general archive behavior, startup weak-alias
precedence, override/cohort negatives through archives, other modes/cohorts,
runtime, CPU/board, hosted exact-SHA CI and global freeze remain separate.
Required-cell credit is typed integer zero. Production sources, frozen helpers,
default matrix and protected unrelated WIP are unchanged.

## CM3 O2-LTO Archive Native Root Replay

The separate read-only `tools/fixtures/cm3_lto_archive_roots/witness.py`
authenticates the actual E2 indexed-archive capture above, not a direct-link
receipt with changed labels. It independently reconstructs the exact archive
scope, original O2 seed, nine source/dependency bindings, private toolchain,
archive members/index/extracted bytes, explicit 8/7/6-plus-archive providers and
all 66 command/stream records. Raw extraction maps and resolution/temp files
remain provenance, not a per-original-TU post-LTO machine-ownership claim.

Local E1 on 2026-11-05 passes:

- Three complete emitted native roots: SVC 184 bytes / 64 instructions /
  five REL references; PendSV 204 / 72 / six; first-start 104 / 34 / two.
  The unchanged adapter checks full symbol/bounds, load/mapping, actual
  machine/startup provider origin, full input-section placement, original
  addends, applied branch/literal targets and every non-relocated byte.
- The same actual saved machine and its own disassembly feed the unchanged
  decoder and native canonical checker. All three bodies close with exact
  zero tail NOPs. Raw transport records retain their false canonical flags;
  the new enclosing protocol result is separate. Two origin-proved slot-role
  projections do not replace the raw token/hash domains.
- Sixteen actual private transport mutations reject with their fixed catalog
  identities/families. One coherent SVC-immediate control changes real machine
  and final bytes plus both disassemblies: all three changed transports still
  preserve, then the full canonical check rejects the intended constant.
  Returned control files, hashes, roles and available identities close.
- The unchanged comparator recomputes identical ordinary/emitted load images.
  This does not transfer emitted metadata or independent root/canonical proof
  to the ordinary image.
- Closing covers 354 artifacts plus manifest, 3,231 watched hashes, 260
  immutable source buffers and seven distinct positive input roles. An
  independent operator audit rehashes complete output/input memberships,
  source/binary copies and all control-file records, and verifies root totals,
  full-body counts, exact control counts and nonpromotion flags.
- Ten separate pure methods pass for archive-specific typed admission,
  member/object/extraction bindings, fixed provider order, direct-receipt
  relabel refusal and reuse of the frozen complete native protocol helpers.
  They are synthetic controls, not another actual ELF replay.

| Source or local evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_lto_archive_roots/CONTRACT.md` | `FA03C22CCEEC310B1510BEA92CB477C4A27C398F3425DA4DFAFBFEFC058F7510` |
| `tools/fixtures/cm3_lto_archive_roots/witness.py` | `7D65BACFC6CDCFA4B02324905693675A1CA26AEDF92008415CC77645A94E1A6A` |
| `tools/fixtures/cm3_lto_archive_roots/test_witness.py` | `A4B657E96C8A8DDC8B4B634D89B8B73ED297FF78853579E49E18CF02A8385F03` |
| `%TEMP%/cm3-lto-archive-roots-pure-20261105-e1/results.json` | `6FAB9C64DC43AB895793DFD9CCE0BB6B1A457F9B0E79A1C6FA912FA3CC6DF73E` |
| `C:/fz-cm3-lto-archive-roots-witness-20261105-e1/results.json` | `17A11CF3671FDF94240271ED921D56258B447E1448F594135463F1DF0ADF0092` |
| `C:/fz-cm3-lto-archive-roots-witness-20261105-e1/artifacts.json` | `C2203D41166B3C41335418988F80FDF55296823CADB7432380E76515FCF8D4F3` |

The result is native emitted archive-LTO root/canonical evidence only. A fresh
pinned FreeRTOS archive pair, full API/callable ABI, C/IR and original-TU
semantics, general extraction/weak-alias or override/cohort-negative behavior,
whole-kernel/policy correctness, other modes/cohorts, CPU/board, hosted CI and
global freeze remain separate. No compiler, linker, emulator or target runs
in this replay. Required-cell credit stays typed integer zero. Production,
frozen helpers, default matrix and protected unrelated WIP are unchanged.

## Pinned CM3 O2-LTO Reference Archive Capture

The opt-in `tools/fixtures/cm3_reference_lto_archive/probe.py` admits the
original ordinary-O2 pinned reference seed independently and recompiles its
four sources for the CM3 soft p4/BASEPRI16 cohort. Only the new port object is
archived. The exact explicit link order is source indices 3/2/1 (startup,
consumer, typed providers), then the archive. There is no direct port duplicate,
whole-archive, forced undefined root, rescue anchor or source/script change.

Local E1 on 2026-11-05 passes capture:

- Four fresh translation units: three genuine slim IR C objects and native
  startup. Both ordinary and emit-relocs final executable links retain their
  own saved LTRANS machine, map, resolution, verbose worker traces and raw
  inspections. The 41 recorded commands all finish successfully.
- The regular GNU archive is 15,964 bytes with one `00-port.o` member and ten
  index entries. Complete raw member bytes equal the new compiled object and
  private binary-file extraction. Both raw maps record inclusion by startup's
  `vPortSVCHandler` reference. This is this consumer's extraction evidence, not
  a general weak-alias or provider-resolution qualification.
- The parser accepts only the bounded GNU index/member grammar, including
  exact index alignment padding and an optional single `//` name table; it
  refuses foreign/duplicate records. No long-name member is needed or admitted.
  Binary `ar x` files, not text stdout or newline normalization, are authority.
- Independent operator checks rehash exact memberships of 1,372 artifacts
  plus manifest, all 1,278 watched inputs and 1,235 original/copied input pairs;
  bind every command sidecar to the catalog; independently parse raw archive
  index/member bytes, both exact link recipes and map inclusion tables; and
  recompute matching within-side final PT_LOAD structures, bytes and entry.
- Ten separate pure methods pass, including archive/index boundaries, optional
  table grammar, fixed four-TU recipe, file-based extraction and prepare-path
  smoke coverage. These tests do not execute target code.

| Source or local evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_reference_lto_archive/CONTRACT.md` | `5BE49FDCFB84B0AC9823314A6C7D1E90455F5A1074BA7D7A6B608C238498BD0B` |
| `tools/fixtures/cm3_reference_lto_archive/probe.py` | `966501D5AB3F8D5EC33375514FC9CA5E43833564DBFA6684D0C1A4E61702BB3B` |
| `tools/fixtures/cm3_reference_lto_archive/test_probe.py` | `71986A1BC1EBD3CA354835A92C5FAB412BDF80AF79CF7D8AE414726DFAD54DFF` |
| `%TEMP%/cm3-reference-lto-archive-pure-20261105-e1/results.json` | `6974346C2EA4DA527937A178C0EBBC7EBE9A827B458D660EC47DC8FDA6E8829F` |
| `C:/fz-cm3-reference-lto-archive-20261105-e1/results.json` | `C4933DB832AEEC664F320CF8478D640BA4C80A915095B1E12B27109580B56DDD` |
| `C:/fz-cm3-reference-lto-archive-20261105-e1/artifacts.json` | `4BE6CAEC090F743A75B8986D3482CD92E3B439132FC36CEB6B19BF1D17F8369E` |
| `C:/fz-cm3-reference-lto-archive-20261105-e1/archive/libfreertos_cm3.a` | `E7E1BD06598E9D01D571488F992B789C5A360FFCBC603ADD33B7EE2D3EB12B16` |

The typed provider fixture is not the real FreeRTOS kernel, scheduler or runtime.
Capture PASS does not promote the new reference machine to root/canonical
qualification or paired native-reference parity. Those must replay these
actual new archive artifacts with the unchanged adapters and difference ledger.
Full callable ABI, source/IR and original-TU semantics, general archive and
weak-alias behavior, other modes/cohorts, CPU/board execution, hosted exact-SHA
CI and global freeze remain separate. Required-cell credit is typed integer
zero. Production, frozen helpers, default matrix and protected unrelated WIP
are unchanged.

## CM3 O2-LTO Paired Archive Replay

The read-only `tools/fixtures/cm3_lto_archive_join/witness.py` independently
authenticates the native archive E2 and pinned-reference archive E1 captures
above, both original O2 seeds and the same captured E8 source inventory. Native
retains six members with explicit startup/application/expectation before the
archive; reference retains one pinned port member with explicit startup,
consumer and typed providers. Complete raw archive/index/member/extracted
bytes, dependencies, tools, plugin/worker identities and all 66 native plus
41 reference command/stream bindings are reconstructed before interpretation.

Local E1 on 2026-11-05 passes:

- Six complete emitted roots: native SVC 184 bytes / 64 instructions / five
  REL references, PendSV 204 / 72 / six, first-start 104 / 34 / two; reference
  first-start 32 / 10 / zero, SVC 36 / 10 / one, PendSV 68 / 19 / two.
  The unchanged adapters retain owning-section placement, original REL
  addends, provider/map origins, full symbols, mapping/pool boundaries,
  applied targets and non-relocated bytes.
- Full canonical decoding of the same actual generated machines closes all
  six bodies with zero tail NOPs. Three exact mechanism assignments and six
  difference rationales close against the identical captured master ledger
  and fixed `cm3_final_join/POLICY_DIFFERENCES.md`. Native's two origin-proved
  current-slot projections remain distinct from raw transport/token domains.
  Raw root records retain their original false canonical flags; the enclosing
  recomputed protocol proof is separate. Neither frame nor mask-policy
  differences are normalized into an instruction-equivalence claim.
- All 32 private transport mutations and two coherent SVC-immediate controls
  execute anew. Each coherent control first passes preservation of all three
  changed transport roots, then rejects the intended full canonical constant.
  Returned private file hashes, exact memberships and available identities
  close. No earlier native control receipt substitutes for this run.
- Each ordinary/emitted own-side load image is recomputed as identical.
  This does not compare native and reference images for byte equality or
  transfer emitted root metadata/proofs to the ordinary image.
- Closing covers 636 artifacts plus manifest, 5,676 watched hashes, 447
  immutable source copies, fourteen physically distinct positive roles and
  sixty immutable helper execution records. A separate operator audit rehashes
  both complete producer trees and all witness input/output/copy/control
  records; independently binds each raw final and generated-machine root body
  hash; checks full root/count/nonpromotion fields; and parses both own-side
  final PT_LOAD structures, bytes and entries.
- Ten separate pure methods pass: exact side-specific scopes/counts/commands,
  literal flags and typed zero credit, direct-receipt relabel refusal, six/one
  member bindings, optional GNU name-table grammar, provider order, hash/raw/
  projection/tail substitution and unique substantive difference rationales.

The only permitted multiple-hardlink input is the exact authenticated installed
Git executable used as nonexecuted reference provenance. Its hash and physical
identity close; no input-role or parser/tool alias exemption is implied.
No compiler, linker, emulator, target or board executes in this replay.

| Source or local evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_lto_archive_join/CONTRACT.md` | `F50A5B0525F4FA93EA3BDFFA9D26C995E13111303B9D51DDB700CA02706A2DED` |
| `tools/fixtures/cm3_lto_archive_join/witness.py` | `FFD12847C2362F4145F5F1693A7AAFD9FEAC0D30FAA2CC1AF8FF35F179753C4E` |
| `tools/fixtures/cm3_lto_archive_join/test_witness.py` | `B6E50038C8F73FFB47301D041D10424C66D81ED3E50A81938CD4BC2971965A59` |
| `%TEMP%/cm3-lto-archive-join-pure-parent-20261105-e1/results.json` | `3C1A4C0B8A793FF5F3DC03CE767C39430540F0D092FC0FFE776159D257B71A16` |
| `C:/fz-cm3-lto-archive-join-witness-20261105-e1/results.json` | `DEA7678030FC5986DDC4D4886FDCD91E6D4C15082BCA71D4351F960F28C1C7E9` |
| `C:/fz-cm3-lto-archive-join-witness-20261105-e1/artifacts.json` | `92CE9BCD2FCCE88AFB70C82E7AE3EE6C2C795423C34DA2EC60A38DB8763458EB` |

This closes the fixed CM3 p4/BASEPRI16 soft O2-LTO archive pair's six emitted
root/canonical and three-mechanism evidence with explicit differences. It does
not close full callable API/ABI, whole-object/kernel or source/IR semantics,
original per-TU post-LTO ownership, general archive/weak-alias or override/cohort
negative behavior, other modes/cohorts, CPU/board, hosted exact-SHA CI or global
freeze. Required-cell credit remains typed integer zero. Production sources,
frozen predicates, default matrix and protected unrelated WIP are unchanged.

## Executing Freeze Replay Dispatcher

The opt-in `tools/freeze_replay.py` implements the closed interface in
`tools/fixtures/freeze_cohorts/REPLAY_CONTRACT.md`. Its 33 fixed routes execute
the existing gates against authenticated retained inputs. Registration is not
route execution or whole-cell qualification. No new ELF decoder, canonical
equivalence checker, compiler route or runtime adapter is introduced here.

Admission hashes the exact parsed catalog and receipt buffers; closes complete
artifact trees and original/captured input bindings; rejects role aliases and
output overlap; and independently reconstructs the declared current plan.
Reachable Capture/Seed inventory authority must agree with each selection's
historical snapshot, including protocol envelopes with no top-level inventory
scalar. Fresh optional report facts must also agree. Immutable source buffers
are executed through isolated Python and the unchanged managed runner.
Nested loaders are admitted only with the fixed loader code and exact captured
closure bytes. ATTEMPT and terminal byte streams remain separate. Primary
child errors survive additional closing failures; no recovery path restores
usable components or PASS after failure.

Parent local execution on 2026-11-05 passes:

- Twelve maintained pure methods, with six source hashes closed and no drift.
  They include three in-process synthetic bootstrap controls: nested loading
  with inner/outer traces, rejection of an unapproved custom loader, and
  rejection of altered nested bytes. No subprocess, real gate or target runs
  in this pure suite. Caller command injection, bad hashes, aliases, stale or
  malformed child evidence, historical promotion, late drift and intended
  receipt substitution also reject.
- Five actual CLI admission controls: unknown route, extra command field,
  wrong receipt hash, Native/Reference alias, and a forged current-E9 inventory
  selection over actual nested-E8 O2-LTO inputs. All reject with the expected
  diagnostic before creating the requested output directory.
- Eight actual CM3 child gates: five ordinary optimization modes, direct
  O2-LTO, direct Os-LTO, and archive O2-LTO. All execute anew and reproduce the
  authenticated complete root/protocol/twin evidence. O2-LTO direct authenticates
  earlier controls without rerunning them; Os-LTO and archive each execute
  their fresh 32 transport plus two coherent canonical controls. Eight E8
  components remain historical; none is current-E9 eligible.
- One actual current-E9 CM0/O2 direct replay. Its Native and Reference captures
  are rebuilt afresh: fourteen TUs, four links and 152 successful tool commands
  (73 native, 79 reference, including inspections/provenance). Three outer
  Python invocations drive the two producers and unchanged join. The new join
  closes eight bodies and three mechanisms. The subsequent dispatcher replay
  is current-E9 eligible, not an old capture with a new label.
- Separate independent parent audits rehash complete output memberships and
  watched inputs, physical identities, terminal command/stream bindings and
  immutable source execution records. They independently map final ELF32
  PT_LOAD bytes to all 48 CM3 and eight CM0 body hashes. The CM3 run closes
  3,195 artifacts plus manifest, 23,925 inputs and 520 execution records; CM0
  closes 236 artifacts plus manifest, 2,439 inputs and 51 records.

Every actual dispatcher result retains all 2,774 canonical keys (730 object,
2,044 final), the ordered missing-work queue and all 26 backlog records.
Current and historical component references never replace missing whole-cell
requirements. Full API/ABI, source/IR and whole-object/kernel semantics,
CPU/board execution, hosted exact-SHA CI and global freeze remain unproved.
Required-cell credit is the literal integer zero.

| Source or local evidence | SHA-256 |
| --- | --- |
| `tools/freeze_replay.py` | `142BDDE647122DB2D66EF66E4C44A33ECEAA9292FFE304EF3C7CBCC740283275` |
| `tools/fixtures/freeze_cohorts/REPLAY_CONTRACT.md` | `4F386EF0AFC933064C4179AB7EB07EA33C4534153DA663B0BC0D48D281F15C9B` |
| `tools/fixtures/freeze_cohorts/test_replay.py` | `E8B5C793D22AE9300C59BF4FCC14E548EEFEF0D85AE562A3118B9AF4DA5AB459` |
| `%TEMP%/freeze-replay-pure-parent-20261105-e3/results.json` | `2C49E57FA395E8ED67F834F6936C48F019B3E8F07049C9BFB150BDA81C6BFB34` |
| `C:/fz-freeze-replay-admission-20261105-e2/results.json` | `1BD239BC3D8A89936DDCA322B7EFAE1A765980AB2EED80E0AA60AAFB907390A7` |
| `C:/fz-freeze-replay-inputs-20261105-e1/cm3.json` | `52A137EE8645BBD9FC210522689FF08ECC16AF688EC00628E85893EC99438446` |
| `C:/fz-freeze-replay-cm3-20261105-e2/results.json` | `92C405B738308E9562F830DA5B470927F45006B9FDAC15866B21A066E9297E62` |
| `C:/fz-freeze-replay-cm3-20261105-e2/artifacts.json` | `12447770F83169DD3D298E0212D434BFD04D1DF1DEB19EDFD98C72ED2F075B82` |
| `C:/fz-freeze-replay-inputs-20261105-e1/cm3-independent-audit-e1.json` | `009A5D0AF22811499A49781950B49BF4AFB8B5302E417A35A15363ED21194062` |
| `C:/fz-replay-refresh-cm0-o2-20261105-e2/results.json` | `F02DA67EC091242806972640B91EDE1D5D936DEB5951332865148F8E9AAA3A70` |
| `C:/fz-freeze-replay-inputs-20261105-e1/cm0-current.json` | `39E08F24184D31883E5F85234C191060F680E2C76F0C40048F93B84649610CB7` |
| `C:/fz-freeze-replay-cm0-current-20261105-e1/results.json` | `DFD89424D3C0EA93C35CB2C778F64A8617F5401FECBC37127181611107AAE773` |
| `C:/fz-freeze-replay-cm0-current-20261105-e1/artifacts.json` | `F2ED47D1DCC4FB71F55A6636A9B72ED0BE671F2E1E86C38DD4F95A0CC9AB5ECF` |
| `C:/fz-freeze-replay-inputs-20261105-e1/cm0-current-independent-audit-e1.json` | `984FA3E00CB539BDECA62673D87EE7912689CF4C8CD16F1C9E6F65C73CCB5417` |

Historical attempts remain intact. The original broad smoke refuses before
output because 25 old ordinary CM0/CM4/CM7 routes bind a live helper Original
that has changed; the frozen gates also require that Original hash. Do not
virtualize historical originals or weaken those readers. One route, CM0/O2,
is refreshed above; the other 24 require fresh producer captures and joins.
The first actual CM3 dispatcher attempt remains FAIL for the nested-loader
conflict. Pure worker E3 remains FAIL for fresh-report fingerprint promotion;
parent E1 remains FAIL because an overlapping test-source edit tripped source
closing despite passing methods. The final frozen source passes the fresh
runs above. The independent audit's first root-level receipt write was refused
by Windows permissions after read-only checks; its successful receipt uses
the external inputs directory and never modifies sealed proof trees.

Next work is the remaining 24 current ordinary routes, then missing
source-group/cohort/mode/final/archive proof adapters and composition with
full ABI/vector/negative-link obligations. Nine successful replay routes do
not satisfy the complete 33-route or 27-group roadmap. Production, pinned
reference, existing helper pins, default matrix and protected unrelated WIP
are unchanged. Hardware qualification remains pending.

## Explicit Ordinary Capture CLI

The maintained `tools/freeze_capture.py` replaces historical-discovery-dependent
operator scripts for fresh ordinary component capture. The closed request
contains only schema version and ordered route IDs. All eleven tool, inventory,
request and output options are required; arbitrary scripts, argv, environment
overrides, LTO and archive routes cannot enter through that request. Thirty
routes are implemented, not claimed as thirty executed qualifications.

For each requested route the CLI executes fixed Native, Reference and Join
sources from authenticated buffers with isolated Python and the unchanged
managed runner. It authenticates the current inventory, complete artifact and
input trees, actual per-TU compile/dependency recipes, two final link recipes,
own-side twins, canonical joins, source/parser aliases and terminal traces.
Completed cases receive real producer/join descriptors; incomplete work remains
explicitly pending. No invented PriorJoin descriptor is used to start a join.
Its catalog can subsequently drive the unchanged replay dispatcher.

The parent qualification on 2026-11-06 includes twelve pure methods, three real
admission rejections before output creation, and a real three-route smoke:
CM0PLUSVTOR/Og, CM3/O3 and CM7/Os. The smoke executes 40 TUs, twelve final links,
42 object checkpoints, 440 successful tool commands and nine outer Python
invocations. The joins close twenty final bodies and nine mechanisms. An
independent parent audit validates complete memberships, input physical
identities, actual source traces and command bindings, and extracts all twenty
body byte ranges from the selected final ELF PT_LOAD segments.

Two confirmed defects in the new capture tooling were fixed without changing
the runtime or existing gates: a replay-catalog-only helper incorrectly required
an unavailable PriorJoin before the new join; terminal journal exceptions could
replace an earlier stage failure. Pure regressions now retain the primary stage
cause and secondary persistence cause, reject journal-only failure, keep pending
work and prevent stale PASS after late closure/seal failures. Metadata repair
after a one-shot journal fault does not retry a compiler or producer stage.

The first pure attempt remains FAIL for the catalog-helper defect; a later
pure attempt remains FAIL for an overly specific expected exception type in
the new journal-only control. Both are retained outside the repository rather
than overwritten. The final twelve-method suite passes with no skipped methods
or source drift. Source hashes and final smoke receipts are recorded below.

This is a reproducible local component-capture checkpoint, not a hosted CI run
or completed freeze cell. Whole-cell ABI/vector/negative-link composition,
remaining ordinary captures, LTO/archive coverage and the wider STM32 backlog
remain pending. RequiredCellsSatisfied stays typed integer zero; global freeze,
full API/ABI, source/IR equivalence and CPU/board execution remain false.
Production C/assembly, the five-operation public API/eight-operation port
boundary, fixed helper pins and protected unrelated work are unchanged.

The final smoke closes 5,410 artifacts plus its manifest, 5,916 watched inputs
and 465 authenticated source-execution records. The final pure suite closes
fifteen source inputs, with twelve executed methods, no failures/errors/skips
and no drift. The first successful smoke at the earlier capture source remains
historical local evidence; the final-source smoke below is a separate rebuild.

| Source or local evidence | SHA-256 |
| --- | --- |
| `tools/freeze_capture.py` | `9C6A92D972562FDFA17AB28CCBD4A052D9364EAE365C8C00364E4F1EB8E3F054` |
| `tools/fixtures/freeze_cohorts/CAPTURE_CONTRACT.md` | `698BB42BFC5923252FAE03BEFF6387F3AA6FD1E582BA2144D6EF361E0882F963` |
| `tools/fixtures/freeze_cohorts/test_capture.py` | `55DCA818E354DAD7F606EE3770B30FCE513EBBA29DC215B14128A69A66A30F95` |
| `%TEMP%/freeze-capture-pure-parent-20261106-e4/results.json` | `4BD68E06216E9652771F3584D552DE3C1D5650713091BD6A491CD596E61719D4` |
| `C:/fz-freeze-capture-inputs-20261105-e1/smoke.json` | `4E9C5DFF111BFD6CF0D09FAA1C90635CBEF563460290D45FF3D63A63CBAA33D8` |
| `C:/fz-freeze-capture-smoke-20261106-e2/results.json` | `A3506ADB03AB9BBBC8D66B210C589C0D2154E7F1A899C3D0B42A357B1B6AD654` |
| `C:/fz-freeze-capture-smoke-20261106-e2/artifacts.json` | `F22231DE35D081DCC40FB5CBDEA012F350EFEA1F35DEC9E8AD9D7734B9C30BD9` |
| `C:/fz-freeze-capture-smoke-20261106-e2/catalog.json` | `57852AAEB5C9A8DAC2FE5D9AF5995B5A8DEE24E00885CE9B50E62AE022F31D66` |
| `C:/fz-freeze-capture-inputs-20261105-e1/audit_capture.py` | `2D5D97685317D9D2A3C41E134EE1432DE618910EA9EB7986793CF5BB792EA20C` |
| `C:/fz-freeze-capture-inputs-20261105-e1/smoke-independent-audit-e2.json` | `3D84A7C08CD5580F8289189F6F166B886BDC694CE09A272D70F17CE0EACCC85D` |

The explicit input inventory is current E9 (`C:/fzin-20261104-e9`), with receipt
`1910B53001FD37DF4B6DC57805EE49E4381B2529E1E3ECB47FDB312EB43A4DFC`,
manifest `640C2CAC37DFC0A10F5A6E8538E7A9F81C7967DEEDEAA4B2924A15CAA1600CEA`
and source fingerprint
`69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313`.
FreeRTOS remains pinned to `a50edad08b29052631aa469d4df6e6ec7ff68878`.

## Current Ordinary Direct Baseline

The 2026-11-06 actual fresh capture requests the twenty-nine ordinary direct
routes other than the already current CM0/O2 pair. Together they cover CM0,
CM0PLUS, CM0PLUSVTOR, CM3, CM4 and CM7 at O0, Og, O2, Os and O3. The actual
29-route batch terminates successfully with 391 TUs, 116 final links, 406 object
checkpoints, 4,288 tool commands and 87 outer Python invocations. Its unchanged
joins close 202 final bodies and 87 mechanisms. An independent audit rehashes
50,519 artifacts, 50,750 watched inputs and 4,439 source-execution records,
binds actual commands/dependencies, and extracts all final body ranges from
ELF PT_LOAD bytes.

The explicit thirty-route catalog adds only the previously refreshed current-E9
CM0/O2 pair from `C:/fz-replay-refresh-cm0-o2-20261105-e2`. It does not promote
historical E8 CM3 evidence. All catalog selections bind the identical E9 source
fingerprint `69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313`.
The unchanged dispatcher then executes all thirty fixed gates anew and closes
successfully. A second independent audit confirms thirty current components,
zero historical components, 210 raw final bodies, 4,413 artifacts, 56,539 watched
inputs and 1,590 source-execution records. The existing 2,774-key inventory and
all 26 backlog records remain intact.

| Local evidence | SHA-256 |
| --- | --- |
| `C:/fz-freeze-capture-inputs-20261105-e1/ordinary29.json` | `A8AB5675CAB5D3F0E65D6259FE9B0A61A0C71E0808D95B380735CDB8D56F6D1C` |
| `C:/fz-freeze-capture-ordinary29-20261106-e1/results.json` | `665347E5A4F1791D1FED359FC02C81B4802B2242F9DFB051B6A494F5B14C2C31` |
| `C:/fz-freeze-capture-ordinary29-20261106-e1/artifacts.json` | `8104EE875E9F09BBC1E33390975173842EA15773F37F5B52495FDD1E9FFBB8F3` |
| `C:/fz-freeze-capture-inputs-20261105-e1/ordinary29-independent-audit-20261106-e1.json` | `DD31064FF069EF0F150F0AB7BD186C05B6F454F1FDC9D283E428F826A9CAE140` |
| `C:/fz-freeze-capture-inputs-20261105-e1/ordinary30-current.json` | `EB7864CBDEC4257BBBE13830BE8757E508512BB47E4185BBD5FE473473857C4B` |
| `C:/fz-freeze-replay-ordinary30-current-20261106-e1/results.json` | `DFF6A68611361EF83F905C09B0F8807843414FB42879A4E7FEE5C7AC252693FB` |
| `C:/fz-freeze-replay-ordinary30-current-20261106-e1/artifacts.json` | `A335839ED169A485254AA489E0653537EAE6A0104640C7A0FF8C3205F937157F` |
| `C:/fz-freeze-replay-inputs-20261105-e1/ordinary30-current-independent-audit-20261106-e1.json` | `78DF45AA037D3C3176CBDDEEC289325688E1A83753FB82760567B28A17ACF4AB` |

This supersedes the earlier pending-fresh-ordinary-capture statement only for
these thirty ordinary direct routes. The scope remains final root transport,
three canonical transfer mechanisms and within-side twins, with the existing
declared native/reference differences. Whole-cell typed ABI/vector/negative-link
composition is not inferred from these component receipts. Required-cell credit
stays typed integer zero; full semantic API/ABI, source/IR equivalence, broader
profile/LTO/archive coverage, hosted CI, CPU/board execution and global freeze
remain unproved or pending. Runtime code, fixed helpers, the five-operation
public API/eight-operation port boundary, pinned reference and unrelated WIP
are unchanged.

## First Bounded CM0 Static Cell

The final-source actual composition on 2026-11-06 passes for only:

```text
cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default
runtime / final / O2 / direct / CM0
```

The new maintained `tools/fixtures/cm0_final_cell/` modules implement the
explicit `CM0_CELL_CONTRACT.md`, rather than treating existing component PASS
labels as whole-cell evidence. `compose.py` admits the current E9 inventory,
single-route catalog and complete Native/Reference/Join closures, recomputes
the unchanged mechanism join, reruns the original producer prelink/final
predicates, binds original/final references, and runs `components.py` afresh.
It grants one narrowly defined static-cell credit only after input/output
closing succeeds. Its component helpers retain zero cell credit themselves.

The complete declared obligation set is now satisfied for this exact cell:
three common prerequisites (CPU-neutral engine, reverse-v1 ownership and
source-provider identity) plus eight runtime obligations (forward-eight,
reverse-v1, current-slot isolation, strong handlers, exact profile/context
cohort, generated mechanism comparison, final vectors and negative links).
The canonical plan remains unchanged: 2,774 keys, one bounded static cell,
2,773 pending keys and all 26 backlog records. This is proof accounting, not
an estimate of remaining implementation effort.

The final run closes 505 artifacts and 2,840 input paths. The fresh nested
component suite closes 1,605 input paths and executes 38 actual tool commands.
It revalidates the positive retained link and rejects exactly five intended
negative links: NVIC-2/3 cohort mismatch, storage-v1/999 mismatch, reverse-v1/v2
anchor mismatch, duplicate SVC and duplicate PendSV. It also compiles five
canonical ABI probes, including three intended undeclared-current-slot
failures, and recompiles three common providers without CMSIS/selected-port
include dependencies. Each isolated common object is byte-identical to its
positive original. The saved-assembly port replay is likewise whole-object
byte-identical and accounts for both direct current-slot load-only sequences.

`bindings.py` independently spells and checks exact thin bindings in both
ordinary and emit-relocs twins: eight forward providers, four reverse
providers, five reverse call/address references, two cold v1-anchor reads,
four cohort references, two slot references and three original startup-vector
references. It uses the existing qualified ELF reader, not another decoder.
The CM0 join checks all three native and five reference transfer roots,
including original/final transport and the declared staged-frame, startup,
scheduler, provenance and mask-restore differences. It does not establish
arbitrary callee semantics, pointer-alias semantics or instruction equality.

The recomputed read-only phase uses 835 distinct admitted buffers for 2,333
initial paths, with 2,291 recorded reads, 106 exact capture aliases, 48 normal
source-loader executions and one legacy helper-loader execution. Path lookup
is lexical within that scope; real opening/closing physical identity and hash
checks remain outside it. Compiler components run after the buffered-reader
scope and perform their own complete closing checks. This is not a sandbox.

All 88 maintained methods pass at the final source: 73 pure model/admission/
fault-injection methods and 15 read-only retained-ELF integration methods.
There are no failures, errors, skipped methods or closing source drift. The
fixed retained CM0 seed and parser paths are explicit local test dependencies,
not a portable fresh-build CI bootstrap. An actual multi-route CLI rejection
also fails for the exact intended single-CM0-route cause before creating its
requested output directory.

Confirmed proof-tool defects fixed during review include missing provider
source authority in reconstructed `Pilot`, incomplete canonical ABI-header
dependency admission, permissive negative-compile diagnostics, late-failure
metadata ordering, live content rereads and live physical path resolution in
buffered predicates. Regression tests cover each class. Recovery first tries
to persist revoked FAIL credit and preserves the primary cause even if later
debug artifacts cannot be written. It never retries a compiler stage.

The external prototype and earlier maintained component/composition attempts
are retained as historical local evidence, not final-source qualification.
Composer E1 failed for the missing reconstructed source authority; E2 through
E4 passed at earlier composer bytes but are superseded by E5 after hardening.
The final-source run and parent test receipts below are separate executions.
No old PASS is relabeled or overwritten.

| Source or local evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/freeze_cohorts/CM0_CELL_CONTRACT.md` | `C50A2B105489205EC6893DA9C71919CE5A42DA4DE9E23A94E496228C62B53EBA` |
| `tools/fixtures/cm0_final_cell/compose.py` | `E115BEC0D38CC2E753CD8331EA369414FF62C52A5BC4F6434F2A1458A00FB8DF` |
| `tools/fixtures/cm0_final_cell/components.py` | `16490A20B1A75C5DBD2D21A5FED988C5BD82F4DE919350985B33491CE473A5F7` |
| `tools/fixtures/cm0_final_cell/bindings.py` | `2237D0615B6D39FF2B7028F18FAC55685644F4B4A4ADD7ACEFDD736E2966E168` |
| `C:/fz-cm0-cell-compose-20261106-e5/results.json` | `2E3550E99726C737731AFCD28218F039D8805B256F484D95F1DF8BCD49D68F62` |
| `C:/fz-cm0-cell-compose-20261106-e5/artifacts.json` | `52E6D41AF3012AD221F6433901F563E6415249C6B071C0AB09974685E879746C` |
| `C:/fz-cm0-cell-compose-20261106-e5/components/results.json` | `7D9170C06F8A30F67EF70A62B8389084B2989C4433C509FE9F2902B75D97CF78` |
| `C:/fz-cm0-cell-compose-20261106-e5/components/artifacts.json` | `FCB616861E1AC78C0E2E3477DBA82FC47A4DA95F6A65E17234E80C9CD166DB79` |
| `C:/fz-cm0-cell-parent-tests-20261106-e2/results.json` | `96D938079E061BA229B80C67097C3F767A0F28F135FE8D030FB3A066647779ED` |
| `C:/fz-cm0-cell-parent-tests-20261106-e2/artifacts.json` | `16DE68BFD6AFD1FC9AD4B7E2AF17ACADD66E87B4400B15604AFB8CFA15C81996` |

The input inventory is current E9 with source fingerprint
`69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313`;
the reference remains pinned to `a50edad08b29052631aa469d4df6e6ec7ff68878`.
The admitted single-route catalog has SHA-256
`39E08F24184D31883E5F85234C191060F680E2C76F0C40048F93B84649610CB7`.

This closes only the written bounded static-cell contract. Full semantic ABI,
source/IR and source-to-machine equivalence, CPU execution, board execution,
runtime handler routing, every-profile LTO/archive qualification, hosted CI
and global freeze remain false or pending. No runtime C/assembly, public5/
port8 boundary, fixed producer/reader/checker, reference pin or default matrix
is changed. The next software work is reusable composition/admission for the
remaining modes and profiles, not another replay of the already current
ordinary mechanism baseline or an unsupported hardware-completion claim.

## Ordinary Direct Component Generalization

The new maintained `tools/fixtures/ordinary_final_cell/` modules provide
prerequisites for thirty ordinary direct routes, not another composer or a
new runtime boundary. `profiles.py` supplies closed independent profile/mode,
recipe, provider, trait and symbol expectations. `abi.py` checks the selected
actual source/dependency authority and canonical declarations with independently
spelled types and attributes. `controls.py` reuses the qualified CM0 Suite's
generic execution/closure mechanics without mutating its globals, and requires
an explicitly admitted native bundle and current E9 inventory.

`bindings.py` uses the existing qualified ELF reader to check all thirty
retained native ordinary/emit-relocs pairs. Its independent reference classes
fix owner, input section, kind, target and multiplicity, not CM0/O2 offsets.
It measures and binds original addends, applied final targets, strong provider
origins, two cold anchor reads, four cohort references, two slot references
and three startup vector references. Each twin also has the exact eight
forward/four reverse providers and exact slot/cohort storage. This is bounded
binding evidence, not arbitrary callee/alias or whole-provider semantics.

The final-source fresh component CLI passes these six selected routes:

```text
CM0/O0/direct          CM0PLUS/Og/direct     CM0PLUSVTOR/O2/direct
CM3/Os/direct          CM4/O2/direct         CM7/O3/direct
```

Every route executes 38 terminal tool commands, revalidates its original
positive ELF by byte identity and rejects exactly five intended negative
links: changed NVIC cohort (2/3 or 4/5), storage-v1/999, reverse-v1/v2 anchor,
duplicate SVC and duplicate PendSV. Each also compiles five ABI probes (two
accepted and three exact undeclared-slot rejections), three common providers
without forced main/CMSIS/selected-port includes and one runtime replay with
saved assembly. All three common objects and the runtime replay are whole-object
byte-identical to their admitted originals. Exact dependencies, diagnostic
classifications, terminal command journals, input closure and output seals pass.

The totals are 228 commands, thirty intended negative links, thirty ABI probes,
eighteen isolated common compiles and six runtime replays. The six manifests
contain 2,358 artifact entries and the receipts close 9,628 per-bundle input
entries; those counts are not deduplicated across runs. CM0 variants and CM3
each close 1,608 inputs; CM4 and CM7 each close 1,598. All component reports keep
integer `RequiredCellsSatisfied=0` and false cell/full-semantic/global/runtime
claims. No earlier producer or reference-join PASS is relabeled as a new cell.

A separate read-only audit confirms all twelve supplied receipt/manifest
hashes, exact output closure (2,364 files including six manifests) and all
9,628 watched bindings across 6,883 unique input paths. Hash and physical
identity closing rechecks cover 7,879 unique files. The 228 command records
contain 180 successful commands and 48 intended exit-1 results: thirty link
rejections plus eighteen absent-slot compile rejections. Positive ELF, probe,
isolated-object and original/normalized slot bindings also pass this audit.
This audit does not rerun compilers or execute target code.

The final parent test run passes all 64 methods without errors, failures, skips
or source drift: 58 model/declaration/admission/adapter controls and six retained
ELF integration methods. The latter use all thirty explicit current native
pairs and targeted negative mutations. They are read-only retained-data tests,
not thirty new compiler component runs or a portable CI bootstrap.

The first smoke (`C:/fz-ordinary-components-smoke-20261106-e1`) passed its first
four routes, then failed on CM4 source-trivia admission after all five intended
negative links. Fail-stop prevented the CM7 attempt. The unchanged qualified
CM0 matcher allowed whitespace but not a C block comment between adjacent asm
string literals. The new bounded adapter checks the two original symbol
mentions and exact literal pairs, normalizes only block-comment trivia in their
gaps and records original/normalized SHA256 plus reversible byte transformations.
The comment token cannot backtrack past its first `*/`; nontrivia and gap
backslashes reject. Assembly/object bytes and qualified predicates are unchanged.
CM4/CM7 each normalize one gap; the other four routes normalize none. Focused
architect/consumer review and negative controls cover these boundaries. The E1
results remain historical; E2 reruns all six at final helper bytes.

Each route directory below is under
`C:/fz-ordinary-components-smoke-20261106-e2/`:

| Route Directory | `results.json` SHA-256 | `artifacts.json` SHA-256 |
| --- | --- | --- |
| `CM0-O0` | `2BD110C292E4638161CD1E16E2E915F4795DB1FB4631FEDD82AFB4933106FE72` | `DFE5A581B47F5D2C69CC6D5E6C4152E0D3A134AAD8A318B0E8E075E0C64C1C2D` |
| `CM0PLUS-Og` | `7C303ACCD96CB891EDB215F4E4CCB163BE9493E2E0AC22A09661758DA79B354E` | `8ADD3929B94B7A4A39A22DF5B63E5B65FA57B7B815562949484EE98F05910C36` |
| `CM0PLUSVTOR-O2` | `B4BD39A325F3CE8A14422270FCACC9128964ED474C118EAA4CE7456EDAE36D4F` | `19BFD0BA0071C504D9FC43342A96D694A654DDB2E0AC29B1161FA9DD5C618F75` |
| `CM3-Os` | `4F65985189716C650296FED062E56DA3845B51D0710AAC707F5871CDC460E5AC` | `5843E210CAE41DD2EE531989411E51DE0E8DA6EB90A56A0DFB3C55A1911E456E` |
| `CM4-O2` | `8F92D7C25B45A05DC0054EF3EADDA0EBBB0138E9F65C4248FF32B6B759B6F8DA` | `945A71F9B558DC03F7BF2581EFBD691E0C857F04FE66592FD1F5CFF9F3E3F699` |
| `CM7-O3` | `58891066798F6C0864A72D89937CAC1B16EC9C115E0A12635203EB5E9DB3E44A` | `4B9049DBE66B12C88C7010B81F4236AAD22B4F6F38FCC5D930DE1C5C987EC4C5` |

| Source Or Local Evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/ordinary_final_cell/ORDINARY_CELL_CONTRACT.md` | `7FE3436F8AE1FCFE494AF526D70D20802EF564A490AD2FCB90D86C1CE46EAD5D` |
| `tools/fixtures/ordinary_final_cell/profiles.py` | `BDD5C9A1F490FF3156CB4DC752F0C411F6FA07852BA5024124E91CC05601CFCD` |
| `tools/fixtures/ordinary_final_cell/abi.py` | `43F2E49D638D0E586A24AD2B32D0B8D86C58CC9A63E134EF6AF064437278CAE5` |
| `tools/fixtures/ordinary_final_cell/bindings.py` | `5AD660BFBF88F0F25B41434844FD2A5BA28C91D15D494AE92AAC5482C70DC6BB` |
| `tools/fixtures/ordinary_final_cell/controls.py` | `10F8203B7AA24502BDCA2274DA8C5B7A8763EF7630E8FE8350C64AC50699F18A` |
| `tools/fixtures/ordinary_final_cell/components.py` | `0421B9D9D53F9844C601AC14BC5B91074A6A4D10753C030BE2A7038FDE3D2B68` |
| `C:/fz-ordinary-components-smoke-20261106-e2/parent-tests.log` | `7B0B70712083F87CCEAC3C703D10D07A396A70DC686D48D1CB595163A733C5BF` |

The catalog remains `ordinary30-current.json` with hash
`EB7864CBDEC4257BBBE13830BE8757E508512BB47E4185BBD5FE473473857C4B`;
the explicit inventory is current E9 with source fingerprint
`69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313`.
FreeRTOS remains pinned to `a50edad08b29052631aa469d4df6e6ec7ff68878`.

This checkpoint does not implement ordinary whole-cell composition or award
new credit. The previously published exact CM0/O2 bounded static cell remains
the only composed cell; all 2,774 keys and 26 backlog records remain intact.
Next comes generic composition and fresh components for the remaining ordinary
combinations, followed by the separately tracked broader profile/LTO/archive
and reproducible-CI obligations. Full semantic ABI, source/IR equivalence,
CPU/board execution, actual handler routing and global freeze remain unproved
or pending. No runtime C/assembly, public5/port8, qualified helper, reference pin
or default matrix changes are part of this checkpoint.

For the subsequent implemented composer and its measured receipts, continue to
[Ordinary Direct Static Cell Composition](#ordinary-direct-static-cell-composition).

## Ordinary Direct Static Cell Composition

The maintained ordinary composer builds on the preceding component checkpoint.
It accepts exactly one explicit route from the closed six-profile/five-mode
ordinary direct surface. `prepare()` authenticates the caller-bound current E9
inventory, catalog and selected Native/Reference/PriorJoin bundles, source and
tool identities, complete plan, and output separation before creating output.
The seven-argument CLI requires fresh isolated, no-site, no-bytecode,
unoptimized Python (`-I -S -B`), with no inherited ELF parser package state.

`recompute.py` reruns unchanged family join/protocol and native prelink/final
predicates against the admitted immutable buffers. It compares complete roots,
own-side twins, mechanisms, producer bindings and captured nonempty difference
rationales, rather than trusting an earlier PASS. Thin `bindings.py` checks
actual original references, provider/map origins, applied final targets,
strong handlers, vectors, current slot and exact cohorts. CM4/CM7 additionally
bind the independently pinned FP-policy supplement; their eager native and lazy
reference policies are not claimed equivalent.

CM3's existing family loader is the sole inner spec-loader authority. The new
orchestrator temporarily delegates through the original stdlib spec factory;
it does not stack two frozen spec loaders or mutate qualified helper globals.
Outer buffered data, source/code and lexical path hooks remain active. Fresh
compiler components and real physical closing execute only after leaving that
read-only scope. Host-loader fixtures and actual CM3 integration cover this
handoff separately.

Each cell reruns the existing 38-command component suite and authenticates the
returned result against its written receipt and artifact manifest. The complete
common-three/runtime-eight obligations can become satisfied only after both
recomputed and fresh evidence, real closing hashes/identities/memberships, and
exact output sealing succeed. Late failures revoke all obligations and credit;
recovery attempts to persist FAIL before secondary accounting artifacts and
preserves primary and secondary failures separately.

`coverage.py` preserves every canonical key and role-specific missing obligation,
plus deep copies of all 26 backlog records. One invocation passes either no
verified key or its one exact literal five-tuple, never inferred completion from
receipt labels. Its successful coverage has 2,774 keys, one bounded static-cell
credit and 2,773 uncredited keys. An index of independently composed receipts is
discovery data, not an atomic batch proof or aggregate-credit authority.

The independent final-source test-log review confirms 120 unique methods:
ABI 12, bindings 9, components 17, compose 14, controls 14, coverage 12,
prepare 11, profiles 12 and recompute 19. All pass without failures, errors or
skips. There are 114 host controls and six retained-ELF integration methods.
Host controls include actual source/E9 JSON reads and temporary loader/filesystem
fixtures; they are not all mock-only. The two PilotReplay methods use a fake
Pilot. The six retained-ELF methods cover the thirty admitted ordinary pairs,
but neither classification means thirty fresh compiler runs or portable CI.

Four actual CLI negatives also reject before creating their requested output:
missing Python isolation, an unsupported LTO route, a bad catalog SHA256 and
a missing route argument. The terminal admission receipt is separate from
compiler/cell proof and grants zero credit. The first parent diagnostic matcher
expected the word `hash` instead of the real `SHA256 mismatch` diagnostic;
a subsequent receipt-write attempt hit Windows root-file permissions. Neither
was a composer admission defect; the retained terminal run uses the exact
intended diagnostics and a writable temporary receipt directory.

### Final Ordinary Campaign

The final-source campaign on 2026-11-06 terminates successfully for all thirty
explicit ordinary routes. Every child runs in a fresh isolated Python process;
all eighteen ordinary implementation/test/contract files remain unchanged
throughout. Each child authenticates the same current E9 authority and its own
selected producer/prior-join descriptors, recomputes the complete family
root/protocol evidence and executes fresh components. The final catalog index
contains thirty independently sealed receipt/manifest pairs, not thirty labels
copied from earlier component runs.

| Profile | Individual Cells | Outer Artifact Entries | Outer Input Bindings | Final Bodies |
| --- | ---: | ---: | ---: | ---: |
| CM0 | 5 | 2,525 | 14,235 | 40 |
| CM0PLUS | 5 | 2,525 | 14,235 | 40 |
| CM0PLUSVTOR | 5 | 2,525 | 14,235 | 40 |
| CM3 | 5 | 3,470 | 15,975 | 30 |
| CM4 | 5 | 2,465 | 13,955 | 30 |
| CM7 | 5 | 2,465 | 13,955 | 30 |
| Totals | 30 | 15,975 | 86,590 | 210 |

There are ninety recomputed transfer mechanisms. Fresh components execute
1,140 terminal commands: 900 successful commands and 240 intended exit-1
results. Those intended failures comprise 150 link rejections and ninety
undeclared-slot compile rejections. The suite also contains 150 ABI probes in
total, ninety isolated common-object compiles and thirty saved-assembly runtime
replays. Each child has the matching positive link and all five intended
negative links. The ordinary source-trivia adapter and qualified checker remain
unchanged from the preceding component checkpoint.

The separate read-only parent audit authenticates the final index and every
individual descriptor, preserves all canonical coverage/missing-work keys and
backlog records, verifies exact artifact membership and rehashes 68,405 unique
files with 68,274 stored physical bindings. The thirty outer manifests bind
15,975 artifacts, or 16,005 files including their own manifests. Their nested
component reports contain 11,790 artifact entries and 81,610 input bindings;
these overlap the outer evidence and are not additional independent artifacts.
The audit checks byte/identity closure and receipt accounting, not ELF semantics
or compiler reexecution. Its own report grants no cell credit, atomic-batch
proof or global qualification.

Independent read-only reviews also close all six five-cell profile groups.
They recheck the 210 raw final ELF bodies, owning spans, original/applied
references, provider/map bindings, sixty within-side twin comparisons, source
and physical closure, exact one-key accounting and fresh component records.
CM3's loader handoff and CM4/CM7's FP supplement, slot-trivia transformations
and retained policy differences receive their profile-specific checks. These
reviews neither rerun compilers nor infer native/reference instruction or
FP-policy equality; no new port defect is confirmed in this campaign.

Preliminary complete-cell integration at
`C:/fz-ordinary-cell-compose-smoke-20261106-e1/` exercised CM0/O0, CM3/Os and
CM7/O3 before the final contract freeze. Those attempts remain historical and
are not relabeled final-source qualification. The measured thirty-route run is
`C:/fz-ordinary-cell-compose-ordinary30-20261106-e1/`, with one case directory
per profile/mode. No target image is executed. No emulator, board, flash or
reset operation is used.

| Source Or Local Evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/ordinary_final_cell/ORDINARY_CELL_CONTRACT.md` | `5B5D72313762DAEABC21F40E3CAD2075DD142CD43927D52216655E167C0A98C1` |
| `tools/fixtures/ordinary_final_cell/compose.py` | `C9E68DC6478C43074553A660FF6751AC7D84F13F498DCF7ED92AF42BFBF1F888` |
| `tools/fixtures/ordinary_final_cell/recompute.py` | `23BCFCD22B2C49F4066A7D32EA6126674D03D09CEEB6AB12AED9A352796B6956` |
| `tools/fixtures/ordinary_final_cell/coverage.py` | `D513BEA4622DB4C0CD4FC7DED6D341BF940233E4FA3B219F9723EA84E6B31DC9` |
| `C:/fz-ordinary-cell-compose-ordinary30-20261106-e1/parent-tests.log` | `E748EBEC648DC135F34E4B619017468EB4D07202A477E945227F8017393466B1` |
| `C:/fz-ordinary-cell-compose-ordinary30-20261106-e1/cell-index.json` | `F612F0521780518343EA7CDB0C33A2B3B9376BE65F0B97040D17FCB65E8FADCC` |
| `C:/Users/admin/AppData/Local/Temp/fiber-ordinary-cell-parent-audit-20261106-e1/audit.py` | `CA008EC2B6F6DD12E4EF0414ACDBFDD57CDC1F6A67526B99016D9FA5CBB0DE92` |
| `C:/Users/admin/AppData/Local/Temp/fiber-ordinary-cell-parent-audit-20261106-e1/results.json` | `1087CC959DE481AE438643F0937ABBE424006F36A441CF04E358E7AF903C2CD1` |
| `C:/Users/admin/AppData/Local/Temp/fiber-ordinary-cell-admission-20261106-e3/results.json` | `2AB6041BFD31F35E0160C911AE35CB4190396124B55E435994555377FBD3CA0D` |

All individual descriptor hashes and all eighteen source hashes are retained
in the index above. The catalog remains `ordinary30-current.json`, SHA256
`EB7864CBDEC4257BBBE13830BE8757E508512BB47E4185BBD5FE473473857C4B`.
E9 receipt/artifact authority remains respectively
`1910B53001FD37DF4B6DC57805EE49E4381B2529E1E3ECB47FDB312EB43A4DFC`
and `640C2CAC37DFC0A10F5A6E8538E7A9F81C7967DEEDEAA4B2924A15CAA1600CEA`,
with source fingerprint
`69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313`.
The reference remains pinned to `a50edad08b29052631aa469d4df6e6ec7ff68878`.

This closes thirty individual bounded ordinary/direct static compositions.
Every child still has only one credited key in its own complete plan; the index
has literal aggregate credit zero. No combined coverage projection or atomic
thirty-cell batch receipt is created. This is not a count of thirty newly
implemented ports, an effort percentage, complete native/reference instruction
equivalence, full semantic ABI, portable fresh-checkout CI or hardware evidence.

### Remaining LTO And Integration Boundary

This ordinary composition does not close the separate final LTO/archive gates.
The next bounded target is current-E9 CM3 O2-LTO and Os-LTO direct composition,
then archive linkage. Historical CM3 LTO captures remain E8 evidence and cannot
be relabeled current E9. Reuse the existing complete-root readers and transport
machinery, with explicit closure of these remaining differences:

At this ordinary checkpoint, native O2-LTO/Os-LTO seed admission was already
parameterized for the current ordinary CM3/O2 source group, while reference
admission still required its historical directory and receipt/manifest hashes.
The additive current capture frontend below now closes that capture-admission
gap without patching frozen globals or relabeling E8 receipts. Complete LTO
root/protocol/provider/ABI and whole-cell composition remain separate work.

- Native LTO has eight slim C IR providers and one native startup assembly TU,
  not nine IR providers. Bind source/header/flags and plugin resolutions to IR
  inputs separately from actual LTRANS machine-to-final placement.
- Post-LTO assembly also defines the local current slot. Use a bounded separate
  predicate for that definition and both handler loads; do not filter mentions
  or weaken the ordinary two-load-only checker.
- Authenticate actual slim objects without assuming raw replay equality:
  compiler-generated LTO unit suffixes can differ. Do not normalize those bytes
  or claim reproducibility from a successful link.
- Bind all forward-eight/reverse-four providers, typed/attribute evidence and
  fresh intended storage/reverse/cohort/duplicate-handler failures to the same
  exact LTO mode and base. Hostile-codegen claims need effective positive controls.
- Archive provider authority also needs raw member offsets and actual plugin
  resolution order; direct-object role ordering is not interchangeable.

No full semantic ABI, source/IR semantics, CPU/board execution, actual runtime
handler routing, hosted CI or global freeze follows from these ordinary cells.
No runtime C/assembly, public5/port8 boundary, qualified helper, reference pin or
default matrix is changed. Unrelated protected WIP remains outside this scope.

## Current CM3 LTO Capture Frontend

The 2026-11-06 maintained frontend in
`tools/fixtures/cm3_current_lto_capture/` admits current E9 evidence for four
direct capture routes: native/reference crossed with O2-lto/Os-lto. It is a
capture-only preparation step for the still-pending current LTO whole-cell
gate, not a final native/reference parity result. Its fixed source fingerprint
is `69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313`.
E9 receipt/manifest authority remains respectively
`1910B53001FD37DF4B6DC57805EE49E4381B2529E1E3ECB47FDB312EB43A4DFC`
and `640C2CAC37DFC0A10F5A6E8538E7A9F81C7967DEEDEAA4B2924A15CAA1600CEA`.
The reference remains pinned to `a50edad08b29052631aa469d4df6e6ec7ff68878`.

Both target optimizations start from independently admitted ordinary CM3/O2
seeds. The nine-argument CLI authenticates seed receipt/manifest and current
inventory descriptors before constructing a seed or creating output. The
unchanged current admission recomputes all 2,774 canonical keys and retains all
26 backlog records. The local reference adapter duplicates only the legacy
constructor to remove its historical path/hash authority; every validator and
its defining globals remain inherited from the pinned original implementation.
Native admission retains the existing parameterized constructor.

All executable helper buffers have fixed source pins before use. A temporary
read hook supplies only the authenticated native bootstrap-loader buffer and
is removed before real physical closing. The twin helper has an independent
pre-use pin. The combined instance closure preserves legacy hashes/membership
and current physical identities/trees. Cloned tools are enrolled and checked
before and after commands. Output is fresh and disjoint from admitted roots.
Neither helper globals nor source/ELF predicates are weakened or overlaid.

The local command wrapper records ATTEMPT before launch and exact TERMINAL
state afterward. It preserves a compiler/runner primary failure even if stream,
tool-closing, object-closing or diagnostic writes fail later. The frontend also
revokes unsuccessful finishing results, including swallowed legacy failures.
Only diagnostic persistence has bounded retries; the compiler, process and
build stage are never retried. Normal sealing hashes intended receipt/manifest
bytes before writes. Best-effort FAIL recovery writes matching forensic
evidence with both verification flags false; diagnostic consistency is not PASS.

Forty-three maintained host methods pass: fourteen reference-adapter controls,
sixteen command controls and thirteen frontend methods with multiple route,
type, drift and failure subcases. They cover exact constructor inheritance,
caller descriptor admission, four closed factories, bootstrap buffer/restoration,
physical closing, typed zero credit, terminal journals, primary preservation,
unsuccessful finish revocation and bounded transient-write recovery. These are
synthetic tests with fake process boundaries, not compiler or ELF execution.

### Final-Source Capture Evidence

The four fresh captures at `C:/fz-current-cm3-lto-capture-20261106-e2/` all
terminate successfully on the frozen source below. Native runs each compile
nine TUs, including eight genuine slim C IR providers and one non-LTO startup.
Reference runs each compile four TUs, including three slim C IR providers and
one non-LTO startup. Across the four routes there are 26 TUs, 22 slim IR inputs,
188 successful terminal host-driver commands, eight actual final links and
eight retained LTRANS machine objects. Each route independently compares its
ordinary and emitted-relocation image's load/allocated contents; this is four
within-side twin comparisons, not native/reference instruction equivalence.
WPA IR is retained as transport evidence, never substituted for machine code.

The separate read-only parent audit verifies exact receipt/manifest bindings,
all 5,668 outer artifact entries, 5,454 input hash/physical bindings and all
command journals/streams. It rehashes 7,833 unique files, re-enumerates outer and
link-directory membership at closing, and derives descriptor hashes from the
checked buffers. Its only multi-link input exception is the exact authenticated
Git provenance executable with its captured two-link physical identity. The
audit output is disjoint from audited trees. This audit proves byte/accounting
closure, not ELF semantics, compiler replay, full ABI or cell qualification.

A separate native review also inspects actual ARM ELF32LE section inventories,
distinguishes slim inputs/native startup/WPA IR/LTRANS machine objects, and
rechecks flags, dependencies, maps and own-side structural twins for both native
modes. The reference second review closes byte/physical/journal evidence only;
independent reference ELF-section parsing, twin recomputation and complete
recipe crosschecking are not completed by that review. Those remain explicit
work for the following independent root/protocol gate, not an implied PASS.

| Route Under The Final Capture Root | Receipt SHA-256 | Artifact Manifest SHA-256 |
| --- | --- | --- |
| `native-O2-lto` | `26B967A51A9546BD7F5234A61B6DF6D36381E6BB402D6EBCC3801E0A202F0EBB` | `3A6F6251AC23EF69EA5FE9BFF94B3F3FDE8CFF8ADD55002DC0865D3E543C3159` |
| `native-Os-lto` | `B85DA52838459F717EBCAB1F36B041F39323084E32301481F966165FBA510FB2` | `9AB69DF1309C6F6A08663C1E5027C29CC14C32BF003EB7C4EF412048CBBB8B33` |
| `reference-O2-lto` | `3969D3E2453A067F9F7E94C280060123CB621168711F54D76C93AF89DBD6DD9C` | `3DFD451295EB14C7F4F83C698D582031F33E5D0C0F2F5E7DBC83C5841F2C7541` |
| `reference-Os-lto` | `D8A6845268D9C83FAB8BED56F11EDF92F51BE248E6A266C104CD88D5469DDFBA` | `C4EB20E595DE2771960C918942F56814CB6B34FD1287049C3D914D26DBD58009` |

| Maintained Source Or Local Test Evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_current_lto_capture/CONTRACT.md` | `A49E0A59323356AC225B057E501583FB6EC7A0481CB09B1716AF9D4F6CBE1271` |
| `tools/fixtures/cm3_current_lto_capture/capture.py` | `128AEAF877FDB6FAC56E1A87CAE9B7F47A3EA41232739FFC0BFCEEBF9737BF2C` |
| `tools/fixtures/cm3_current_lto_capture/admission.py` | `BB4927C3046CC7FEEB42BF37D84CDF0790CB6C58D7C5F17E0AB2983E6727AEAF` |
| `tools/fixtures/cm3_current_lto_capture/commands.py` | `C89CF702850D10582479F57D24590F13AFB757ECBE3A45BEF77F1B705DECC6BF` |
| `tools/fixtures/cm3_current_lto_capture/test_admission.py` | `2040085C2DD4A2E2B33A1E66DDAC82B9AA92C2BC907DE2218A77289632CF67D5` |
| `tools/fixtures/cm3_current_lto_capture/test_capture.py` | `26F4E9659E93913CC38B3BFCF775C822FC1BBE4A52179E7EE9F7ADB10EF25DFD` |
| `tools/fixtures/cm3_current_lto_capture/test_commands.py` | `71E67CF0961A0A48F8A417A38050AD66D0DCBF2D2A07CC67EA20B42A832AA2F5` |
| `C:/Users/admin/AppData/Local/Temp/fiber-current-cm3-lto-parent-admission-20261106-e1/results.json` | `C5B02EA0F0A97DEC0CB5ACE9D267BB408B68CCCAF0CEEABB672DF32CF3E9A160` |
| `C:/Users/admin/AppData/Local/Temp/fiber-current-cm3-lto-parent-commands-20261106-e1/results.json` | `B35E26BF45C6C62EA268CA540E42C554701632736683E629E090B72C3ECF820F` |
| `C:/Users/admin/AppData/Local/Temp/fiber-current-cm3-lto-parent-capture-tests-20261106-e2/results.json` | `D415AC17A4FB2A717D8BD91E1B7FB471771864E63958E959F0D10E123DC5BD43` |
| `C:/Users/admin/AppData/Local/Temp/fiber-current-cm3-lto-parent-audit-20261106-e1/audit.py` | `605B35F726661CC83B87429A90420E530A7CA5BCAFD7432ADD23F1A59C9966B1` |
| `C:/Users/admin/AppData/Local/Temp/fiber-current-cm3-lto-parent-audit-20261106-e1/results-e2.json` | `B5C00E3B2178169D85BC92DCE2CAA05CDC9C36C2A28C99A5E36691E229FC836C` |

Two successful preliminary O2 captures at the sibling `20261106-e1` root use
the earlier producer and contract before the final failure-recovery fixes.
They remain historical and are not final-source qualification evidence.
Raw source pins refer to the measured LF working-tree bytes. Automatic checkout
line-ending conversion must reject rather than normalize these authenticated
buffers; portable checkout/tool bootstrap remains part of the separate CI gate.

Each final capture grants literal zero canonical cells. Current-source complete
root/REL/origin replay and native/reference canonical protocol composition are
the next bounded gate. Complete forward/reverse provider and attribute controls,
fresh storage/reverse/cohort/duplicate-handler negatives, archive resolution,
broader profiles and portable hosted CI remain pending. Raw slim-object equality
is not required or claimed: compiler-generated LTO suffixes can vary. No source/
IR semantic proof, full semantic ABI, native/reference policy equality, global
freeze or CPU/board execution follows. Runtime C/assembly, public5/port8, pinned
helpers, the reference pin and default matrix are unchanged; unrelated protected
WIP is neither inspected nor included.

## Current CM3 Catalog And O2-LTO Replay

The 2026-11-06 next gate first exposes a capture metadata defect: the unchanged
native O2-LTO witness rejects E2's duplicate input-provider row before creating
output. The current capture preparation had already bound
`tools/fixtures/classic_final_join/join.py`, while inherited twin comparison
appended the same Original/Captured/Sha256 row again. This was not a target-code
or root-preservation defect. E2 remains immutable historical capture evidence,
not an input catalog silently repaired for a stricter downstream checker.

The producer correction admits exactly the known pinned helper's two identical
three-field rows, retains both raw rows and original positions in
`CoalescedTwinHelperInput`, and emits one unique provider binding. Conflicting
paths/digests/fields, three repeats and every other duplicate reject. Successful
sealing independently requires unique Original providers. Source buffers,
captured files, original bytes, physical closing and all downstream predicates
remain unchanged. The frontend suite now has fourteen methods and multiple
duplicate subcases; combined with fourteen constructor and sixteen command
methods, all 44 maintained host methods pass.

### Fresh Captures And Actual O2 Gate

All four routes are rebuilt at `C:/fz-current-cm3-lto-capture-20261106-e3/` on
the corrected frozen producer. They retain the same current E9 fingerprint,
ordinary CM3/O2 seed authority and reference pin as the preceding checkpoint.
Each native capture has nine TUs/eight slim IR inputs/57 terminal commands;
reference has four TUs/three slim IR inputs/37 commands. Across the four routes
there are 26 TUs, 22 slim IR inputs, 188 successful host-driver commands, eight
final links and eight genuine saved machine objects. All own-side twin and
input/output closing checks pass. The unchanged parent byte/accounting auditor
also passes all four bundles: 5,668 artifact entries, 5,454 input physical/hash
bindings and 7,833 unique files. These are capture facts, not cell credits.

The unchanged `cm3_lto_protocol/witness.py` and
`cm3_reference_lto_protocol/witness.py` then consume the fresh O2-LTO captures
and pass in separate isolated Python processes. Native preserves 492 complete
root bytes, 170 instructions and thirteen references; reference preserves 136
root bytes, 39 instructions and three references. All original/applied REL
fields, provider/map origins, decoded address forms, mapping/literal boundaries
and complete machine/final body hashes are checked. Each side freshly executes
sixteen actual private ELF mutation controls plus one coherent SVC-immediate
change that preserves transport but must fail the canonical protocol.

The unchanged `cm3_lto_join/witness.py` independently replays both resulting
protocol groups and returns `CM3-LTO-JOIN-PASS-NOT-QUALIFIED`. It binds six full
roots to three mechanisms and the existing six difference rationales. The join
authenticates its children's 32 transport and two canonical controls with
`MutantsReexecuted=False`; their actual execution belongs to the preceding
fresh child witnesses. Native's nine saved core slots and per-context
EXC_RETURN remain distinct from the reference eight-slot/ORR-LR-13 first-restore
protocol. No instruction, frame-policy or scheduler-policy equality is inferred.

| Bundle | Receipt SHA-256 | Artifact Manifest SHA-256 |
| --- | --- | --- |
| E3 `native-O2-lto` | `DC640E58A210B4608B57EA23077E4406D2C061CBB2475F5A77A81D9985298BD6` | `9578F526EEB9444F2D80482DBC7DFAD9FC69C2B1C1DB1C35544A70B99038CB58` |
| E3 `native-Os-lto` | `D8BBA48B5EBEA3555226A9BA2E9D65D7B5E7EFED44A817902A11A23E0A6317B4` | `422958DE9A8F5BB0F43C7EABC763A0FAF7EEEC796CFAB946D7275EA8761E2F9E` |
| E3 `reference-O2-lto` | `4FBF9F47DF259DF44618A044CA79EC2E9AB1FE6C1B6A77B7ACEEDBCCB05B74B9` | `D0D74ED79D5594454A802310095FE577A9EB993DE232ACB713CFD0232251E4A6` |
| E3 `reference-Os-lto` | `B7D7D82EAF35E1B73BFC788B204EF998E45B9FDA077D583201362E7B2EBBE246` | `F527A4D21B4CC77C91F7C3314B9D83DBCDC2B208A4A83CEC11180DFDF2226785` |
| Native O2 protocol | `933A475BABFAE76E6905789D5E642E6E30B5ED070EA73F88ADD6F847E0F5BB4F` | `1C088E38FB42FE0E58472A35BAD6B388E857F7FA1DDAB8D79020EB345FCB0038` |
| Reference O2 protocol | `D22ABC473B5D19A546BE7D9ED0EC78D53AB3851E7413E39EB5BE4EB7AC6E8910` | `646EB56E4161065E8B152A5319BAB78E0CBC27194CA17D87FFB1EDC14915C606` |
| O2 six-body join | `6713CA83F2A08349AB5B86DF0B4417698C6D5ABE05008E0C34160E2B18F807F1` | `BBAD1EF5B7D882545C9B7E3D585606EB1317AF8A5102AF61DB428F9749248379` |

Protocol bundle root is
`C:/fz-current-cm3-lto-protocol-20261106-e2/{native,reference}-O2-lto/`.
The earlier native attempt at the sibling `20261106-e1` path rejected the E2
catalog before output creation. Join root is
`C:/fz-current-cm3-lto-join-20261106-e1/O2-lto/`.

| Revised Source Or Local Evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_current_lto_capture/capture.py` | `1191CDCDA9FC9312B09858D6439674DBCA19ABFCE5B0108F3575AEF3C65C0852` |
| `tools/fixtures/cm3_current_lto_capture/CONTRACT.md` | `103BA538B11930BDD736CFF4756A8E9C7EAE4E07FF26726892CBAA7433B59D80` |
| `tools/fixtures/cm3_current_lto_capture/test_capture.py` | `2B5AF148320684AA429BA7ED3456A4951E8515D41303CB099DB505E41FF58436` |
| `C:/Users/admin/AppData/Local/Temp/fiber-current-cm3-lto-parent-capture-tests-20261106-e3/results.json` | `DB4507F7C49AFA2A8624DAB85889A8118D6A9C07B838CF12764F7F70AF4D51DA` |
| `C:/Users/admin/AppData/Local/Temp/fiber-current-cm3-lto-parent-audit-20261106-e1/results-e3.json` | `2AB0C880AE878E0E1F83495A09CC63491693E9E4C97DAC3B291419AC722F1072` |

All helper/decoder/checker hashes remain those of their existing frozen
contracts. The byte auditor source remains `605B35F726661CC83B87429A90420E530A7CA5BCAFD7432ADD23F1A59C9966B1`.
The independent E2 reference review also reports actual section,
WPA-versus-machine, twin and recipe checks. Those observations retain their
historical E2 scope and are not relabeled E3 replay or current Original-byte
closing after the producer revision.

Every capture, protocol witness and join awards zero cells. Current-source
O2 root/REL/origin and canonical mechanism replay is now closed, but complete
provider/attribute/ABI controls, whole-cell composition and archive linkage are
not. A new Os-LTO admission frontend is separate work and is not qualified by
this checkpoint. Broader-profile LTO, portable CI, source/IR semantics, full
semantic ABI, global freeze and hardware remain unproved. No runtime C/assembly,
public5/port8 operation, frozen reader/protocol helper or reference pin changes.

## Current CM3 Os-LTO Mechanism Replay

The 2026-11-06 additive `tools/fixtures/cm3_current_lto_replay/` frontend admits
the current E9 inventory and E3 native/reference Os-LTO captures from the prior
section. It replaces only `cm3_os_lto_join.Witness.__init__`; inherited readers,
complete-body predicates, actual mutation catalogs, command reconstruction,
sealing and mechanism composition retain their frozen source bytes. The old
constructor's historical producer and E8 reference-seed authority are not used.
Independent current inventory, both complete capture trees, their ordinary
CM3/O2 seed descriptors, source buffers and physical identities must agree
before output creation. The sole optimization transform remains O2 to Os.

The runner authenticates all bootstrap buffers before executing them and blocks
host subprocess/shell creation during admission and replay. It invokes the
inherited replay exactly once, then validates the unchanged structured-report
schema. Failure handling retains the primary error if the failure hook or
seal also fails. A standalone diagnostic writer can make at most two bounded
attempts to persist matching FAIL receipt/manifest bytes after a failed seal;
this is never a compiler, process or replay retry. Persistent inability to write
diagnostics still returns failure, not qualification.

Fourteen synthetic admission methods verify constructor-only inheritance,
caller/current/capture/seed authority, literal route/transform fields, unique
provider catalogs, watched counts, source/ledger bindings, role alias rejection,
disjoint output and pre-output closing failures. Fourteen frontend methods
cover isolated bootstrap, exact arguments, structured-result enforcement,
single invocation, forbidden processes, primary-error preservation and stale
PASS revocation after transient diagnostic errors. All 28 pass in fresh parent
isolated Python processes; six constructor inputs and three frontend inputs
close without drift. These are host synthetic controls with mocked admission
and process boundaries, not 28 ELF or target tests.

### Measured Actual Replay

The fresh actual bundle is:

```text
C:/fz-current-cm3-lto-join-20261106-e1/Os-lto/
```

It returns `CM3-OS-LTO-JOIN-PASS-NOT-QUALIFIED` with
`Scope=CM3_OS_LTO_SIX_BODY_MECHANISM_JOIN_ONLY`. The fixed cohort is current
CM3 p4/b16 soft-float, Os-LTO, direct linkage. Source fingerprint remains
`69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313`.

Native's three roots preserve 492 bytes, 170 instructions and thirteen references;
reference's three preserve 136 bytes, 39 instructions and three references.
The inherited readers bind actual saved machine objects to final ELF bodies,
all REL/addend/provider/map origins and each side's structural load-image twins.
The canonical composition consumes six complete bodies and three mechanisms,
with the existing six difference IDs and no instruction-equivalence claim.
All 32 actual private transport mutations and two coherent SVC-immediate
canonical controls execute freshly here (`MutantsReexecuted=True`). This differs
from the O2 join's authentication of already-executed child controls.

The replay retains 582 source-buffer copies, fourteen binary-role copies and
61 executed source buffers. All 5,783 input bindings and 771 artifact entries
close. A separate parent read-only rehash also verifies exact receipt/manifest
identity, output membership, all input/output hashes, typed result/control
counts and literal zero cell credit across 5,784 unique files. That parent
check is byte/accounting evidence, not an independent ELF-semantic proof.

An independent consumer review also matches both descriptors and rehashes
5,785 unique files, including the manifest. It inspects retained full-root,
origin/REL, twin, protocol and control evidence, including 172 private control
files, without discrepancies or input drift. It does not independently rerun
the pinned readers/checkers; that review is not a second predicate computation.

| Source Or Local Evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_current_lto_replay/CONTRACT.md` | `CDB260181CF3A1E4999E392A7478921198A1B868DC108261390ADBC3E490A0EF` |
| `tools/fixtures/cm3_current_lto_replay/os_admission.py` | `DA5EB7F209A1787A8C909267B258D7E5B835E64B77785ACCF052306D9D91E857` |
| `tools/fixtures/cm3_current_lto_replay/witness.py` | `7AFE40E8344E0E9329004BB4D9682606251C9FB05E7B17A3233BF16F1798AC4A` |
| `tools/fixtures/cm3_current_lto_replay/test_admission.py` | `0C862D4F4872DB51B4667D213678C1C03A8078AB2AE276E4495C11114162E1B5` |
| `tools/fixtures/cm3_current_lto_replay/test_witness.py` | `06E8879DC086FE1593DF9EBE2D83DDBDE46E2A279C8B7718F0E82F8AADBC3265` |
| `C:/Users/admin/AppData/Local/Temp/fiber-current-cm3-os-replay-parent-admission-20261106-e2/results.json` | `E79E6D7594F66C7540743D390F7556CA44170D979CAAB794FC6072E4D28BD2AA` |
| `C:/Users/admin/AppData/Local/Temp/fiber-current-cm3-os-replay-parent-frontend-20261106-e1/results.json` | `343A1EB0A7FE3333CA9F6F4A39D5A9DF9B0DE26B62BCAE8C7548BC69F371636F` |
| Actual replay `results.json` | `ABB6F0227ACB482B185BAE9A67A2BB787543D56242A3D1F13AAF06DDFB665247` |
| Actual replay `artifacts.json` | `EF27FCD461602994CE6052DC72DED57B5B3D0DC1952AEB7E6F1F4ECFC3C6C634` |

The capture producer stays `1191CDCDA9FC9312B09858D6439674DBCA19ABFCE5B0108F3575AEF3C65C0852`;
the inherited Os witness stays
`BEC9C699F8C62A69CB2BF35B24CF51D8815329517F83A11517BF9657D294D7AB`.
Other decoder/protocol/helper pins remain those of their existing contracts.
Raw new-source pins refer to measured LF working-tree bytes; automatic newline
conversion must reject, not normalize authenticated code. Portable checkout
and tool bootstrap remain part of the later CI gate.

This checkpoint closes the bounded current-source Os-LTO root/origin/canonical
replay, not a whole-cell proof. All 2,774 inventory keys and 26 backlog records
remain visible and receive zero credit here. Complete forward/reverse provider
and attribute controls, fresh storage/reverse/cohort/duplicate-handler link
negatives, current-slot whole-cell evidence, archive resolution, broader-profile
LTO and portable hosted CI remain pending. Full semantic ABI, source/IR
equivalence, runtime policy equality, global freeze and CPU/board execution are
not claimed. No runtime C/assembly, public5/port8, existing frozen predicate or
reference pin changes; unrelated protected WIP is neither inspected nor staged.

## Current CM3 O2-LTO Runtime Bindings

The 2026-11-06 additive component at `tools/fixtures/cm3_lto_runtime_bindings/`
extends the fixed CM3 O2-LTO direct link audit. Its enclosing witness admits
the current E9 inventory, E3 native O2-LTO capture and ordinary CM3/O2 Seed by
independent descriptors before output creation. All reachable inventory facts,
current producer, raw/captured providers, dependencies, tools and source buffers
must agree. It retains both legacy byte/membership and modern physical/tree
closing, with fresh disjoint owned output. The only permitted multiple-link
provenance file is an exact admitted external Git executable, never executed.

All 57 actual native capture command recipes are reconstructed using the
unchanged Os witness command checker and a bounded O2 facade. The raw O2
Sources rows lack SeedCompileFlags; a deep-copied command view adds precisely
nine such fields from independently admitted ordinary Seed rows. Source/order/
hash equality precedes that projection. Raw compile flags still have to equal
the frozen O2 transform; raw capture records and command rows are not changed.
Both raw receipt descriptors and projection provenance remain in the evidence.

The witness executes authenticated source buffers, blocks host process/shell
creation during replay and consumes only fixed immutable reader inputs. It
validates exact leaf selectors, typed counts, named provider/consumer records,
nested audit and nonclaims before promoting the component verdict. Intended
receipt/manifest bytes and complete membership close before success. Late
failure independently clears both new binding verdicts even when the failure
hook throws; the pinned recovery helper permits only bounded diagnostic writes,
not replay or process retries. An output not created by this run is not revoked.

### Binding Scope

On each own actual machine/final twin, the unchanged audit supplies 26 complete
definition/origin records, eight forward functions, seven pointer roles, exact
private/storage identities, LOCAL current slot and ABI anchor, strong handlers,
GLOBAL post-LTO panic, attributes and full vector geometry. The extension adds
four reverse definitions, making thirty mandatory definitions, plus three
separately counted consumer extents. It does not relabel merged-machine origins
as original C translation-unit ownership.

The extension binds four reverse BL calls with original addend -4 and one
task-return ABS32 with original addend zero inside independently named consumer
function extents. Applied destinations, Thumb bits, original/final symbols,
mapping, map placements and emitted REL metadata are checked. Other common
runtime reverse consumers remain outside this selected-port reference scope.

It also binds two cold anchor reads and startup's original ABS32 references at
4/44/56 to Reset/SVC/PendSV and their final pointers. The cold LOCAL anchor may
use an unnamed section symbol, a nonzero original addend and an LDRB byte
displacement; raw metadata and the effective anchor address are retained rather
than rewritten as a named external zero-addend import. One delayed read per
twin, in context_init, retains r7 across five calls and records an AAPCS callee-saved
register assumption. CalleeRegisterPreservationProven and
ControlFlowOrDominanceProven remain false. This is retained-code binding, not
execution or full C-callee semantics.

### Tests And Actual Evidence

All fifty final-source host methods pass: eighteen byte-backed synthetic binding
methods, fifteen mocked admission/projection methods and seventeen frontend/
failure methods. They distinguish actual-shaped O2 metadata from Os-only fields,
file/directory admission, equivalent path spellings, raw/Seed projection and
foreign authority, malformed leaf records, alias/addend/origin faults, retained
cold-read linkage, owned output and stale-PASS revocation. Three suites close
five/four/three source files respectively without drift. Synthetic fixtures do
not execute actual ELF parsers, compilers or targets.

The fresh actual bundle is:

```text
C:/fz-current-cm3-lto-runtime-bindings-20261106-e3/
```

It returns `CURRENT-CM3-LTO-RUNTIME-BINDINGS-PASS-NOT-QUALIFIED` with
`Scope=NATIVE_CURRENT_CM3_O2_LTO_RUNTIME_BINDINGS_ONLY`. Both own-machine twins
pass thirty mandatory definitions, three additional consumers, eight forward
and four reverse providers, five selected reverse references, two cold reads
and three original startup vector bindings. There are ten new original binding
sites per twin; ordinary has zero applied REL records and emitted has ten.
The inherited seven pointer roles remain separately checked. Own-side load-image
twins, all 57 reconstructed command records and complete closing pass. This run
does not execute a new compiler/linker command or a target.

The bundle retains 338 source copies, fourteen binary-role copies, 51 executed
source buffers and nine explicit Seed-flag projection rows. It closes 3,217
input bindings and 353 artifacts. A separate parent read-only audit rehashes
3,218 unique files, validates every recorded physical identity, exact manifest/
receipt hashes, output membership and typed counts. That separate parent check
is byte/physical/report evidence, not another ELF predicate recomputation.

An independent consumer audit also closes the descriptors, all 353 artifacts,
3,217 watched files/physical identities and the source/binary/executed-buffer
bindings without drift. It independently recomputes both complete binding
proofs and the PT_LOAD/layout/entry/vector twin comparison exactly. The delayed
context_init read's AAPCS assumption remains explicit; no compiler or target
executes and no callee-preservation/control-flow claim is added.

| Source Or Local Evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_lto_runtime_bindings/CONTRACT.md` | `DAEB282DE77E2A258A66B87651CB5302BE358A7E3B3A1AF194D089D070BA2AFB` |
| `tools/fixtures/cm3_lto_runtime_bindings/bindings.py` | `A8C994427DDE61619AB789D62E198B24DEC0B05EF8D1EE8E1C28BE86536E4C3B` |
| `tools/fixtures/cm3_lto_runtime_bindings/witness.py` | `DFFA1D51EA6513C31612479720695973006BE627442C53D047AE65FDCD279289` |
| `tools/fixtures/cm3_lto_runtime_bindings/test_bindings.py` | `E879782FE6CD0149E4827757F17FFF6E8CCB9BB1EF683C8E1E30B8B50D1C75D1` |
| `tools/fixtures/cm3_lto_runtime_bindings/test_admission.py` | `5CB3D8FFC04AFA700B4A2425562D2822DEECA05E0FE3B0C03C4719C476AE7152` |
| `tools/fixtures/cm3_lto_runtime_bindings/test_witness.py` | `2A4A1387A74E7E8F6F58AC1DCCF69440DD47ADBE7568AB431A867D8EF6AA4CA6` |
| `C:/Users/admin/AppData/Local/Temp/fiber-cm3-lto-runtime-bindings-parent-pure-20261106-e1/results.json` | `A1561833C80D15C00864444F94C0E8B8FE44D1BDB5FB227B5A5A3E0FB34A84D2` |
| `C:/Users/admin/AppData/Local/Temp/fiber-cm3-lto-runtime-bindings-parent-admission-20261106-e1/results.json` | `BA6A240898496518FD9CA41DFBE4AACD3096182EA6CC695D8A5F1C618BF95526` |
| `C:/Users/admin/AppData/Local/Temp/fiber-cm3-lto-runtime-bindings-parent-frontend-20261106-e6/results.json` | `D295D2FFC768CD7843EC96A6B82144450150555C9B3B5C9D91A058CA5DA7E6B1` |
| Actual replay `results.json` | `1C2F88C7B6CF1BE52AA462960F730D897A064E75B05B9A9F96E529BE5829DCB4` |
| Actual replay `artifacts.json` | `5BA000BFE20CC6627FA9FA67AD86740DCA3E408CFCE30604E9CC5CE40F5D34EE` |

The final frontend regression set retains an earlier red result at
`fiber-cm3-lto-runtime-bindings-parent-frontend-20261106-e4-red/results.json`
under the same TEMP root: it exposes acceptance of junk AdditionalConsumerOrigins
before the exact name/raw-origin check was added. Actual attempts at sibling
`20261106-e1` and `20261106-e2` reject before output creation: the former catches
raw-versus-canonical descriptor path spelling, the latter the omitted directory
selector for SourceInventoryReceipt. The final E3 run uses corrected frozen
source; those pre-output rejections are not target defects or successful
receipts. Missing O2 SeedMode/SeedSide and SeedCompileFlags assumptions were also
removed before final execution, with independent Seed and command-view controls.

Source fingerprint remains
`69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313`;
the capture producer remains 1191CDC, the link audit 9D6B4E1, the reused command
checker BEC9C69 and the failure helper 7AFE40E at their existing full pins.
Raw new-source hashes bind measured LF bytes. Checkout newline conversion must
reject rather than normalize authenticated buffers; portable bootstrap is still
a separate CI obligation.

This is zero-credit provider/reference component evidence. All 2,774 keys and
26 backlog records retain their existing authority. Whole-slot source/generated
access isolation, typed ABI/hostile-codegen probes, fresh storage/reverse/cohort/
duplicate-handler link negatives and complete CM3 LTO cell composition remain
pending, as do Os/archive/broader-profile cells and portable CI. Full ABI and
semantic ABI, source/IR equivalence, policy/instruction equality, original TU
ownership, kernel/CPU/board execution and global qualification remain false.
Runtime C/assembly, public5/port8, qualified readers/producers and reference pin
are unchanged. Unrelated protected WIP is not inspected or included.

## Current CM3 O2-LTO ABI And Link Controls

The additive `tools/fixtures/cm3_lto_abi_controls/` component now executes fresh
typed declaration probes and five negative links for exactly current native
CM3 p4/b16 soft-float O2-LTO/direct. It does not invoke an ordinary-only receipt
constructor or falsify an LTO report as ordinary. The fixed runtime-bindings
admission rechecks E9, capture producer 1191CDC, the independent ordinary Seed,
tools/inputs and all 57 capture argv records without granting its ELF-binding
verdict. The source-copy tree belongs to the Seed; actual positive objects,
source-specific compile flags and link recipe belong to the current capture.

The pure ABI adapter preserves the independently spelled CM3 type/attribute
oracle and source pins. It binds the real capture's nine source rows, eight
slim-IR roles and explicit non-LTO startup, actual dependency declarations,
canonical provider headers, object/dependency paths and exact compile flags.
The original Seed discovery comparison, object/external bytes and command
authority are separate outer obligations, not an invented Dependencies field.
GCC14 no_sanitize reflection remains explicitly unproved; accepted declarations
and CPP scans do not establish attribute effects or full semantic ABI.

The final E3 run at
`C:/fz-current-cm3-lto-abi-controls-20261106-e3/` is terminal PASS-NOT-QUALIFIED.
Its 41 actual managed commands contain 33 exit-zero attempts, five intended
link rejects and three intended compile rejects. There are six fresh links,
ten C compile attempts and seven inspected successful slim-IR objects. No target
image is executed. Discovery/actual dependencies are checked for every fresh
compile, including the three exact undeclared-slot rejections.

The positive link reuses the actual nine inputs and semantic linker flags,
removing only standalone `-v` for closed diagnostics. Single-partition LTO,
saved-temporary/plugin flags, input order and linker script are unchanged.
The original ordinary-kind LTO twin (without --emit-relocs) and fresh positive
ELF have identical raw bytes. The frozen reader independently checks load
geometry/bytes, allocated sections, vectors and entry. Reader/helper execution
uses captured source and binary buffers with lexical path resolution; real
path/physical admission and closing run outside the immutable reader scope.
Forty-nine executed reader buffers are recorded.

| Fresh Negative | Controlled Compilation | Required Cause |
| --- | --- | --- |
| private cohort | expectation TU 6; NVIC bits 4 to 5 in its private header copy | only the actual alternate private cohort import is unresolved |
| storage cohort | application TU 7; selected storage revision 1 to 999 | only `fiber_port_storage_cohort_arm_cm3_v999_r0` is unresolved |
| reverse ABI | state TU 1; v1 anchor definition renamed v2 | unchanged consumers lack `fiber_internal_runtime_port_abi_v1_anchor` |
| SVC conflict | one added strong slim-IR SVC_Handler provider | exact original/added plugin-object duplicate |
| PendSV conflict | one added strong slim-IR PendSV_Handler provider | exact original/added plugin-object duplicate |

All controlled compilations succeed before the link rejection is counted.
Plugin-aware NM binds each intended import/definition; ordinary machine-size
assertions are not applied to slim IR. Complete closed diagnostic grammars
reject wrong symbols/providers, unrelated compiler/plugin failures, timeouts,
extra causes and stdout. The three unresolved diagnostics bind retained actual
ARM ELF32 REL LTRANS machines and their hashes, not just expected filenames.
All five failed links leave no final image. Saved LTO auxiliaries, including
cwd-owned wrapper argument files, are enrolled in the output namespace.

Five typed probes retain the unchanged independent source oracle: types and
attributes accept, while slot read/write/address reject for the exact undeclared
identifier. Accepted objects are genuine slim IR; raw ELF section counts bind
the complete indexed readelf table before the no-fat-fallback predicate. The
attribute probe's CPP scan retains both canonical header origins from that same
accepted attempt. This is a declaration proof, not post-LTO slot isolation or
an assertion that compiler attributes defeated every adversarial option.

Forty-seven pure methods pass: twelve ABI, eighteen diagnostic and seventeen
admission/orchestration methods. The combined late-error control starts from
a written synthetic PASS, makes the failure hook raise and the first FAIL
receipt write fail, then requires an independent bounded diagnostic write to
leave matching FAIL receipt/manifest bytes, original primary error and both
secondary errors. Separate stdout write/flush failures must also revoke a
written PASS through the protected CLI failure path. No tool/replay retry
occurs. Replaced output-directory or
hard-linked diagnostic destinations are rejected before fallback writes.

The measured E3 output has 799 declared artifacts (800 files with its manifest),
347 captured source buffers and 3,451 input hash/physical bindings. These are
overlapping provenance records, not independent execution counts. The source
fingerprint remains `69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313`.

Independent final E3 review rehashes all artifacts and watched/physical inputs,
binds every command stream, reclassifies five link and three compile failures,
and recomputes accepted probe sources, twelve CPP declarations/header origins,
provider facts and the positive ELF load-image comparison. It parses all seven
accepted slim objects and finds no unexplained source/input/output drift. This
review executes neither GCC nor a target and grants no additional qualification.

| Source Or Local Evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_lto_abi_controls/CONTRACT.md` | `B592F0B7741C5FA69507FEF67DD4B03D424926A1A9245E2A3929D656693623DC` |
| `tools/fixtures/cm3_lto_abi_controls/controls.py` | `7984A228966FC17641BD83D23486DB7E50BC2B7E5BC12D70A712F6E83800F14F` |
| `tools/fixtures/cm3_lto_abi_controls/abi.py` | `672508E25F984A6F3F7224E019395C874C2745786D318390699F80BCCD055CC6` |
| `tools/fixtures/cm3_lto_abi_controls/diagnostics.py` | `0A1CD4EB14172C3E3FF1E5B05A733C7837404E7DD95C8D6953323EB26FEA250C` |
| `tools/fixtures/cm3_lto_abi_controls/test_abi.py` | `B7ABB10BFF30AB83FFC6AE20EBA82D487D06692D3DC9E23ACAE687512A1D40C2` |
| `tools/fixtures/cm3_lto_abi_controls/test_diagnostics.py` | `A10AFE5C33AA4EFBEF7D02506D333A29BEB0C63D61AE54EDD42378FB70196AE2` |
| `tools/fixtures/cm3_lto_abi_controls/test_admission.py` | `6B2508EAAA61EB17984035DFC91D838EC66442FE7A7C13E4175D30C477661729` |
| `%TEMP%/fiber-cm3-lto-abi-parent-20261106-e1/results.json` | `C1D7410345567BF760604E5A0B7F9130B9C542CDDA9456A75803DD8C0F7F5BBA` |
| `%TEMP%/fiber-cm3-lto-diagnostics-parent-20261106-e1/results.json` | `3E759D8743F423649DF756DF4AAD6570F91D1F71F2E6EAB42B770AE7801BD936` |
| `%TEMP%/fiber-cm3-lto-controls-admission-parent-20261106-e3/results.json` | `2D7D81F084CAEFB075F8D63FF67C34121E46CA8F002348C663B3310A39F36723` |
| Actual E3 `results.json` | `815E2D568C7EFD4430E074EFF9A53342D33573EFEA4B8C7F56E872BF8DECA7DB` |
| Actual E3 `artifacts.json` | `5F78EA3FEFAB669D4E3B50817DF11DFA87100C66145AB8C9D4F41463450DEF88` |
| `%TEMP%/cm3-lto-abi-controls-independent-review-20261106-e3/results.json` | `B9A01CB90DD523A9EF2078D63CDD196003390F1C944E0D9C55DF96D39011E2CF` |

The sibling actual E1 and E2 runs are historical successful evidence before the
final hardening and CLI stdout guard, not qualification of final E3 sources.
The earlier parent admission E1 test receipt is a red development fixture with
stale mocked fields; the final seventeen-method E3 run uses the final source.
None is a target failure or relabeled PASS.
Raw LF helper pins reject newline conversion; portable CI bootstrap remains debt.

This closes only current CM3 O2-LTO typed declaration and five-link-control
components. Whole-slot source/generated isolation, CPU-free common LTO evidence,
hostile-codegen/attribute-effect obligations and complete same-capture cell
composition remain pending. Os/archive/broader-profile cells, portable CI and
hardware remain separate. All 2,774 keys and 26 backlog records retain their
authority; RequiredCellsSatisfied stays integer zero. Full ABI/semantic ABI,
source/IR semantics, original-TU ownership, policy/instruction equality, kernel/
CPU/board execution and global qualification remain false. No runtime C/assembly,
public5/port8, qualified helper or FreeRTOS reference byte changes. Protected
unrelated WIP is neither inspected nor included.

## Current CM3 O2-LTO Common And Slot Isolation

The additive `tools/fixtures/cm3_lto_isolation/` component now compiles common
core/state/panic without CPU headers and binds section-mediated current-slot
accesses in both original and freshly linked CM3 O2-LTO machines. Its literal
scope is current native CM3 p4/b16 soft-float direct evidence, not all profiles.
The fixed ABI-control admission independently rechecks current E9, capture
producer 1191CDC, ordinary Seed, source/tool/plugin authority and all 57 capture
commands. An explicit subclass reuses only command/output/IR utilities; it owns
its twelve-command completion, phase revocation, final schema and sealing.
Old typed-probe and five-link-control flags remain false, not inherited credit.

The unchanged common-source ownership predicate checks the admitted core,
state, panic and runtime source-role manifest. Three fresh compilations keep
the same source bytes, O2/CM3/soft flags and real slim LTO, removing only the
forced platform main header and replacing all include search paths with
context/fiber/root. Discovery and actual dependency lists agree at 11, 10 and
8 files respectively; all are admitted and none is CMSIS or `fiber/port`.
The three new ARM ELF32 REL objects have indexed header-bound section tables,
`.gnu.lto_` content and no nonempty executable fallback. This does not require
or claim equality of raw slim IR or serialized compiler options.

The two fresh links replace exactly input objects 0/1/2 with the isolated IR
and retain original objects 3..8, semantic flags, ordering and linker script.
The ordinary recipe omits only diagnostic `-v`; the second link adds only
`-Wl,--emit-relocs`. Both retain one-partition LTO and actual machine/plugin
temporaries, including cwd-owned wrapper argument files. The frozen ELF reader
compares the original/replacement ordinary images and both ordinary/emitted
twin pairs: entry/flags, PT_LOAD geometry/bytes, allocated sections and vectors
are identical. Nonallocated metadata and raw IR may differ.

For each original and fresh emitted image, the pure slot predicate binds the
actual merged LTRANS machine, map, final ELF and final disassembly. It retains
local four-byte NOBITS slot identity, whole-section placement and final writable,
non-executable zero-fill storage. Six complete source-derived fixed common
code-generation protocols bind guards, branches, calls, all stores and literal
pools; their five slot reads and single publication store are explicit. These
protocols do not establish general C semantics or callback/callee correctness.

Exactly eight original ABS32 words reference the dedicated slot section; eight
applied emitted references resolve to that same local slot. Their raw empty-name
STT_SECTION targets, addends and placements are preserved, not rewritten as
invented named imports. Both handler instruction streams census all eight
slot-bearing words projected from original RELs and map placements. Projection
does not require final REL metadata; pure controls cover nonemitted finals, but
both actual E2 slot proofs use emitted images. Ordinary images are load-compared,
not independently slot-inspected in E2. Each handler has exactly its own immediate
address/pointer-load pair. Extra own-pool loads, cross-owner pool reuse and
unsupported covered PC literal/address forms reject closed. The generated
`.LANCHOR`/source membership checks supplement the ELF evidence.

The leaf deliberately reports `CompleteHandlerBodiesValidated=False` and
`ArbitraryPointerAliasProof=False`. The outer `WholeSlotAccessIsolation` flag
is explicitly qualified by
`WholeSlotAccessIsolationScope=SECTION_MEDIATED_CURRENT_CM3_O2_LTO_ONLY`.
Full native handler preservation/canonical protocols remain separate enclosing
cell prerequisites; arbitrary constants/computed aliases and whole-program
memory safety are not claimed by this census.

Final E2 at `C:/fz-current-cm3-lto-isolation-20261106-e2/` is terminal
PASS-NOT-QUALIFIED: twelve actual managed exit-zero commands, three isolated
slim objects, two replacement links and one final disassembly. It seals 424
artifacts (425 files with the manifest), 3,238 hash/physical input bindings,
351 captured source buffers and 49 executed reader buffers. Those overlapping
provenance counts are not extra independent executions. The source fingerprint
remains `69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313`.

Thirty-five pure methods pass: thirteen runner and twenty-two slot controls.
They include complete synthetic positive records, malformed nested leaves,
typed/count/scope promotion, dependency/recipe changes, raw relocation/addend/
branch/map changes, coherent machine/disassembly stores and final-only/coherent
cross-pool loads. Source ownership and real ELF parsing are not delegated to
these synthetic models. Recovery tests start from a written synthetic PASS,
make the failure hook throw and the first diagnostic write fail, then require
matching FAIL receipt/manifest bytes and all isolation phases false without
rerunning tools. Success-output flush failure follows the same revocation path.

Review found and closed runner recovery/empty-leaf gaps and two handler-census
gaps (final/T32 forms and cross-owner pool reuse). E1 actual success precedes the
last gap's fix and remains historical. The earlier twelve-method pure receipts
and red development scaffolding likewise do not qualify the final sources.

Independent E2 review rehashes every artifact and watched input/physical identity,
checks all command journals/streams and recomputes transformed flags, both
dependency sets, three slim objects, source ownership, all three load comparisons
and both slot proofs. Each proof reproduces six complete common bodies (276
bytes), two handler pairs and eight original/applied slot references. It closes
with zero drift. This is independent replay of frozen predicates, not a second
independent decoder, another compiler run or additional cell qualification.

| Source Or Local Evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_lto_isolation/CONTRACT.md` | `5327BB040CE5DF0FE96A3F965C4548F555A3FD5B843B07C071DC7E36CF943C1F` |
| `tools/fixtures/cm3_lto_isolation/isolation.py` | `6EC1242D0ABBB120E2D684B30389B81043A67D267DE6F01F63F400FEC3E76524` |
| `tools/fixtures/cm3_lto_isolation/slot.py` | `669F294A622B076984E36F6FA9C73235BD0D3F778AA4A36F496051D49DE822B3` |
| `tools/fixtures/cm3_lto_isolation/test_isolation.py` | `B7416F7FC9249AED7762BB1F5F6042910C0F7043379BD65C80646D805ED457B9` |
| `tools/fixtures/cm3_lto_isolation/test_slot.py` | `0816B192F630259E6C4DD6579D9268A3A22898EAC1D8AE248F1B9DAF35C26AAE` |
| `%TEMP%/cm3-lto-isolation-parent-pure-20261106-e3/results.json` | `EB60B8F824099533E3E43BDF5CB388708D7E014E8A838B1154EAE6CE14E696EE` |
| `%TEMP%/cm3-lto-slot-parent-pure-20261106-e2/results.json` | `C1169473C46B8C96BB922F4E0E98B6BCE0FF0DC2A9156C8C142B2455C4A6CA14` |
| Actual E2 `results.json` | `30E54547F28D488EAAE776ADEAD18828C674E264927FF2CF1379AE6FAB91DB0C` |
| Actual E2 `artifacts.json` | `06406BD929ABB8AB323C08E1860488ED3766CBC18B9028B9FCC5BD466B9743F5` |
| `%TEMP%/cm3-lto-isolation-independent-review-20261106-e2b/results.json` | `AEC4FB2B520B9614FD1C7FCAF6103EF407FDB1102ED4BE349A5D5B7440535C3F` |

This closes only CPU-header-free common LTO compilation and bounded
section-mediated slot isolation for this current capture. Hostile-codegen
attribute effects and complete same-capture LTO cell composition are next;
Os/archive/broader-profile qualification, portable CI and board evidence remain
separate. All 2,774 keys and 26 backlog records remain visible; this component's
RequiredCellsSatisfied stays literal integer zero. No runtime C/assembly,
public5/port8, qualified helper, reference or protected unrelated WIP changes.

## Current CM3 O2-LTO Attribute Effects

This additive component uses fixed current admission, not inherited ABI-control
success flags. It independently authenticates E9, the current O2-LTO capture,
its ordinary Seed and all consumed source/header/tool/worker/parser bytes before
creating fresh output. Source-copy authority and actual LTO compile authority
remain distinct. CPU-free flags remove the forced platform header and rebase
only the three approved common include paths; discovery and actual dependencies
must agree. Every successful compilation is inspected as real slim IR.

The raw hostile flags are `-finstrument-functions`, `-fstack-protector-all`,
`-fprofile-arcs`, `-ftest-coverage`, `-fsanitize=undefined` and
`-fsanitize-coverage=trace-pc`. They remain normal driver arguments during actual
`-nostdlib -r -flinker-output=nolto-rel` lowering, not plugin-only intent.
Fresh captured-GCC `-dumpspecs` bytes permit exactly one removal of `-lgcov`
inside its existing conditional. No other specs edit, counterflag, compiler
change, runtime archive or hook provider is permitted.

Retained argument files bind the exact ordered WPA inputs and single LTRANS
temporary/output chain. Verbose compiler records bind the actual reported WPA,
LTRANS and assembler executable identities and hashes, all six lto1 flags and
their consumed owned response files. This does not claim an independent OS
process trace. The aggregate and worker ET_REL machines are both inspected in
one initially fresh immutable parser scope over twelve distinct binary roles.
No parser-cache deletion, module-global override or qualified-reader edit is used.

The protected catalog is six engine, seven state and one panic definitions.
Original declarations and definitions must carry canonical sensitive/GRO
tokens; actual bounded machine extents, maps, symbols and RELs determine effects.
Thread placement is checked on both actual machine roles. Ordinary cold
registration remains intentionally instrumentable, and constructor/counter
metadata is classified separately rather than treated as protected code.

Three private copies remove only the canonical bundle at the intended actual
declaration and definition, replacing exactly one positive IR each. They must
compile/lower and expose instrumentation at that named carrier; the unchanged
protected predicate must reject. The weak noreturn panic carrier requires an
actual enter transfer, not an impossible return-side exit. Paired stress sources
differ only by the definition's dispatcher bundle and require actual SSP,
instrumentation, gcov counter, signed/bounds UBSan and trace-pc activation in
the ordinary body, with suppression in the protected counterpart.

Final fresh E6 at `C:/fz-current-cm3-lto-attributes-20261106-e6/` is terminal
PASS-NOT-QUALIFIED. All 45 managed commands exit zero: eight discovery/compile/
IR-inspection/plugin-NM groups, one fresh specs query and six lower/disassembly
pairs. Original CPU-free dependency counts are 11/10/8, replacements are
11/10/8 and the two stress sources each have four dependencies. There are six
aggregate and six actual worker machine roles, not twelve separate compiler
runs. The sealed bundle contains 669 artifacts (670 files with the manifest),
3,355 hash/physical input bindings, 351 captured source buffers and 49 executed
reader buffers. These overlapping provenance counts are not independent tests.
Source fingerprint remains
`69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313`.

The positive aggregate has fourteen clean protected roots, three Thread
placements, two compiler constructors and sixteen imports: eight forward ABI
operations plus eight ordinary cold compiler-support imports. All three
annotation variants retain fourteen audited roots and expose the intended
carrier effects; their constructor counts are six/two/six. Their unchanged
positive predicate is refused on the aggregate. Both machine roles detect each
intended carrier. Protected stress has zero imports/constructors; ordinary
stress has twelve imports, two constructors and all five active families,
including an actual bounded resolved gcov-counter reference. LTO's numeric and
`.lto_priv.N` constructor suffixes are narrowly classified with unchanged
extent/mapping/per-body checks, not an arbitrary prefix exemption.

Forty-three pure methods pass: thirty source/metadata predicates and thirteen
runner controls. Synthetic fixtures are not genuine-ELF evidence. The tests
cover exact raw options, source deltas, one parser scope/twelve roles, wrong
worker identities/response chains, malformed nested records, constructor names
and a reproduced stress-profiling false positive. Ctor metadata without the
stress body's counter reference can no longer earn profiling activation. Late
failure tests begin with a written synthetic PASS and require matching FAIL
receipt/manifest bytes even when the failure hook and first diagnostic write
throw; there is no process retry.

E1..E5 remain failed historical attempts: dependency target grammar, an omitted
legitimate LTRANS gcno output, dotted compiler-worker path normalization,
repeated fresh-parser admission and legitimate constructor suffixes were
corrected before E6. Read-only successful inspection of earlier objects does
not relabel those failed receipts or qualify later source versions. Failure
revokes all component phases before fallible diagnostics; late seal/closing or
success-output failure cannot leave a reusable PASS receipt. Runtime C/assembly,
public5/port8, qualified helpers and the pinned FreeRTOS reference are unchanged.

Independent E6 replay rehashes all 669 artifacts and 3,355 watched input
hashes/physical identities, verifies every command journal/stream and checks
all 351 source copies. It recomputes eight compilation/dependency records, six
complete saved worker chains, source/annotation/mutation plans and all twelve
aggregate/worker effect proofs in one captured-reader scope. All four aggregate
unchanged-predicate refusals reproduce; closing reports zero hash or physical
drift. This is independent replay of frozen predicates, not a second decoder,
another compiler run, OS process tracing or additional cell qualification.

| Source Or Local Evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_lto_attributes/CONTRACT.md` | `47E6E37823358DD1025A1BA5D6A5491F1A2A1FF91FAC62CB20B2F00D7F22635F` |
| `tools/fixtures/cm3_lto_attributes/runner.py` | `9C99D38EACC8F3E3B2B63F343CA79555A66264AC76A3CA11957D2BEB0745987A` |
| `tools/fixtures/cm3_lto_attributes/attributes.py` | `93275A5903A67CB2DAEABB76BEF1431B052878BB478455E54343DB20881E83C0` |
| `tools/fixtures/cm3_lto_attributes/test_attributes.py` | `DBD593615066CC531F64432CEDD6680F9E0F6BFDC20D00D1350A098B139413C7` |
| `tools/fixtures/cm3_lto_attributes/test_runner.py` | `9882725918C24D5ABE9F420A9EBEA5E90E256E3FBD2F48563D44CE15A78E70D5` |
| `%TEMP%/cm3-lto-attributes-parent-pure-20261106-e3/results.json` | `EC9210E9A66D82520085DA3559AC0518A52D9FA6FB50F6F25E17B8E7A22CC72A` |
| `%TEMP%/cm3-lto-attributes-runner-parent-pure-20261106-e2/results.json` | `904560E100FD08637BA02BDE80473A5B8E9EE35E34453B78E9B362571DD94FCA` |
| Actual E6 `results.json` | `F164FF283B0EC4D422C83120152C3DFA32B6D75FC67C446309EFBF3DE26F944B` |
| Actual E6 `artifacts.json` | `CA0B0EC8B2349CED192C798CD26F4938764ADE904145FFE340EB1D7B36D0B54B` |
| `%TEMP%/cm3-lto-attributes-independent-review-20261106-e6/results.json` | `82C121E9E856981AC8A8D8F5FC16D4B5FC15A700CE15409DC419A1C4D86B3BE7` |

This is not a final firmware, full source/IR/ABI or arbitrary IPA/ICF theorem,
transitive callee protection, GRO-effect proof on an FPU target, full cell,
archive/other mode/profile, portable CI or board qualification. Required-cell
credit remains literal zero, with all 2,774 keys and 26 backlog records intact.

## Supported Sanitizer-Coverage Build Policy

The supported selected-port counter-option bundle now explicitly includes
`-fno-sanitize-coverage=trace-pc` after `-fno-sanitize=all`. GCC14 does not treat
trace-pc as disabled by the latter option. All nine supported-counter arrays
in `tools/compile_matrix.ps1`, the README and the normative runtime-boundary
contract use the same extension. Raw attributes-only tests are unchanged.

Development CM3/O2 slim-LTO experiments retained under
`C:/fz-cm3-port-policy-development-20261106-e1/` through `e5/` establish the
reason for the amendment, not qualification. The actual three selected-port
providers lower cleanly with the older six counters because their present
annotations suppress the observed effects. Removing only the function-entry
counter still produces a clean machine and is not an effective negative.
Applying the raw-six stress vector plus the old six counters to the nine-input
final causes undefined trace-pc calls in ordinary cold registration and the
fixture entry. That failed e3 link is preserved. An ordinary-driver replacement
link in e4 succeeds but is not a hostile final. With the explicit seventh
counter, the supported-policy final in e5 links without unresolved symbols.
No source annotation or runtime body was changed in these experiments.

PowerShell AST parsing and the exact nine seven-option bundle shapes pass.
Current E9/capture prewrite admission still passes after the policy/docs edits;
the runtime source fingerprint is unchanged. These are targeted development
and integration checks, not a rerun of the complete compile matrix, a sealed
new generated-code component, raw attributes-only suppression, additional
profile/mode or required-cell credit, CI qualification, or hardware evidence.
The selected-three machine/final audit and effective identical-source stress
control are a separate component under development.

## Current CM3 O2-LTO Selected-Port Policy

`tools/fixtures/cm3_lto_port_policy/` now implements that separate component
for the current CM3 p4/b16 soft/no-FPU/no-MPU O2-LTO direct capture. It admits
the same current E9 inventory, actual eight-slim-IR/one-startup capture,
ordinary Seed, unchanged providers/dependencies, toolchain/plugin/workers and
fixed reader buffers before creating managed output. It owns its stages and
closing predicate; no earlier component's success label is reused.

The actual three selected providers compile unchanged with the raw six stress
options followed by the supported seven counters. Dependency discovery and
actual compilation agree. Plugin-NM binds the exact 31-definition IR surface:
29 functions and two context/storage cohort objects. Both the combined
selected machine and the actual LTRANS worker census all 49 function extents,
3,806 instruction bytes, 122 mapped data bytes and 241 original REL fields.
Missing bodies, aliases, overlaps, uncovered bytes, malformed mapping/REL sites
and forbidden compiler-runtime dependencies fail closed. Recognized extended-
register encoding/mnemonic/operand forms are enumerated, not advertised as a
complete instruction decoder or a GRO-effect theorem on an FPU target.

An identical ordinary stress source is compiled under supported and raw-only
recipes. Both actual supported machine roles are clean. Both raw roles expose
all five instrumentation families, twelve compiler imports and an actual
bounded gcov-counter reference; the unchanged clean predicate rejects them.
Fresh dumpspecs bytes bind the existing single-conditional automatic `-lgcov`
removal used only for raw lowering. No runtime archive, stub, source annotation
difference or cancellation of a requested raw family creates the negative.

The final link replaces only the three selected IRs and preserves the other
six input object hashes/order. Its seven counter-options apply globally;
those six generated bodies are not presumed unchanged or raw-attribute-protected.
The complete actual final LTRANS has 71 functions and only four unresolved
linker-script symbols: `__pilot_ram_begin`, `__pilot_ram_end`,
`__pilot_text_begin`, `__pilot_text_end`. The final ELF has 72 functions, zero
unresolved symbols and 530 checked REL fields. Both roles receive the complete
byte census; the ELF also binds entry and vector slots 1/11/14. The unchanged
transport adapter independently retains the three complete transfer roots,
original/applied references and actual generated-machine origins. It does not
infer source-TU ownership, every C addend, or canonical FreeRTOS equivalence.

Final E6 at `C:/fz-current-cm3-lto-port-policy-20261106-e6/` is terminal
PASS-NOT-QUALIFIED. All 36 managed commands exit zero: five IR compilations,
three real relocatable lowerings, one final link and their discovery/inspection/
disassembly work. Eight physically separate machine roles are audited. There
are 538 sealed artifacts (539 files including the manifest), 3,281 input
hash/physical bindings, 352 captured source buffers and 49 executed reader
buffers. These overlapping provenance counts are not independent test cases.
Nineteen pure policy and thirteen runner methods pass, including ordered
overrides, byte/REL corruption, actual output grammar and late-failure recovery.

E1..E5 remain failed historical attempts. E1 rejected legitimate plugin-NM
trailing whitespace; E2 incorrectly ordered the independent GRO target flag
against GCC's regrouped `-f` options; E3 treated wide-objdump inline relocation
annotations as branch operands; E4 lacked `-z` and therefore could not census
suppressed zero literal words; E5 incorrectly required the pre-link final
worker to have no linker-provided address imports. The final checks retain
strict individual option precedence, complete real disassembly and exact
role-specific import surfaces. Bare hexadecimal branch targets such as `d0`
are distinguished from D-register operands, without exempting FP instructions.
Earlier diagnostic inspections and intermediate unit-test failures do not
relabel any failed receipt as successful or qualify later source versions.

Independent E6 replay rehashes all 538 artifacts and 3,281 retained input
bindings, rechecks every command journal/recipe/dependency/specs record and
four actual worker/assembler chains, and verifies all 352 source copies.
One captured-reader scope recomputes all eight machine roles and three root
transports: 492 root bytes, 170 instructions and thirteen original/applied
references. Closing verifies 3,419 hashes/physical identities with no errors.
This reuses frozen predicates independently of the producer verdict; it is
not a second decoder, another compiler/target run or extra cell credit.

| Source Or Local Evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_lto_port_policy/CONTRACT.md` | `05A871A63F6EDACA98AFFFEF7A78533F1F0CE8CE81023A9C7C2D489DC69781B9` |
| `tools/fixtures/cm3_lto_port_policy/policy.py` | `8FC3AD729BF8903D716E34579700FC22D417040156EFCF0B434D2C43D75F0CA0` |
| `tools/fixtures/cm3_lto_port_policy/runner.py` | `E06E55AC26B3828EDA54333DC7D5E0982DCC791694A2E9FE64E2A31C3BBE9AAB` |
| `tools/fixtures/cm3_lto_port_policy/test_policy.py` | `34B4F6663E765D9D093789F9EFD441DEA657C64F718E3946BC8049097BDEC24D` |
| `tools/fixtures/cm3_lto_port_policy/test_runner.py` | `81C009ED0F6F9A17AADAD854E978D4EC956C72F381F0DF3B30AECD79AFE74487` |
| `%TEMP%/cm3-lto-port-policy-parent-pure-20261106-e6/results.json` | `676CEF0DB27BF596033B270E04FA4D2538180F187951BC967FA4C7334D0C5DBF` |
| `%TEMP%/cm3-lto-port-policy-parent-runner-pure-20261106-e8/results.json` | `7FE3CAE18656FB7EC11E6549F40FC35F51CD11A6DD8F848BA954E37B7EC2CE88` |
| Actual E6 `results.json` | `67881BF68FFF5BB4F5FE482170F8300FABA6D9260464037992CE9BD3D6A61B6B` |
| Actual E6 `artifacts.json` | `41ADD7F0BDE6528B8C871DDE1C1D554DC75CE30E494B7851EB7F15682AB22585` |
| `%TEMP%/cm3-port-policy-review-20261106-e1-driver/audit.py` | `1507D2057812AD48C4029737D0E2818D6CFD0FC8C196260B657160C9D2428A22` |
| `%TEMP%/cm3-port-policy-independent-review-20261106-e6/results.json` | `042FFE031D273768EEF2C63B2BFB0185CB9E2BB1D7C99C3D03237C3D1AF26BE8` |
| `%TEMP%/cm3-port-policy-independent-review-20261106-e6/artifacts.json` | `F721DED49E385AE150EF488D398F19D584676ABE3A2F4ED98B2E3F14B8E72B13` |

This is supported-policy, concrete-compiler/static-fixture evidence, not
attributes-only protection, arbitrary callback/callee behavior, full IR/ABI or
instruction semantics, source-to-machine or FreeRTOS instruction equivalence,
an archive/other mode/profile, hosted CI or hardware qualification. Required-
cell credit remains literal zero; all 2,774 keys and 26 backlog records remain.
The existing common-attribute and normal-original image proofs stay distinct
from this replacement variant. The next integration is complete same-capture
CM3 O2-LTO cell composition, not another standalone component. Runtime C/ASM,
public5/port8, frozen helpers and the pinned FreeRTOS checkout are unchanged.

## Current CM3 O2-LTO Direct Static Cell

The additive `tools/fixtures/cm3_lto_final_cell/` composer closes exactly
`CM3/O2-lto/direct` for
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default`, fingerprint
`C7C37950A2C7391B8E9C719A828CE9A288A5634FBEB6C3934A41F5AF6177C700`.
It does not adapt an ordinary-only helper by mutating globals or relabeling
LTO metadata. The ordinary coverage helper validates the full E9 plan; a
separate pure model selects only this fixed LTO key.

The caller-bound catalog has nine exact roles: Inventory, Native, Reference,
Join, Bindings, ABIControls, Isolation, CommonAttributes and PortPolicy.
Complete manifests/input closures and exact capture/Seed/source identities
are admitted before replay. The two protocol children are derived from the
authenticated join producer bindings, not selected through a second unrelated
catalog. Both child captures must equal the selected current capture records.

Final E4 at `%TEMP%/cm3-lto-final-cell-20261106-e4/` terminates exit zero/PASS.
All three common prerequisites and eight runtime obligations are composed:

| Evidence | Actual Replay |
| --- | --- |
| Component recipes | 134 records: ABI 41, isolation 12, common attributes 45, selected policy 36 |
| Actual slim IR | ABI 7, isolation 3, common attributes 8, selected policy 5 |
| Runtime bindings | Both original normal machine/final pairs, forward8, reverse references, anchors and startup vectors |
| FreeRTOS mechanisms | Six complete native/reference start/SVC/PendSV bodies, own twins and declared rationales |
| Common isolation | Source ownership, three CPU-free compile/dependency records, replacement images and both slot proofs |
| Compiler effects | Twelve common aggregate/worker roles; eight selected-policy roles including final/vector/root evidence |
| Negative controls | Five intended link rejections, five typed/slot probes, actual undefined machine REL sites and diagnostics |
| Original normal census | Independent emitted LTRANS/final complete byte, symbol, allowed REL and recognized-form census |

One immutable source/binary reader scope contains 456 source buffers and 2,977
input paths. It consumes 87 recorded paths and executes 58 reader buffers.
Physical closing remains outside that scope. The final seal closes 8,666
input bindings and eleven output artifacts (twelve files including manifest).
These overlapping provenance counts are not independent test cases.

Only two new host inspection commands run, both captured `objdump -drwC -z`:
one for the original emitted LTRANS object and one for its final ELF. Their
attempt/terminal journals and raw streams are sealed. Compiler/linker/target
executions are zero. The original worker census has 71 functions, 4,382
instruction bytes and 206 mapped-data bytes; the original final has 72,
4,444 and 236 respectively. Supported-policy replacement bodies are not
presumed identical to the original generated bodies. Prior 32 transport and
two canonical-control catalogs/edits are authenticated, not reexecuted.

Coverage preserves all 2,774 exact required rows and all 26 backlog entries.
It credits only the fixed runtime/final/O2-lto/direct key, leaves 2,773 keys
pending and preserves 23 Pending / 3 ReferenceOnly backlog statuses. This is
one per-cell receipt, not a merged global rollup of historical cell receipts.

Thirty-seven focused synthetic methods pass: model 15, replay 13 and
orchestration/recovery 9. Recovery independently revokes provisional PASS,
coverage and every obligation on late failures, including stdout failure after
sealing. Nonzero/timeout inspector results retain their primary cause even
when stream storage fails; manifest recovery errors remain in FAIL diagnostics.

Earlier attempts remain unsuccessful. E1 failed admission because a catalog
file directly under TEMP made its parent overlap the fresh output; isolating
the catalog fixed the layout without weakening the guard. E2 revoked credit
when the new replayer treated deliberately reused common-IR inspection labels
as globally unique. It now requires the exact object-specific label/argv pair.
E3 revoked credit when an inherited empty `Compilations` field hid isolation's
three actual `IsolatedCommon` records. Both maintained regressions preserve
the complete fixed 23-object census. No runtime defect or frame change was
introduced or repaired in this proof-only slice.

Independent read-only review rehashes all eleven output artifacts, all nine
bundle trees, 8,666 retained input hashes and their recorded physical identities.
It checks full coverage/backlog accounting, all eleven current source pins,
the recorded recipe/machine evidence, snapshot bindings and separate original
censuses. It closes 8,676 unique files with zero drift and no reported issue.
This is an independent byte-closure/accounting review, not another execution
of ELF/protocol/slot/policy/diagnostic predicates or an additional cell credit.

| Source Or Local Evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_lto_final_cell/CONTRACT.md` | `7D5D8814CCBBC0E6DE242D0FFAF32D522E87DC6BB1844E3FE1E2C43756B1B6C2` |
| `tools/fixtures/cm3_lto_final_cell/compose.py` | `A056B0EDB67C87944819108A7113591791924E83BFB9D6E75735AE42F0681B1C` |
| `tools/fixtures/cm3_lto_final_cell/model.py` | `B9E75BFD97510F7571F9D80161D92AF6FE2E251FEC629FE7608D7ED37CC75815` |
| `tools/fixtures/cm3_lto_final_cell/replay.py` | `2A4C48B121F991B6E509D9F57661867C5D638FE4FA3F4BD3F71FB1E90ACF2638` |
| `tools/fixtures/cm3_lto_final_cell/test_model.py` | `10654FF33B7A344C197087D1C09B39D35D2DF2B94CBCBC50FE79589EA34489A3` |
| `tools/fixtures/cm3_lto_final_cell/test_replay.py` | `D823AAA4A3BD401075723AF06B069588A9599FCDE9389DDF76372378E21629D6` |
| `tools/fixtures/cm3_lto_final_cell/test_compose.py` | `807358A3C5DC25A09042BCC285418DBF957D6BF3B57E3426FD5C6A7E150082C4` |
| `%TEMP%/cm3-lto-cell-catalog-20261106-e2/catalog.json` | `AF1162F6726B37C27AC5D64860743C18782EE6308A17CF365EA4E153778D9F34` |
| `%TEMP%/cm3-lto-cell-model-parent-20261106-e1/results.json` | `7A1464955ACE6C9AFE9549BCF0F63D79D91400C3906AF1BF7351B40EC86D16EE` |
| `%TEMP%/cm3-lto-cell-replay-parent-20261106-e3/results.json` | `D6CA3F1B6574E263B441C427E62AF64B6D35406CC844548834DD47517E028E60` |
| `%TEMP%/cm3-lto-cell-compose-pure-20261106-e4/results.json` | `7E7175DCF41639B0ADE8BD23A66989A5E752602522713766C07AC70907913878` |
| Actual E4 `results.json` | `BA28CD3732C649EFB8B9C6CC778FEBB80F14E4583B974C7374238AC9DAD1E60C` |
| Actual E4 `artifacts.json` | `27FD717042DDA8BA1C96704047993DF5C479EEC70DC030E4BFBE5BE3FD0F3B02` |
| Actual E4 `coverage.json` | `568DB0EA3B094EA5B092482DDC7827B627FB93E4C3DBCE49E138886F6B724180` |
| Actual E4 `missing-work.json` | `1C1C23BD26BD3AFF00873724C0EC6C379AAE3E9A842EACF3DBC62A842E557DC9` |
| `%TEMP%/cm3-lto-final-cell-independent-review-20261106-e4/audit.py` | `B576F1286F569FFB66AC163047EEABC615F2BA4E10C30C8B2A428B084E84DA80` |
| `%TEMP%/cm3-lto-final-cell-independent-review-20261106-e4/results.json` | `8B9FD9FF7966D8F00A419FEB1F6B0EF49CCF652751E9CDBFF6CDABD57EB0E21B` |

Runtime C/ASM, public5/port8, qualified helpers and pinned FreeRTOS are
unchanged. No full semantic ABI/C/IR/instruction/policy equivalence, arbitrary
callee safety, source-to-machine ownership, another mode/profile/archive,
hosted CI, global freeze or hardware qualification follows from this cell.
The next integration work is to extend actual final-LTO cell coverage, not
to count existing zero-credit components as completed cells automatically.

## Current CM3 Os-LTO Roots And Bindings

The next mode now has actual current-source evidence, using the E3 native and
reference Os captures and independent E9 inventory. The ordinary O2 Seeds
remain source-copy authority only. Current capture records retain the sole
O2-to-Os optimization transformation and genuine saved workers/final ELFs.
No frozen helper globals, O2 result modes or historical receipts are rewritten.

`tools/fixtures/cm3_os_lto_final_cell/` is the single staged home for the
remaining Os cell work. Its initial two stages are not full-cell qualifiers:

| Stage | Actual Terminal Evidence |
| --- | --- |
| `roots` | Protected E2 PASS, six complete bodies / three mechanisms, own-side twins, declared rationales, fresh 32 transport and two coherent canonical controls |
| `bindings` | E2 PASS, both own native machine/final twins, 30 mandatory definitions, five selected reverse references, two cold reads and three original startup vector references per twin |

Both constructors reconstruct the full 57 native / 37 reference capture
recipes and bind the same current source fingerprint, capture producer and
ordinary Seeds. The roots run closes 5,793 input hashes and 777 output files;
it captures 587 source buffers and executes 61 reader-source records. The
binding run closes 5,018 input hashes/physical identities and 603 output files.
Its one immutable parser graph has 587 source buffers / 600 input paths and
52 executed-source records. These provenance counts are not test counts.

The native Os binding model calls only explicit mode-neutral low-level
predicates and the unchanged Bindings class, not their O2 top-level audit or
inspect entrypoints. Original and final symbols/sections/RELs, read-only pointer
tables, ABI/private/storage identities, BSS slot geometry and strong vector
slots are checked independently on ordinary and emitted-relocation twins.
Selected applied binding counts are zero and ten respectively; load images
must agree. Typed declarations, all consumers and whole-body semantics are not
inferred from these selected-site bindings.

Os context initialization retains the cohort and ABI anchors through r8.
The initial byte0 read is not the later byte1 runtime ABI read. The new narrow
T32 alternative binds the positive PC-relative literal, raw LDRB instruction,
section ABS32/addend, final byte address and contiguous entry-to-read bytes.
Possible r8 writes and unsupported encodings reject. Six intervening calls
require named original RELs, map-bound targets and emitted applied RELs where
applicable. AAPCS callee-save behavior remains an explicit assumption; callee
semantics and dominance/control flow are not proved.

The first actual binding attempt E1 failed because the new matcher expected
width-suffixed `ldr.w`/`ldrb.w` mnemonics, while the frozen reader normalizes
them to `ldr`/`ldrb`. E2 fixes only that interface mismatch; raw 32-bit opcode,
register, literal, REL and preservation checks remain. The synthetic fixture
now models actual normalization and rejects false width-suffixed records.
E1 remains a retained FAIL with zero credit, not a relabeled success.

Twenty-five pure ABI/binding methods and fifteen orchestration methods pass.
They cover typed counters/nonpromotion, original/final site mutations, r8
clobbers, cohort-versus-anchor reads, call authority, exact pin authentication,
O2 rejection, process prohibition and late failure revocation. The new CLI
keeps flushed summary printing inside its protected failure path, including
the roots stage. Legacy roots reports acquire ClosingErrors before recovery;
a transient FAIL-write fault cannot skip retries. The frozen frontend remains
unchanged and is not used as the CLI here.

Independent E2 bindings review rehashes all 603 output files, all 5,018 inputs
and physical identities, five original trees, recipe/journal records, source
pins and leaf accounting with zero drift. This is accounting/byte-closure
review, not independent execution of ELF/protocol/slot predicates. The earlier
current roots E1 review similarly checks its 772 outputs and 5,783 inputs;
that historical entrypoint is distinct from the new protected E2 run.
The protected E2 roots review independently checks all 777 outputs, 5,793
input hashes, five original trees, 57/37 recipes, six roots and 32/2 control
records with zero closing drift. Historical physical identities are not fully
persisted by the frozen roots interface; the review checks current identities,
not an invented historical physical-identity record.

| Source Or Local Evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_os_lto_final_cell/CONTRACT.md` | `7F6FA323F1DC117541B7DFCB7CAE4844252E7C3FD19FCF46C8CF8174E4020057` |
| `tools/fixtures/cm3_os_lto_final_cell/abi.py` | `D0471869CA413901AB51016BDA662683FAED60231FB87CD9F9BA14BFD121A73E` |
| `tools/fixtures/cm3_os_lto_final_cell/runner.py` | `1B4BFC82D20398FA4F128B368104360C888C27DDBF5104ED74A80819F4371716` |
| `tools/fixtures/cm3_os_lto_final_cell/test_abi.py` | `3DE1A1AC6199AC5F8E0ADAB02827A1964CF40C387EA0785DB0B785E8E9C9613D` |
| `tools/fixtures/cm3_os_lto_final_cell/test_runner.py` | `7323343DCE90524FE9184CC1E282191A9E1C402695F6F061FDEE70E4A3221E0C` |
| `%TEMP%/cm3-os-lto-final-cell-parent-abi-pure-20261106-e1/results.json` | `C0135ECDED4B1050FDCC475FB2C8633B8B6D7F15E467DEA4D896E7D0FC5DA893` |
| `%TEMP%/cm3-os-lto-bindings-20261106-e2/results.json` | `369526F5CE2DEA3B1A496AEF5437A8EF25FBB0F131D38C71E5696509CE0D12A9` |
| Binding E2 `artifacts.json` | `BB08641ABE9E715CFA4C9FADEA0DABAF6032867C152D62A976C3710C8985EA88` |
| `%TEMP%/cm3-current-os-protected-replay-20261106-e2/results.json` | `F74E17BE8B55C0359F807E968ED7D7EFC42FA495F2E2AF37A4ED78B69EF2A57A` |
| Protected roots E2 `artifacts.json` | `0F91EF537CE6E138297F3A1A152E532789CD586E37C4328E523284BB45ECD858` |
| `%TEMP%/cm3-os-lto-bindings-independent-review-20261106-e2/results.json` | `96EE8E5D230F341ED9F18FBB28AB9518400562894CD84AC9D0CCBF22B2C413F8` |
| `%TEMP%/cm3-current-os-replay-independent-review-20261106-e1/results.json` | `EC6343610E75D55699A9E8A702DC497005AC370A3C50861091F0558B6E015AA5` |
| `%TEMP%/cm3-current-os-protected-independent-review-20261106-e2/results.json` | `8C2884023959AFF4E53FC7A33E944E6B8BDB5312411D64880C6736F1C9293E79` |

Compiler/linker/target executions are zero in both replay stages. Runtime
C/ASM, public5/port8, qualified helpers and pinned FreeRTOS remain unchanged.
Both results have literal zero required-cell credit. The full 2,774-key plan
and 26-entry backlog are not reduced by these components. The next executable
batch must provide Os typed ABI/link controls, complete slot isolation,
common/selected-port compiler-stress evidence and the normal-original census
before a same-fixture composer may credit the Os cell. No full semantic ABI,
source/IR/machine equivalence, arbitrary callback safety, archive/hosted CI,
global freeze or hardware qualification is claimed.

## Current CM3 Os-LTO Slot And Batch Support

The additive Os `slot.py` has its own six complete protocols and narrow
encoder/assembly grammar. It receives authenticated neutral origin, mapping,
REL and handler-address helpers; it neither changes their global O2 program
table nor calls their O2 top-level inspect and relabels a result.

The real E2 session/slot probe authenticates the existing E9 Os native and
reference captures before constructing the new command session. Nine actual
Os providers and the source-copy Seed, actual tool/plugin identities,
captured environment and exact Os link recipe are retained. The constructor
is dry: no output exists and no child process is started. Session start then
captures its enrolled bootstrap bytes. Both original Os native twins are
audited in one immutable parser graph, with writes performed only after that
scope has closed.

Both slot leaves pass with six complete bodies / 272 bytes, five common
loads, one common publication store, eight slot references and two immediate
load-only handler pairs. Ordinary/emitted applied slot-reference counts are
zero/eight. Original/final raw bytes, section-mediated symbols and RELs,
source/generated inline pairs and all slot-bearing word membership remain
bound. This does not establish arbitrary-pointer alias safety, complete
handler-body semantics or source-to-machine semantic equivalence.

The first actual probe E1 fails because its temporary driver attempts to
persist a leaf output while the immutable read-only scope is active. The
guard rejects that new path. E2 moves persistence outside the scope and
repeats the whole probe in a fresh directory; the slot predicates and session
sources are unchanged. E1 remains FAIL with zero credit. The E2 probe closes
5,627 input hash/physical bindings, 603 mapped artifacts (604 files including
the manifest), 598 source buffers and 54 executed reader-source records.
Compiler/linker/target invocations are
zero; these provenance counts are not test counts.

Forty-six synthetic methods pass: 16 slot, 20 recipe and 10 session tests.
Source-reviewed mutations cover instruction/REL/branch/alias/pool/store
changes, wrong modes/flags/recipes, literal counters, undeclared helper
buffers, managed journal faults, object drift and timeout without retry.
An independent session-source review finds no confirmed inherited-method
attribute or closure blocker. Its pure tests mock tool results; the actual
probe establishes admission and slot replay, not real compile/link execution.

`BATCH_CONTRACT.md` keeps 41 ABI-control, 12 isolation, 45 common-attribute
and 36 selected-port-policy commands explicitly planned, not executed. The
session records complete terminal phase ranges but cannot publish PASS/cell
credit. Exact command-label/disposition checks and phase semantics belong to
the new Os driver. One immutable final reader must compose the actual outputs
before the Os cell can receive credit. The old O2 phase drivers and verdicts
are not reused.

| Source Or Local Evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_os_lto_final_cell/BATCH_CONTRACT.md` | `D9EAE7806028289EDB5A69B6317DA6247A19E1B15ACED5B75FF5D6194DE8EE66` |
| `tools/fixtures/cm3_os_lto_final_cell/batch_recipes.py` | `C15D57AA9FE3963FF84F22D831F4E1F5F941AC351571AB347ECBC29E9172004B` |
| `tools/fixtures/cm3_os_lto_final_cell/batch_session.py` | `E600788C8563ED44327A61CED2B5D518A354DE19B33BA6614B04733E3E5D4FB6` |
| `tools/fixtures/cm3_os_lto_final_cell/slot.py` | `B47B8ACF2F98172D79509BC60DF42D4603F3FAF7CEC9F1BA29995057621F7F9F` |
| `tools/fixtures/cm3_os_lto_final_cell/test_batch_recipes.py` | `0634225EB7527728E22916679ED76FC076ECC4E364E4D760B4D272269EF8BA87` |
| `tools/fixtures/cm3_os_lto_final_cell/test_batch_session.py` | `B53991270787B33381E5C8159674B2FFBAFFCCA1C9EF49CF7CF08E70F71243DC` |
| `tools/fixtures/cm3_os_lto_final_cell/test_slot.py` | `EC6EC3F2ADFB25747897927FCFE587F2F7C0DCBECD6A602C6C75B4425E4330C2` |
| `%TEMP%/cm3-os-batch-probe-20261106-e2/results.json` | `436E2A955B026061485F6B0C4184EA4C844FC50B9D9552F671D5D52734A7623B` |
| Session/slot E2 `artifacts.json` | `97AB10CD1B31F3C7649AFDFCC31503758D040DE82457CB3D036F35C7267A7B2C` |
| `%TEMP%/cm3-os-lto-slot-parent-pure-20261106-e1/results.json` | `68F1E80C65F8D3D5A1F71D710D964131DAC33969E90FF83194169E208486B6F8` |
| `%TEMP%/cm3-os-lto-batch-recipes-parent-20261106-e1/results.json` | `F3B680804A3364AA73722EA03C5B59BD0D74DF663D67B87A8B0B30E96C4A9650` |

This is a zero-credit support/static-replay checkpoint. The actual Os
ABI/link/probe batch, isolated-common replacement, compiler-stress evidence,
normal-original census and final same-fixture composition remain pending.
All 2,774 inventory keys and 26 backlog records remain. No runtime C/ASM,
public5/port8, frozen helper, FreeRTOS, CI or hardware change is implied.

## Current CM3 Os-LTO ABI Controls

The same Os fixture now has an executed ABI-control component, not just a
planned command count. `abi_controls.py` runs exactly [0,41) over the admitted
Os session. The positive link retains all nine original Os objects. Three
stale identity/anchor and two duplicate strong-handler variants are compiled
from explicit copies/additions. Real slim-IR/plugin symbols and complete
diagnostics establish each intended missing or duplicate definition. Separate
types/attribute probes compile; C reads, writes and address-taking of the
current slot fail with the exact undeclared-symbol diagnostic. Exactly eight
of the 41 commands have intended nonzero exits.

`declarations.py` receives the authenticated ordinary oracle explicitly and
reuses only mode-neutral source/type/CPP predicates. Fixed eighteen-source
identities and nine provider/dependency declarations are bound independently.
The ordinary Seed flags and actual Os/slim transform have separate checks;
objects and external dependency bytes remain capture/admission obligations.
The positive recipe removes only one verbose flag, preserving actual Os
input order, target, LTO and linker policy.

`abi_attempt.py` waits for every tool to finish, then enters one immutable
captured-parser graph. It recomputes provider declarations and twelve CPP
canonical declarations and compares positive/original load images. Writes,
source physical closing and exact output membership checks happen outside
that graph. The successful E2 report closes 5,862 input hash/physical bindings
and 1,053 mapped artifacts (1,054 total files with the manifest), with 600
source buffers, 662 reader input paths and 54 executed-source records.
There are 41 host tool calls, including 26 compiler-driver calls, and no
target or board execution. These provenance counts are not test counts.

The E1 prototype also executes all 41 commands and its positive reader, but
three synthetic methods expose 63 malformed-record acceptances in its
completion predicate. Phase equality accepts numeric aliases, the nonclaim
set is incomplete and clean-error fields are checked by truthiness. The
driver is repaired only after that attempt terminates. E2 reruns all 41
commands on the stricter source in a fresh directory. E1 is retained as
prototype evidence, not rewritten as the accepted hardened checkpoint.
Its later original-driver source drift is intentional; its captured source
buffer preserves the prototype bytes. No CPU/runtime defect is inferred
from these report-checker defects.

The fixed checker requires exact integer phase boundaries/counts, literal
2,774-key/zero-credit counters, all applicable nonclaims literally false,
present None error fields and an exactly empty closing-error list. The five
fresh link controls are truthfully recorded as NegativeLinkControlsExecuted;
the frozen bindings-only runner is unchanged. Post-seal output, manifest or
flushed-summary failures revoke the result without replaying tools. Forty-eight
focused methods pass: 16 declaration, 12 phase-build and 20 driver controls.

Next-phase `isolation.py` and `attributes_phase.py` have 12 and 14 passing
synthetic tests. They are build-only [41,53) and [53,98) adapters, not executed
phase evidence. Own Os flags, CPU-free dependency checks, explicit replacement
objects, source edits, specs adapter, saved worker roles and zero-inclusive
disassembly plans are retained. Worker options, load-image/slot/provider
proofs and hostile-machine effects are deferred to the enclosing reader.
Both modules leave overall FAIL/zero. A test-harness review moves frozen
helper authentication before execution in isolation and ABI-build tests;
the corrected 12/12 suites pass without runtime-phase source changes.

| Source Or Local Evidence | SHA-256 |
| --- | --- |
| `tools/fixtures/cm3_os_lto_final_cell/ABI_CONTROLS_CONTRACT.md` | `7DECF4FA302A3DC1C92C3E0B882A90BDAF851BE2B86C3E33EBFBE46A52BB40B6` |
| `tools/fixtures/cm3_os_lto_final_cell/abi_attempt.py` | `18237999981DAF689C4D297CC93A9CE574804F1C65578FD4A9E91CD715440279` |
| `tools/fixtures/cm3_os_lto_final_cell/abi_controls.py` | `A05048E4A5047EDF0090C39AD8199C5D5A6B5981A1E0EBA9FA69ACD2850F8379` |
| `tools/fixtures/cm3_os_lto_final_cell/declarations.py` | `B502C330A5F00CE10393390866F160030EE604E8A9BC8080F8633D9BF66245B2` |
| `tools/fixtures/cm3_os_lto_final_cell/test_abi_attempt.py` | `B63285AF21F5CFAD01415CE6AC9929C5E0D26B78392356C1BE0864B556628699` |
| `tools/fixtures/cm3_os_lto_final_cell/test_abi_controls.py` | `E62A1C732513DBE0AD8D8C5C5EED13182377D3A8F092E2032850BF91B1732868` |
| `tools/fixtures/cm3_os_lto_final_cell/test_declarations.py` | `8ED2DA88049C251D410CA5FAE61D5941D4E40359AB3A58E5D1C306CF703A0F9F` |
| `tools/fixtures/cm3_os_lto_final_cell/isolation.py` | `3838848CF4421656ECF0DAFBDA03AE72FC4A2EFD5083C31202A592CBA16D9F65` |
| `tools/fixtures/cm3_os_lto_final_cell/test_isolation.py` | `900DDD53F8CD675CCAF027A870571073B5D67FF76236F1D179925A593AE3CC46` |
| `tools/fixtures/cm3_os_lto_final_cell/attributes_phase.py` | `CAD8817F486DE3E3B945C54CC8AAF2EACCC185A85134BEE8D343835E3F07DF3C` |
| `tools/fixtures/cm3_os_lto_final_cell/test_attributes_phase.py` | `9C63AF7DADBCA3D4D079B728F3534FB5EE99288FF6A4110B9FD0ED97E28360D3` |
| `C:/fzosabi-20261106-e2/results.json` | `A02D7DE621786FDE7AC187AEB703C40C8D0A149CC1C5E86384A6076B30CB33F4` |
| ABI E2 `artifacts.json` | `2E72A67FB2FC696E6B7BC4E190FB6412A248E1361173611E36DF535B2519E439` |
| Prototype E1 `results.json` (not accepted checkpoint) | `9896B8EB81CDBECA2995A3F6CF09BD22A869D82A6E018696D4709455362E35F5` |
| `%TEMP%/cm3-os-lto-abi-attempt-owner-20261106-e1/results.json` (FAIL) | `3507DD6E25DE371255214BD1EA5C6C0DB69D1F0F715EF7341739ECDAADEFC2EF` |
| `%TEMP%/cm3-os-lto-abi-attempt-parent-20261106-e2/results.json` | `478773C4F2A327CD89CDB0285214B27FD5E2311BDD1221939136A256BE7C7742` |
| `%TEMP%/cm3-os-lto-abi-controls-parent-20261106-e2/results.json` | `1D278C85E1231983F606780CA5F92C71573087265EB6F66CFBE4CEAB1B42A1C7` |
| `%TEMP%/cm3-os-lto-declarations-parent-20261106-e1/results.json` | `6268E6F9631BB94313DCD90A7A08349942D0482F2F1DE8E5A8F32EE1775357BF` |
| `%TEMP%/cm3-os-isolation-build-pure-parent-20261106-e2/results.json` | `46EB3EE2ADC5CA06F117438117B3F288F32D5589878C852475FC68FFDDAC9CEE` |
| `%TEMP%/cm3-os-lto-attributes-phase-parent-20261106-e1/results.json` | `48005AE4FAC8B9ACCB12082A4BC1BEC7808A723A4975E040810828E703F9BEF0` |
| `%TEMP%/cm3-os-batch-independent-review-20261106-e2/results.json` (earlier slot/support accounting) | `4F1B71F3FD81C24CE928C839E6FF2A70FA9D1E9F9BDDE9142B7B608102BFCFE8` |
| `%TEMP%/cm3-os-abi-independent-review-20261106-e2/results-r2.json` | `6F0DCEB582472EC6D0FED65D6652608E0409D18EC26CA1887E2378F576EB11DC` |
| ABI E2 independent `audit.py` | `45335DA6AEDBE57BAA54000CE6C03FE4185D812C16CD6FD35F79A8B30925676D` |

The earlier slot/support independent review confirms 603 mapped artifacts /
604 total files, 5,627 inputs and identities, 598 source copies, 23 bootstrap
and 54 executed-source bindings with zero drift. It verifies accounting and
recorded leaf counts, not independent slot predicate execution.

Independent ABI E2 accounting review closes every mapped output and the
manifest (1,054 files), all 5,862 original inputs/physical identities, 41
journals and 82 raw streams with zero drift. It binds 600 source copies, 25
bootstrap and 54 executed-source records, nine providers, twelve canonical
declarations, five intended link and three undeclared compile records.
Reader accounting distinguishes 662 buffered input paths from 75 actual
unique read bindings. Its initial assumption about that relationship fails;
the first reviewer receipt is retained. The corrected r2 review changes no
production source, artifact or predicate. Positive raw ELF byte identity,
the single recorded immutable graph and load-image comparison are bound but
not independently recomputed. No compiler, ELF predicate, target or board is
executed by this review, and it grants no additional credit.

The Os cell still has zero credit: the remaining build phases and actual
machine/worker proofs, selected-port policy, normal-original census and
same-fixture composition are pending. This does not reduce the 2,774-key plan
or 26 backlog records. Full semantic ABI, arbitrary-callback protection,
archive, CI, global freeze and hardware qualification remain unclaimed.
Runtime C/ASM, public5/port8 and pinned FreeRTOS are unchanged.

## Current CM3 Os-LTO Batch And Machine Preparation

The new build-only orchestration uses one admitted session and the exact
41/12/45/36 command plan. It does not execute O2 phase drivers, constructors,
readers or verdicts. All source/helper buffers are enrolled before admission,
and the existing full pre-command closure remains in force.

Real attempt `C:/fzosbatch-20261106-e1` terminates FAIL after 115 managed host
commands. The first 98 commands complete ABI controls, isolated common builds
and six common hostile lowerings. Selected runtime/boot/exception compilation,
plugin queries and the first selected aggregate lowering also complete. All
115 command records are terminal: 65 compiler-driver calls, eight intended
nonzero controls and no unexpected tool nonzero result. This is not a finished
134-command batch and gives zero required-cell credit.

The immediate rejection is in the option checker, after GCC succeeds: actual
saved WPA/LTRANS arguments contain canonical `-march=armv7-m` and
`-mlibarch=armv7-m`, including repetition. Exact `-Os` is also repeated. The
checker had rejected all `-march` options; the common worker adapter separately
assumed only one `-Os` occurrence. The corrected source accepts repeated exact
CM3 facts but rejects foreign values, split forms and valueless forms. Original
source/compile flags are not rewritten. Updated pure port-policy/common-worker
suites pass 12/13 methods. E1 is retained as FAIL, not retroactively promoted.

The failure receipt has stale zero command counters; the separate sealed
`commands.json` is the actual 115-command authority. The driver now preserves
that journal and its real counters in failure reports. Parent post-terminal
checking verifies every one of the 1,522 manifest-mapped artifacts and exact
membership (1,523 files including the manifest). This verifies byte/accounting
closure, not the pending machine predicates. Later original driver/phase source
changes are intentional; E1's captured source copies retain the executed bytes.

Pure Os-owned machine support is separate from the tool build: common effects
(14 methods), port census (17), machine composition (10) and common worker
provenance (13 after canonicalization fix). The census public API cannot use
`None` to skip provider validation. Final vectors require allocated file-backed
sections, unique readable load coverage and matching raw bytes. The composer
binds twelve common plus eight port machine roles and eight disassemblies to
their declared path/hash pairs. Parser bytes must equal those bound bytes.
No O2 top-level verdict is relabeled. Unresolved setter attribution stays pending;
no caller may convert it into a clean protected-body result.

| Local Evidence | SHA-256 |
| --- | --- |
| E1 `results.json` (FAIL) | `47E2DD49B2A0D9CF81B161A8AF261FA19FE4E1707F4EB539824656E316244669` |
| E1 `artifacts.json` | `2653E362B7367D42DB4077EA315056C9580D8D50B2152332558B0C1C8DBD2909` |
| `%TEMP%/cm3-os-port-policy-pure-parent-20261106-e2/results.json` | `75D24AB44B379508BB983A4E08523A21119D8814335B7C7950D7F162CF755C3E` |
| `%TEMP%/cm3-os-common-workers-pure-parent-20261106-e2/results.json` | `104CA8B4B4E03C40FDDA04558627258505ED1ED8F9980106962721F85144D669` |
| `%TEMP%/cm3-os-common-effects-pure-parent-20261106-e1/results.json` | `061256F9C3B67EE6EBBE1142CFCA5D38D7931E47C3AF25CF16C860431A1A9E1C` |
| `%TEMP%/cm3-os-port-census-pure-parent-20261106-e2/results.json` | `CF35358BCFA1E7F8F5F3FE70C848EC7A355CF07960CC72133CBB11CF629C6837` |
| `%TEMP%/cm3-os-machine-replay-pure-parent-20261106-e1/results.json` | `745CD9F271BCF6EE1D2686137D7024E29BD665A2B6EF7D1F9CE89FD701CB3962` |

A bounded review also identifies two driver-hardening duties: pending catalog
membership must equal its original component projection, and recovery writes
must require the successfully claimed output directory's unchanged physical
identity. The supplemental `BATCH_RECOVERY_CONTRACT.md` records both obligations.
The next producer execution must use the fixed checker/guards in a fresh output;
all actual machine/worker predicates still require the single immutable reader.
These records grant no Os-cell, archive, CI, global-freeze or hardware credit.
The 2,774 inventory keys and 26 backlog entries remain unchanged. Runtime C/ASM,
the five-operation public API and eight-operation port boundary are unchanged.

Both reviewed driver gaps are now implemented, with twelve pure guard methods
and twenty-two orchestration methods passing. `batch_guard.py` reconstructs the
complete ordered 142-role handoff from original top-level records and InputHashes,
not copied pending metadata, and checks typed component correspondence. The
driver calls it before sealing a build-only disposition. Recovery retains the
existing failure-persistence routine inside a per-write guard: the originally
claimed root must remain the same non-reparse directory; only direct regular
single-link results/manifest files may be overwritten. Unclaimed/preexisting
and replaced roots are regression-tested without modifying unrelated files.
The root check is not an atomic hostile-filesystem race defense.

| Updated Source Or Pure Evidence | SHA-256 |
| --- | --- |
| E1 executed batch driver, retained in captured source buffers | `2C477E6190BC23621F3FE9A8547841484724657F2DED20BAEF9735007DBA99B1` |
| E1 executed port-policy phase, retained in captured source buffers | `FA1EEED580BA905A0F8F04D7731A6F581D26820BBA4E44F9D720BDC0BE14A205` |
| Current `batch_attempt.py` | `EC52A23182A5B0B4A09E18429E5BFB94902FBC42592785295D7283ACB572F38A` |
| Current `test_batch_attempt.py` | `A6BF61A3B5293FB48AD253D88838C90A81127B7A57A2E8F01A312717C3988B7F` |
| `batch_guard.py` | `1281084AF70A6AADEA9590E4839311D3F3FA813B17ED06EEE5CD402F4E69BAFD` |
| `test_batch_guard.py` | `BE47EA9F0984DB09803DB4E5FE95AA0D05402E87B5BD36F5A80B6380B918013E` |
| Current `port_policy_phase.py` | `371821947E1F14E0C0DEBC5561EFD3EF8B539B20C9B00F288A8534143D29EB80` |
| Current `common_workers.py` | `F12A77717924A11DF5F6FA29800271D335A09C475819171C31EFC0B757474EDB` |
| `%TEMP%/cm3-os-batch-attempt-pure-parent-20261106-e3/results.json` | `7103D834F41335731F8193F6A9ABFF81F976F1CC0DFE639116FC9B84246B660F` |
| `%TEMP%/cm3-os-batch-guard-pure-parent-20261106-e1/results.json` | `02F9E70E05BB6528F643EBFF5ACB2612BBB85423F70C281C4D72D0522B4B97AB` |

No corrected full-batch tool run is claimed by these pure tests. The next actual
producer attempt must use a fresh output directory and this fixed source cohort;
its one-scope machine/worker/ABI/isolation/transfer replay remains required.

## Current CM3 Os-LTO Sealed Batch

Corrected producer `C:/fzosbatch-20261107-e1` completes all 134 terminal host
commands: 72 independently recounted GCC-driver calls, eight intended nonzero
controls, no timeouts and no unexpected exit. Its four phase ranges are exactly
41/12/45/36. The status is `BUILT-PENDING-READER`; all component replay and
required-cell counters remain unpromoted. This supersedes only the earlier
statement that a fresh corrected producer execution was still required.

Independent post-terminal checking verifies every one of 1,634 manifest-mapped
artifacts and exact membership (1,635 files including the manifest). It also
checks 6,120 input hashes/physical-identity records, 610 captured source records,
the complete 134-command journal and the 142 original pending-reader roles.
The earlier `C:/fzosbatch-20261106-e2` process had stopped after 26 terminal
commands without a final manifest; it remains incomplete, not repaired in place.
The original failed E1 and all captured executed source bytes remain unchanged.

| Corrected Batch Evidence | SHA-256 |
| --- | --- |
| `C:/fzosbatch-20261107-e1/results.json` | `3DCE7C453AF909B6B917B9A3EED552F1725D70ED9420CEA74A36797ADB12EEC7` |
| `C:/fzosbatch-20261107-e1/artifacts.json` | `35E2A0B0895AD8458F8476C8E6F672176E39687B69137804E3342DDC663BD635` |

The additive `machine_attempt.py` authenticates the builder's exact opening
registry before admitting the same explicit Native/Reference/inventory cohort.
It verifies original physical identities without overwriting an earlier
identity during role re-enrollment. All helper sources are authenticated before
construction; frozen helper imports, receipt reparsing and ELF reads then use
one immutable reader. Worker paths may be lexically normalized without physical
filesystem access. Undeclared artifact paths and traversal remain forbidden.

`worker_bindings.py` reconstructs ten ordered worker plans from original phase
records and exact command positions. It binds all thirteen compilation sources
and their discovery/compile journals, reconstructs both specs adapters from
actual dumpspecs stdout, verifies six common and four selected-port lowering /
final cohorts and saved WPA/LTRANS options, and binds zero-inclusive disassembly
to the producing stdout. The final supported link replaces only three selected
port objects; the other six native objects remain unchanged. Stored
`ActualWorker` records are comparison targets, never input-selection authority.
Recorded compile commands do not establish source-to-IR semantics or OS process
tracing; those remain explicit nonclaims.

First actual replay `C:/fzosmachine-20261107-e1` is retained as FAIL at
`closed REL kind/symbol/section`. Binary census identifies type 38 TARGET1 only
in the two original priority-100 compiler constructor arrays, across ten of the
twelve common images. The corrected matcher accepts only unique four-byte
`.init_array.00100` / `.fini_array.00100` sections with exact type, flags,
alignment and entry size, zero original addends and matching local Thumb
constructor functions. Other TARGET1 sites/targets/shapes fail. Returned rows
retain no resolved ABS32 or applied-destination claim. The platform-specific
meaning follows the [Arm ELF ABI](https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst);
no linker interpretation is assumed by this original-field census.

| Retained Failure And Focused Pure Evidence | SHA-256 |
| --- | --- |
| `C:/fzosmachine-20261107-e1/results.json` (FAIL) | `47D68503D0D154366618B4007E9AC13BE5C8B0BB263E5AD112CBE45343D659EC` |
| `C:/fzosmachine-20261107-e1/artifacts.json` | `A7B63E329D10F15530FC6B2EFA82A80A1188EEDD3FB25A8731630E5E50A10F05` |
| `%TEMP%/os-common-effects-target1-parent-20261107-e1/results.json` (20 methods) | `A4A7358534426165456B263EC27F300EA015851151E0633859519A4AF1F66E45` |
| `%TEMP%/os-worker-bindings-parent-20261107-e2/results.json` (30 methods) | `265AD207A85F995DA4140B5D7E10EE482BB64924123FB4C1C5FD758C86B9C99D` |
| `%TEMP%/os-machine-attempt-parent-20261107-e7/results.json` (35 methods) | `5BAB5A154DBF8B5F60AC1A2EB667C7B874C64D166E7CAB71064F070DB1018E19` |

The additional unchanged composer and port-census suites pass 10 and 17 methods.
The total is 112 focused synthetic methods, with zero failures/errors/skips and
no source drift. They test shape/negative/ownership contracts, not actual Os
machine qualification. Independent bounded diagnostics also accept all twelve
common and eight selected-port images after the fix, reject the intended
mutant/raw carriers and find no unresolved common attribution; those diagnostics
are not a substitute for the complete sealed CLI replay.

The driver preserves unresolved attribution as pending and grants zero cell
credit even on a bounded completed replay. ABI, isolation, normal-original
census, final roots and reference parity still require same-fixture composition.
In particular, the original capture's disassemblies omit `-z`: two separately
journaled zero-inclusive inspections are needed for a complete original-image
census; the supported replacement final image cannot substitute for it.
No runtime C/ASM, context layout, public5/port8, reference pin, 2,774-key inventory
or 26-record backlog changes. Archive, CI, global freeze and hardware remain
unqualified.

### Actual Machine And Worker Replay

Fresh attempt `C:/fzosmachine-20261107-e2` completes with exit zero and status
`MACHINE-WORKER-COMPONENTS-REPLAYED-NOT-QUALIFIED`. Inside one immutable parser
graph it recomputes twelve common and eight selected-port machine roles and ten
saved worker chains, including actual mutants/raw stress rejecting the unchanged
clean predicates. There are zero unresolved common-attribution entries. The
first failed replay is not rewritten or used as positive evidence.

The completed result closes 6,684 input hashes/physical identities, 618 captured
source buffers and 1,659 supplemental reader inputs. Its immutable graph has
2,277 admitted input paths, 64 executed-source records and 295 unique actual read
bindings; admission does not imply every buffered path was consumed by a
predicate. The output manifest maps 2,278 artifacts (2,279 files with the
manifest). Primary/closing errors are empty. Tool/compiler invocations, target
execution and required-cell credit are zero. Worker invocation evidence remains
compiler-reported, not an OS process trace.

| Actual Replay Or Executed Source | SHA-256 |
| --- | --- |
| `C:/fzosmachine-20261107-e2/results.json` | `FB8595A87A782D39C04FA17D8A5ECFF7361BF3C219DE3FE76F0E70D20644470B` |
| `C:/fzosmachine-20261107-e2/artifacts.json` | `B2A766A0ABC31596F07C1F871F8884853ADBD724E0F79F01AD78009040ED3F53` |
| `machine_attempt.py` | `3CB43C29FF23281AC9EC36C32BC7C700E35038C78DE7BD95389213417D8684F0` |
| `worker_bindings.py` | `7A899F3B0EAD365900086F252455ACA25E10684ACC24F7605754D29308896834` |
| Corrected `common_effects.py` | `800942F1CA34DCE0198258C13D85F5BA422DF6BF88726694360C16B39270C81D` |
| `MACHINE_REPLAY_CONTRACT.md` | `89EB98B0DBE5053503DE545D77D35147A8879D6268B8E5221C743B4FAD6D8DCF` |
| `MACHINE_ATTEMPT_CONTRACT.md` | `F8FC812307D6D8DB3074B5CE78720FC24C9353D34FD01ABC2A3787428AEE053B` |
| `%TEMP%/os-machine-replay-parent-20261107-e1/results.json` (10 methods) | `745CD9F271BCF6EE1D2686137D7024E29BD665A2B6EF7D1F9CE89FD701CB3962` |
| `%TEMP%/os-port-census-parent-20261107-e1/results.json` (17 methods) | `CF35358BCFA1E7F8F5F3FE70C848EC7A355CF07960CC72133CBB11CF629C6837` |

The complete Os cell is still not qualified. The next bounded slice is the
normal-original census and its two missing zero-inclusive inspection journals,
followed by same-reader ABI/isolation/root/reference composition. No prior O2
top-level verdict or supported replacement-image result supplies that credit.

## Current CM3 Os-LTO Original Image Census

The additive `normal_attempt.py` admits the unchanged sealed 134-command batch
and the same explicit Native/Reference/inventory descriptors. It authenticates
all added helpers and the attempt contract before witness construction, keeping
the original builder opening registry separate. Exactly two managed captured
objdump commands inspect the original emitted final ELF and its original saved
LTRANS object, both with `-drwC -z`. There are no new compiler invocations.
Aggregate/per-command journals, raw streams, copied dumps, targets and executable
bytes are bound to the same hashes and physical identities.

The pure `normal_census.py` reconstructs the selected definition surface from
the three actual plugin-nm outputs at batch indices 103/108/113. Source, original
object, selected object and journal bytes are independently bound; stored
definitions are comparison targets. The surface contains 29 public functions
and two cohort objects across runtime/boot/exception. This is journal/object
provenance, not source-to-IR semantics or original translation-unit ownership.

Fresh actual attempt `C:/fzosnormal-20261107-e1` completes with exit zero and
status `ORIGINAL-CENSUS-REPLAYED-NOT-QUALIFIED`. One immutable graph recomputes
the original whole-image censuses and ordinary/emitted load-image comparison:

| Original CM3 Os-LTO Input | Functions | Instruction Bytes | Mapped Data Bytes |
| --- | --- | --- | --- |
| Emitted saved LTRANS object | 71 | 4,078 | 206 |
| Emitted final ELF | 72 | 4,140 | 236 |

The load twins are identical. The 256-word synthetic vector table is allocated,
file-backed and load-bound, with entry/SVC/PendSV symbol bindings; canonical root
protocols and actual target execution are not inferred. The supported replacement
image is not substituted for either original input.

The completed receipt records 7,306 closed input hash/physical-identity pairs,
615 captured sources, 2,900 immutable input paths, 59 executed-source records
and 35 unique actual read bindings. The pure census records 23 bound input reads.
Buffer admission is not proof that every buffered file was consumed. The output
manifest maps 626 artifacts (627 files including the manifest); post-terminal
checking verifies all output hashes and exact membership. Primary and closing
errors are empty, tool invocations are exactly two, compiler invocations and
required-cell credit are zero. The upstream batch and Native receipts remain
unchanged.

The two new synthetic suites pass 22 census and 20 driver methods, with no
failures, errors, skips or source drift. Independent review found and closed
two driver issues before execution: process creation is blocked throughout
immutable reader entry/body/closing, and bounded JSON parsing rejects finite
syntax that overflows to infinity as well as literal nonfinite values. Tests
also cover typed journals, target substitution, output ownership/recovery and
revocation after flushed-summary failure. These synthetic methods do not
replace the actual ELF replay.

Independent post-terminal audits additionally verify all 7,306 input hashes
and physical identities, six dependency trees with 6,408 mapped artifacts, all
615 source snapshot pairs, 40 bootstrap and 35 builder-opening records, and the
59 executed-source / 35 reader bindings. Separate byte diagnostics rehash all
143 function bodies and 592 recorded relocation fields and compare the three
load segments and vector words. These are independent byte/accounting checks,
not a second execution of census predicates or stronger semantic qualification.

| Original Census Evidence | SHA-256 |
| --- | --- |
| `C:/fzosnormal-20261107-e1/results.json` | `3BC6FB8489267674C035B889720F8C3599057266DC67CBBAC511CE6C7F054BBC` |
| `C:/fzosnormal-20261107-e1/artifacts.json` | `B3846B21C347C0B8D313003A030A5E8B116293423B936BA80FE15737F7100E97` |
| `normal_attempt.py` | `ADC2D945F336C4325D3A14151DF5B0E8566DE348871211B9EFB0280A3AC8E084` |
| `normal_census.py` | `65CE1B6E796390CFA8EDDA36C81D4986ED07BD41351CB8CBF72117FABBBD09D1` |
| `test_normal_attempt.py` | `4597C5C2AC7574A00856952284B1C9708A1DFAB03110395FAADA013DE70F06BD` |
| `test_normal_census.py` | `EA39F7DD45F36111CE56A5E3334798699195079DD3EEF081E4C67F92981F5664` |
| `NORMAL_ATTEMPT_CONTRACT.md` | `E262137A5393EC7D245A1CEDFEFB7E5B8DB9A52CB97CDF2EB226A662BD3472BB` |
| `%TEMP%/os-normal-attempt-parent-20261107-e2/results.json` (20 methods) | `2B555F04CF2DE1DE42C75D87AA0D859E4D70A2A3A28F810D4CBE17A5C8C10575` |
| `%TEMP%/os-normal-census-parent-20261107-e1/results.json` (22 methods) | `AA6C601E6E533C9D5B5CFB4CB868EE0C0E6469462C23F2A62A48E74D33570E39` |

This closes only the missing original-image census obligation. The next bounded
slice recomputes provider declarations, saved preprocessed attributes and
positive-link reproduction alongside this census in one fresh reader. Full
negative ABI-control replay, isolation, root protocols and reference composition
remain separate obligations; receipt-only merging is insufficient. Runtime
C/ASM, context layout, public5/port8, the reference pin, 2,774-key inventory and
26-record backlog are unchanged. No archive, hosted-CI, global-freeze or hardware
qualification is claimed.

## Current CM3 Os-LTO Census And Deferred ABI Composition

The additive `abi_census_attempt.py` admits the sealed original-census handoff
as input, not a reusable verdict. It verifies its receipt/manifest, exact tree,
declared input hashes/physical identities, captured-source pairs and shared
batch/capture authorities. The two saved zero-inclusive inspection journals,
raw streams, dumps, original targets and captured objdump are rebound to the
current admission. No new tool command is executed.

The same fresh immutable graph reparses the batch, Native and handoff receipts,
recomputes the original census, and invokes the pure `abi_replay.py` for three
deferred facts: provider dependency declarations, saved preprocessed attribute
declarations and positive load-image reproduction. All 70 admitted project
sources are explicitly added to reader roles, covering the 43-file provider
dependency set; prior hash admission alone is not reader access. The leaf binds
76 unique explicit inputs, nine providers, eighteen fixed source identities,
twelve CPP declarations (eight forward/four reverse) and two compared images.
Both leaf results must name the same original ordinary ELF and identical load
comparison. Stored provider/CPP/census facts are comparison targets only.

Fresh actual `C:/fzosabi-census-20261107-e1` completes with exit zero and status
`ORIGINAL-CENSUS-AND-DEFERRED-ABI-REPLAYED-NOT-QUALIFIED`. It recomputes the
original 71/72-function worker/final census and identical ordinary/emitted load
twins alongside the three ABI facts. The receipt closes 7,929 input hash and
physical-identity pairs, 618 captured sources, 43 bootstrap records, 2,956
immutable paths, 63 executed-source records and 107 unique actual reader
bindings. The 23 census and 76 ABI leaf bindings are not total graph reads.
Admission does not imply consumption of every buffered input. The output has
621 mapped artifacts (622 files including its manifest), with empty primary /
closing errors. New tool/compiler invocations and cell credit are zero; the two
recorded upstream inspection invocations have their own separate counter.

The new suites pass 22 leaf and 21 driver synthetic methods without drift,
failures, errors or skips. The retained first driver test receipt is FAIL: a
synthetic summary callback exposed that diagnostic printing after an exception
could run after process/shell guards were restored. The corrected main keeps
its catch/diagnostic path inside both guards; all 21 methods then pass without
weakening the regression. No real process or target code was executed by that
negative test. Independent bounded review also checks the explicit shared-image
guards and the strengthened nested result schema; diagnostic probes are not a
substitute for the sealed CLI execution.

Post-integration repetition of all four new suites passes 85 methods with the
same successful receipt hashes. Independent post-terminal accounting verifies
all 7,929 input hashes/physical identities, 621 output artifacts, seven upstream
trees with 7,034 mapped artifacts, 618 source snapshot pairs and all 63 executed
source / 107 reader bindings. Separate bounded diagnostics verify the 76 ABI
bindings, shared image joins and narrow nonclaims without rerunning the CLI or
predicates. All 7,306 original-census and 6,120 batch bindings remain preserved.

| Deferred ABI Composition Evidence | SHA-256 |
| --- | --- |
| `C:/fzosabi-census-20261107-e1/results.json` | `00551787515C6C648127D4EA16370F84726C3E099D7F2C3DF022543E08247969` |
| `C:/fzosabi-census-20261107-e1/artifacts.json` | `152C49634E435075CD3B51ECE4D004EB38275772401E0E1A3BA59E956A783440` |
| `abi_census_attempt.py` | `529565FAEF586E10DB09C9A913D6E2541CC4E9BBC6169FCEFB802F0B43DAC111` |
| `abi_replay.py` | `6854D207E12345E856CB9CDCF9B7BA6281EF66FE3C003A474573524D1B1FE3FB` |
| `test_abi_census_attempt.py` | `85726443E182DA9D8C2E1F55C77E9CC71EC10C60C85C29912BD5FF70D76B5D7A` |
| `test_abi_replay.py` | `EC721471F18089C94DCB19FEBE731B5364BEEA9149866A3A98E8A396389EC4BF` |
| `ABI_CENSUS_ATTEMPT_CONTRACT.md` | `A2CF578726FF811AA028D811B65CAE19321A1697D3C32E29467062F15556A900` |
| `%TEMP%/os-abi-census-attempt-parent-20261107-e1/results.json` (FAIL) | `6E7B4CEC87C7D8073D25C38F406B53057855F5810691768CFC2DC36B7381E4E0` |
| `%TEMP%/os-abi-census-attempt-parent-20261107-e2/results.json` (21 methods) | `EC4838BF05C8B418B806A6ADA7BD3F7F5BCBD0FF3EC5AA7FA3AC4D0D404C7C34` |
| `%TEMP%/os-abi-replay-parent-20261107-e1/results.json` (22 methods) | `979BB0B8DA03828321D40F243E8AAC401BA2F18184DD29A50848E058D4940C7F` |

The next bounded slice replays the five intended failed-link controls and three
absent-slot compile controls from bound raw journals, including plugin-nm
evidence, original mutations and dependency records. Accepted typed/attribute
compile provenance is a separate remaining obligation. This composition does
not prove those controls, source-to-machine semantics, attribute effects,
external dependency semantics, map/recipe semantics, isolation, root protocols
or final reference parity. Full ABI, whole-cell, archive, CI, global-freeze and
hardware qualification remain false. Runtime C/ASM, context layout, public5 /
port8, reference pin, inventory and backlog are unchanged.
