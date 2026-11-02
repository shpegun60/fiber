# ARM_CM33F_MPU Non-secure FreeRTOS Reference Audit

## Status And Boundary

Status: complete explicit build-selected runtime; post-selectable-metadata
six-gate qualification passed, 2026-11-02.
The constructor, immutable integrity checks, exact MPU-image encoder/builder,
private FPU-policy helpers, linker assertions and basic first-start transfer are
implemented. Private SVC #71/#72 and protected PendSV have separate execution
and pinned-reference assembly receipts recorded below. The SVC object now owns
the seven remaining forward operations, exact context/storage providers and
the handler-bundle dependency; the constructor supplies the eighth operation.
The complete-group runtime and current-code parity gates have passed separately.
Global auto
selection remains absent; the concrete profile is explicitly build-selected.
`FIBER_PORT_RUNTIME_SELECTABLE` is now one. The repeated manifest, constructor,
first-start codegen/execution, running-component execution and complete-group
runtime gates all pass with that value. The separate immutable current-code
running parity receipt predates only this metadata promotion; a fresh parity
replay remains part of combined qualification. No board result is implied.

### Transitive Compiler Closure Followup

The A32 raw-flags audit finds unannotated CMSIS inline CPU calls below otherwise
annotated C3FP helpers. The dictionary now owns sensitive, general-registers-only
raw CPU reads, WFE and NVIC priority-byte operations. Call sites use those local
primitives; no naked transfer, frame, context identity or runtime-selection
change is made. The existing documented compiler counter-options remain required
until an independently qualified build-policy change; the attributes-only gate
is an additional stronger proof, not a reinterpretation of older receipts.

All six maintained gates pass again against the repaired sources: manifest,
constructor, first-start generated code, first-start execution, running-component
execution and complete-group runtime. The last gate executes 161 AN505 cases and
9,349 checks; sixteen-region and default-panic cases retain their compile/link-only
boundary. The separate raw whole-group compiler audit and immutable reference
parity replay remain pending. No actual FreeRTOS execution or board claim is
made by these six gates.

```text
Complete-group runtime:
  %TEMP%/cm33f-mpu-runtime-e77cc17fb945475eb601ea05c9b8096d/receipt.json
  SHA-256 F0D7416DA54E443D500F15DC2094448AE3B9CA1D213E91DE718DFD9DF14FA863
Five-component replay:
  %TEMP%/fiber-c3fp-a32-components-c2fd9ab296e74c2e966c6326dbed5011/results.json
  SHA-256 4DA94805FC330EC3380BE49C4C70A2B459B6D11EFB8882411A3733B98E954840
Independent parent rehash:
  17,450 recorded input/artifact entries, fifteen manifests, zero mismatches
Exact six-gate union, 84 repository-local inputs:
  %TEMP%/fiber-qualified-repo-inputs-b300424c6cab49779b7dac08ae0abbd4
  ZIP SHA-256 D97289FE58A0B546D9EC2F6B60403C86435E754100F98A8BFF178D118E814691
```

This is the next required scalar-FP MPU cohort from the pinned
`ARM_CM33_NTZ/non_secure` reference, not a SecureContext or TF-M role. Its intended
boundary is Cortex-M33, Non-secure unprivileged Thread execution, scalar FP,
PSPLIM and a protected per-context MPU image, with explicit 8/16-region manifests.

The new identity is C3FP (`0x43334650`), private layout generation 1
(`0x00010008` / `0x00010010`), feature mask `0x1C87`, and public storage
`arm_cm33f_mpu` revision 1 with the 8/16-region suffix. Corrected C55 generation-2
semantics are the starting contract of this new identity, not an old M33 layout
being reinterpreted. Neither private nor public identity borrows C55P or scalar
M33 MPU identity merely because some frame mechanics match.

The five public operations, eight-operation generic forward port ABI, reverse
ABI ownership and CPU-neutral public headers remain unchanged. Completion stays
under the current v2 ownership model. The later clean CPU/Context extraction
must wait for the documented port-freeze checkpoint and comparison gates in
[`CONTEXT_FIBER_ARCHITECTURE.md`](../../../../CONTEXT_FIBER_ARCHITECTURE.md).

### Repaired-Source Running Parity Replay

The independent A32 replay passes actual pinned-reference generated-code
comparison at O2/Os, hard/softfp and 8/16-region configurations: eight tuples,
264 compiled transfer mutants and sixteen harness controls. It compares the
running components, not every C validator or a full provider executing on a CPU.
Seven captured production files remain byte-identical; the eighth has only the
documented removal of an extra EOF newline. The immutable receipt continues to
identify the original exact bytes; naked instruction semantics do not change.

```text
  %TEMP%/fiber-c3fp-a32-immutable-20261102-c88eaab7aff6485fa1904ded9f2996e5
qualification.json SHA-256:
  10775407DACF2203E318AC97C0C0413EEEAB38E71944A9D4114727A0101219C0
Immutable source ZIP SHA-256:
  1589E212E775B58333AA29AB144A6D04AA7230A5FC70D7952B2D13650AF250D0
```

### Implemented File Boundary

| File | Implemented scope |
| --- | --- |
| `fiber_port_types.h` | CMSIS-free C/C++ storage; 54-word overlapping protected image, four/twelve region pairs, aligned 352/416-byte context; distinct storage facts and declaration, no storage provider or expectation relocation. |
| `fiber_port_boot_types.h` | The 88-byte immutable boot record and exact processor/feature metadata fields; no constructor or sealing implementation. |
| `fiber_portmacro.h` | Strict M33 manifest, scalar-SP compiler policy, region/register/frame dictionary, C3FP identities, per-field offset/size assertions and private inline register/vector building blocks. `FIBER_PORT_RUNTIME_SELECTABLE=1` after complete-group qualification. |
| `fiber_port_boot.h` | Private boot API, immutable seal constants, twelve linker boundaries, global-image type and declaration of the later task-return continuation. |
| `fiber_port_boot.c` | Unprivileged basic construction, exact v8.0-M MPU encoding/map checks, metadata/MPU sealing, initial-image-only validation and private CPACR/FPCCR preparation/readback. |
| `fiber_port_linker_contract.ld` | Required symbols, exact 32-byte apertures/ranges, section placement and disjointness; board addresses and startup zeroing remain integration-owned. |
| `fiber_port_private.h` | Private first-start, running SVC, protected first/next scheduler bridges, PRIMASK helpers, bundle/component anchors, naked handlers and three return-site labels; imports frozen forward/reverse declarations without a C current-slot declaration. |
| `fiber_port_svc.c` | Strict rewind-only first start, SVC #70 provenance, global/per-context MPU installation/readback and basic first restore; owned private #71/#72 veneers and running admission; seven forward adapters, exact providers and cold handler bundle. No FP transfers. |
| `fiber_port_pendsv.c` | Pre-save validation, conditional scalar-FP protected save/inverse restore, frozen reverse selection/publication, masked MPU replacement, protected first scheduler selection and CPU/MPU preservation checks; independent cold reverse-v1/cohort component guard. |

The dictionary includes the established trait, exact-cohort and geometry headers
so components cannot invent a different contract. The dictionary itself defines
no provider or handler. The constructor remains boot-owned and retains its
reverse-v1 and exact-cohort expectations. Direct concrete-type allocating
consumers need the existing explicit storage-expectation header; bare type
queries must remain linkable without a runtime provider.

### Runtime Activation Slice

Post-promotion qualification uses the real common runtime and all production
forward providers. It passes 9,349 complete-group checks with 161 AN505
executions. The 64 sixteen-region images and 16 default-panic images are
compile/link-only evidence (72 compile-only cases total), not executed MPU
isolation or default-panic paths. Running-component execution separately passes
988 checks/57 launches; first-start execution passes 120 subset checks and 28
public-surface compatibility checks. Constructor and first-start generated-code
gates retain their own reference comparison and negative cases.

```text
Six-gate post-metadata receipt:
  %TEMP%/fiber-c3fp-promotion-e283e071721b469d9dcbc093358f4f09/receipt.json
  SHA-256 65F8F111BE97C3960ED92082574EFAC8B72FCAB29AA0C6DBB887BC7A21166DE8
Complete-group receipt below that root:
  full-runtime/cm33f-mpu-runtime-c882ccc80c634e3d849d93edf3a4d77c/receipt.json
  SHA-256 C372896EA1B30604254DB4F2678867DA0CAE9EFAC85CBC0F9AA4622834325C08
Independent parent rehash:
  17,450 recorded input/artifact entries, 15 manifests, zero mismatches
Exact 102 repository-local qualification inputs:
  %TEMP%/fiber-qualified-repo-inputs-4cd4170a18d64871824d3c5b51d6a123
  ZIP SHA-256 F4979D999F23E9C6BCAE9EBDD45DFF9A67D3F2FFC95DBAD864DB3CD622E98D81
```

This qualifies one concrete C3FP runtime, not every pending FP/TrustZone/TF-M
combination, the complete current-tree matrix, all optimization modes, hosted
CI or a board. The exact input archive remains authoritative if later source
or documentation changes.

The six existing naked bodies (first-start bridge, first restore, private yield,
private task-return, SVC and PendSV) are text-identical to the archived staged
component snapshot. No frame/layout/storage identity changes in this slice.
`fiber_port_runtime_schedule()` is a naked tail branch to the existing private
yield veneer, so the admitted SVC-71 return site does not change.

`runtime_prepare_start()` retains reverse v1, exact cohorts and the unique
PendSV bundle, then validates the privileged environment, linker map, active
vectors, FPU and exception policy before common first selection. The first
selection uses `select_scheduler_candidate(NULL)` under PRIMASK with the same
CPU/MPU snapshot contract as the running scheduler bridge; it does not publish.
Common publishes the selected context before `runtime_start_first()` reaches
the existing private first-start bridge. The MPU remains disabled until SVC-70
installs the checked global/per-context image. Mandatory lifecycle/publication
ownership and the five/eight-operation boundaries do not change.

The direct barrier belongs to unprivileged executable flash, schedule/yield to
syscall flash, and privileged adapters/bridges to privileged flash. Runtime
placement checks include the actual common `fiber_current()`/`fiber_schedule()`
entry points. The complete-group gate must qualify archive extraction with weak
startup aliases, exact providers, GC/LTO, missing/stale objects, attributes and
actual common startup/scheduling before the selectable flag is promoted.

Pre-activation component evidence is preserved independently:

```text
Pinned-reference running parity: O2/Os x hard/softfp x 8/16 regions
  8 configurations, 264 compiled transfer mutants, 16 harness controls
  %TEMP%/fiber-c3fp-running-provenance-20261102l-O2/C3FP-RUNNING
  %TEMP%/fiber-c3fp-running-provenance-20261102m-Os/C3FP-RUNNING
O2 artifacts.json SHA-256:
  56C92F333BF5465B7A4861009BD1B2EFEC72274C0C94A10AFB51CDD7FCF8DC01
Os artifacts.json SHA-256:
  E95178571F8ECC5DAA1ACCC9FCA130217738BA8FF6AF0F545A2AB44CA1068D36
Parent rehash before activation: 1,489 inputs and 1,169 artifacts per receipt,
  zero mismatches; documentation artifacts are immutable output snapshots.
Running execution: 988 checks / 57 QEMU launches / 24 r16 compile-only ELFs
  %TEMP%/cm33f-mpu-running-execution-36a098061f3f4f2e974d8f717b680ac9
Parent independent artifact rehash: 2,083 files, zero mismatches.
Adapter strict compile smoke: 24 actual objects, O2/Os x hard/softfp x r8/r16
  %TEMP%/fiber-c3fp-runtime-adapter-compile-f263b2ca5aa944c785b227294b40b550
```

Those receipts qualify their recorded source hashes, not the later adapters.
The old execution input ledger has one later Markdown wording change; its
original bytes match the preserved 24-file component archive. No C/header drift
is inferred from that wording fix. Post-activation parity/execution replay and
the complete-group integration gate remain required. No board result is claimed.

The two public storage headers and every identity/layout/trait value are unchanged
by slice 2. The only dictionary-header edit updates its introductory stage comment
so it no longer says construction files are absent.

## Source And Hash Evidence

```text
FreeRTOS root:
  C:\Users\admin\Documents\my_workspace\stm32\experiments\_reference\FreeRTOS-Kernel
Commit: a50edad08b29052631aa469d4df6e6ec7ff68878
CMake port: GCC_ARM_CM33_NTZ_NONSECURE
Reference directory: portable/GCC/ARM_CM33_NTZ/non_secure
Comparison directory: portable/GCC/ARM_CM55_NTZ/non_secure
```

The local reference HEAD and ordinary worktree status were checked during this
audit; HEAD matched the pin and status was clean. SHA-256 values below were
computed from actual on-disk files, not copied from an older ledger. This is not
a replacement for the maintained full reference-pin guard.

| M33 NTZ reference file | SHA-256 | M55 NTZ comparison |
| --- | --- | --- |
| `port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` | Byte-identical. |
| `portasm.c` | `DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5` | Byte-identical. |
| `portasm.h` | `185477BF5A84B9B61927E4A0894427A4F471C448840DBF521F312B6F52D03B6C` | Byte-identical. |
| `portmacro.h` | `F0D3FE9D1ADAA0894EE3A03F14152ADD4B115DF8AF144B5912FEA3EDD23FBE0B` | Different: M55 hash `B7F94C8C21A4B583837C10F00ED93A1EA8C5801DEA8A3AD6C6DB13A49F947420`. |
| `portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` | Byte-identical. |
| `mpu_wrappers_v2_asm.c` | `00B42952962E48F8C9421F5EC66BBCE9E02465760560728FEE2D743CE1706F3E` | Byte-identical. |

Shared source bytes establish a useful transfer baseline, not equivalence of
different preprocessed manifests or permission to reuse another profile's proof.
M33 `portmacro.h` names Cortex-M33, Mainline, minor version zero, defaults MVE to
zero and rejects nonzero MVE. M55 instead names Cortex-M55, minor version one,
and requires explicit MVE configuration. M33's SMP validation flag does not
enable SMP here: the common header rejects MPU with multiple cores.

### Corrected Fiber Comparison Snapshot

The adaptation baseline is the corrected
[`ARM_CM55F_MPU/non_secure`](../../ARM_CM55F_MPU/non_secure/FREERTOS_PARITY.md)
implementation, including the post-MSR CONTROL correction. The table preserves
the original reference-audit worktree snapshot, before the later
`FAP-ARMV8M-RBAR-SH` correction. Its old shareability constant is not normative;
the difference below supersedes it. These hashes are not a claim that this M33
profile runs, nor a receipt for later sibling edits.

| File relative to the C55 comparison directory | SHA-256 |
| --- | --- |
| `fiber_port_types.h` | `37F3A7423F79628F6412701962B3157DEDF60D60722ADB7E6AEDF0E50B2055C8` |
| `fiber_portmacro.h` | `B33858C663A891D0AAC774EACB3C485CAD7A384A736D6214974A0E9CFEECCD32` |
| `fiber_port_boot_types.h` | `442C41B3EB9E641E55A380307742C6664CBC849D5E2AC4E189BD79121F36B996` |
| `fiber_port_boot.h` | `5618A68005C76DE05423FB969E9D9D6DADA6F6FD897AE5729BF3598FB71E7226` |
| `fiber_port_boot.c` | `881DCE6C9472BAC9A5BF58A6F5238B13CD0AB424F630734666AED4786A499466` |
| `fiber_port_private.h` | `B149E8135E81C29C3B4D4CD286C29BF4C96E8A1F030A8530E66F3E46135537B6` |
| `fiber_port_svc.c` | `65F21EC7E8367930073A78F3F92BC9A6E6EC05223445A3AE27B98CAFDB21997D` |
| `fiber_port_pendsv.c` | `9E4AA80B874FED2B0A00F5FC27DE4D661CEA2EEEDCBADFCD79F24448A20239E0` |
| `fiber_port_linker_contract.ld` | `BF6C271C12225869BB5529BE5DE35CE79C9525252BD71D30E0AF4B793AD4313C` |
| `FREERTOS_PARITY.md` | `3A4126B2809E608EBFB56EC5AD1132391323CF5FFF837DBF368EDBC25D10B589` |

The C55 comparison currently uses private layout generation 2:
`0x00020008` / `0x00020010`, public storage revision 2, port ID C55P and feature
mask `0x1C87`. Those values identify C55 only. The M33 header slice adopts the
corrected semantics under its own generation-1 identity; equal geometry never
makes a C55 object acceptable.

### Architectural Difference: FAP-ARMV8M-RBAR-SH

Pinned `portmacrocommon.h:203-205` defines Inner Shareable as `1 << 3`.
This is a confirmed reference defect, not behavior to preserve for parity.
[Arm Cortex-M33 DUG, Table 4-58, page 4-329](https://documentation-service.arm.com/static/5f16e93d20b7cf4bc524af1d#page=329)
defines Normal-memory RBAR.SH values 0 as non-shareable, 2 as outer shareable
and 3 as inner shareable; value 1 is UNPREDICTABLE. Device memory ignores SH.
Local `mpu_armv8.h:68-74` agrees with the architectural values.

The M33 dictionary deliberately uses `3u << 3u` for Inner Shareable and asserts
all three valid encodings. The slice-2 encoder rejects field value 1, accepts
0/2/3, and retains strict exclusive-end and attribute checks. The supported default
images are non-shareable (0), so the coordinated sibling correction does not
change those images, saved-image interpretation or layout. A latent private
encoding/validation correction is not a reason to revise the context or storage
ABI; no new public configurable-region capability is introduced here.

## Exact Intended Manifest

The reference configuration to compile independently is:

```text
configENABLE_MPU=1
configENABLE_FPU=1
configENABLE_MVE=0
configENABLE_TRUSTZONE=0
configRUN_FREERTOS_SECURE_ONLY=0
configENABLE_PAC=0
configENABLE_BTI=0
configNUMBER_OF_CORES=1
configTOTAL_MPU_REGIONS=8 or 16
```

The current assembly-comparison fixture uses `configUSE_MPU_WRAPPERS_V1=0`,
`configSYSTEM_CALL_STACK_SIZE=128`, and `configENABLE_ACCESS_CONTROL_LIST=0`.
Record these when building a comparator. Wrappers-v2 system-call storage is
outside the protected CPU image and will not become Fiber storage or an API.
Auditing that branch does not import FreeRTOS kernel system-call semantics.

Fiber dictionary compilation is explicit build selection with
`FIBER_PORT_ARMV8M_MAINLINE=1`, not the M55 `ARMV81M_MAINLINE` selection, and a
profile-owned `FIBER_PORT_CM33F_MPU_TOTAL_REGIONS=8` or `16` manifest. Both public
storage and the dictionary reject the existing foreign M33 scalar, M55 scalar,
M55 FP, M55 MVE/FP, M4 and generic MPU-region manifest macros, even if their
counts match. The dictionary also requires `FIBER_PORT_BUILD_SELECTED=1`.

Exact GCC FP target flags:

```text
-mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard
-mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=softfp
```

Do not copy the M55 `-march=armv8.1-m.main+fp` flag, enable MVE, silently accept
a double-precision target, or treat `-mfloat-abi=soft` as this FP cohort. Hard
and softfp change the C procedure-call ABI, not the exception image; both still
need independent generated-code and final-link proof.

This is a manifest contract, not proof of the literal `-mcpu` string. GCC 14
with `-mcpu=cortex-m55+nomve -mfpu=fpv5-sp-d16 -mfloat-abi=hard` can expose the
same `__ARM_ARCH_8M_MAIN__=1` and `__ARM_FP=4` as M33, without an exposed
`__ARM_ARCH_8_1M_MAIN__` marker. A forged CMSIS33 identity cannot distinguish that
compiler invocation. Do not invent a discriminator or claim every spoofed M55
flag set is rejected; qualification records the actual M33 flags independently.

### Strict CMSIS And Compiler Policy

Require real device/CMSIS facts and compiler agreement in the private dictionary:

```text
__CORTEX_M == 33
__MPU_PRESENT == 1
__VTOR_PRESENT == 1
__FPU_PRESENT == 1
__FPU_USED == 1
__NVIC_PRIO_BITS in 1..8
32-bit pointers/size_t; Thumb; ARMv8-M Mainline compiler target
scalar single-precision FP generation matching the recorded compiler flags
no MVE, Secure CMSE, PAC or BTI compiler feature manifest
```

Missing or contradictory facts must be rejected, not defaulted into support.
Do not predefine port-owned derived FPU facts or override CMSIS `__FPU_USED`
to conceal a target mismatch. A nonzero `__ARM_FP` alone is insufficient: the
dictionary requires exactly 4 and rejects soft-only `__SOFTFP__` code generation.
Record effective compiler flags and macros; the generic Mainline macro alone
does not identify M33.
Reject Secure compilation (`__ARM_FEATURE_CMSE >= 3`); value 1 is normal for
this Non-secure Security-Extension-capable compiler target and is not a reason
to reject it. Reject known PAC/BTI feature spellings even when an enabling
macro's numeric value is zero, as in the corrected sibling manifest policy.

Read-only preprocessor observations in this audit used STM32 GNU Arm GCC
14.3.1 (`14.3.rel1.20251027-0700`) and the local CMSIS core header:

| Flags | Observed compiler / CMSIS facts |
| --- | --- |
| Exact M33 flags, hard | `__ARM_ARCH_8M_MAIN__=1`, `__ARM_FP=4`, `__ARM_PCS_VFP=1`, `__ARM_FEATURE_CMSE=1`, CMSIS `__FPU_USED=1`. |
| Exact M33 flags, softfp | Same architecture/FP/CMSE facts, no `__ARM_PCS_VFP`, CMSIS `__FPU_USED=1`. |
| Same CPU/FPU flags, soft | No `__ARM_FP`, `__SOFTFP__=1`, CMSIS `__FPU_USED=0`; wrong cohort. |

CMSIS device facts were explicitly supplied before including `core_cm33.h`;
`__FPU_USED` was derived by CMSIS, not forced. This is preprocessing evidence
only, not a new runtime compile/test result. Supporting on-disk hashes:

```text
h7s_fiber_test/Drivers/CMSIS/Include/core_cm33.h
  225C47C36230EDAA314F1E7A45B38279F6AB4D58FAEB132226DB35F7007D58AA
h7s_fiber_test/Drivers/CMSIS/Include/cmsis_gcc.h
  43BFD1FE69FBBC2CA70AAF7D43CC3E20F16E0C7F66E1BDEF9B51AF6DC14B2617
```

Public type-only C/C++ storage must remain independent of CMSIS and CPU headers.
Synthetic negative fixtures may supply contradictory facts to test rejection;
they are not substitutes for a real selected device/core manifest.

## Protected Geometry Audit

`portmacrocommon.h:250-302` selects `MAX_CONTEXT_SIZE=54` for FP with no
SecureContext/PAC. `port.c:1533-1647` seeds a basic protected image, even though
the backing capacity can later hold an extended save. `portasm.c:289-412`
defines the later FP copy order. The exact reference image is:

| View | Word indexes | Byte offsets | Contents |
| --- | --- | --- | --- |
| Basic | 0..7 | 0..28 | r4-r11; r9 at byte 20. |
| Basic | 8..15 | 32..60 | Copied r0-r3, r12, LR, PC, xPSR; PC at 56. |
| Basic | 16..19 | 64..76 | PSP, PSPLIM, CONTROL, EXC_RETURN. |
| Basic | 20 | 80 | One-past active-save cursor target, not another saved register. |
| Extended | 0..15 | 0..60 | s16-s31. |
| Extended | 16..32 | 64..128 | Copied s0-s15 and FPSCR. |
| Extended | 33..40 | 132..160 | r4-r11. |
| Extended | 41..48 | 164..192 | Copied r0-r3, r12, LR, PC, xPSR. |
| Extended | 49..52 | 196..208 | PSP, PSPLIM, CONTROL, EXC_RETURN. |
| Extended | 53 | 212 | One-past active-save cursor target. |

These are overlapping views of one 54-word / 216-byte backing array, not two
independent images. The basic cursor is word 20; the extended cursor is word
53. A running context's cursor returns to the backing start after restore.
The initial constructor must clear the backing deterministically and initialize
only the basic view, without executing FP instructions.

The user PSP holds the architectural exception frame, not this privileged
backing array. Basic hardware state is 32 bytes; extended state is 104 bytes,
or 108 including the possible alignment word. The copied low-FP block is 17
words: the hardware reserved word is not copied into the protected image.
At raw exception PSP, the core frame comes first; low FP begins at PSP+32.
Do not add a 72-byte offset before reading the stacked PC/xPSR in runtime SVC.

Retaining the sibling's physical admission policy gives 112 aligned usable
PSP bytes after redzone/canary handling. Raw allocation boundaries still require
exact 32-byte MPU granularity. The generic sibling descriptors are different
quantities: 80-byte basic protected restore image, 132 additional privileged FP
bytes, 112-byte logical initial context, and 320-byte logical maximum. They must
not be mistaken for a 216- or 320-byte user-stack requirement.

The initial M33 type deliberately matches the audited C55 outer byte geometry,
with cursor/MAIR0/regions at offsets 0/4/8, four or twelve region pairs and the
following layout under its distinct identity:

| Regions | Protected image | Runtime flags | Boot metadata | Context size |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 40 | 256 | 260 | 352 |
| 16 | 104 | 320 | 324 | 416 |

The dictionary asserts the entire overlapping backing, every basic/extended
register field, boot-record offsets, outer offsets, sizes, alignment, cursors
and region count. It binds M33's own exact identities; this freezes storage
for this staged slice, not a claim of constructor/handler correctness.

## Function And Macro Disposition

Types, construction, integrity checks, map encoding and private FPU-policy
helpers are implemented as described above. Runtime transfers below remain
planned; their reference audit does not imply that a M33 handler exists.

### A32 CPU Primitive Additions

These local additions replace CMSIS function calls, not CMSIS register/fact
definitions. Every primitive uses the canonical inline-sensitive and
general-registers-only bundle so hostile compiler flags cannot introduce hooks
through an unannotated inline callee.

| Added primitive | Replaced operation / disposition |
| --- | --- |
| `fiber_port_cpu_read_ipsr` | Raw IPSR read for Thread/Handler admission. |
| `fiber_port_cpu_read_control` | Raw CONTROL read; existing role-specific checks remain. |
| `fiber_port_cpu_read_primask` | Raw PRIMASK read; no mask modification. |
| `fiber_port_cpu_read_faultmask` | Raw FAULTMASK read; no mask modification. |
| `fiber_port_cpu_read_psp` | Raw live PSP read; bounds validation remains separate. |
| `fiber_port_cpu_read_psplim` | Raw PSPLIM read; existing bank policy remains. |
| `fiber_port_cpu_wait` | Raw WFE in the nonreturning panic wait. |
| `fiber_port_cpu_priority_index` | Validates system/external IRQ index before byte access. |
| `fiber_port_cpu_get_priority` | Reads the appropriate SHPR/IPR byte and shifts implemented bits. |
| `fiber_port_cpu_set_priority` | Writes the same SHPR/IPR encoding as the replaced CMSIS operation. |

### Reference Disposition

| Pinned reference location / symbol | Audited behavior | Implemented / planned disposition |
| --- | --- | --- |
| `portmacro.h:49-66` architecture/MVE facts | M33, Mainline, minor 0; MVE prohibited. | Implemented in the M33 dictionary with real core/compiler agreement, exact SP FP and no MVE/PAC/BTI/Secure compilation. |
| `portmacrocommon.h:109-111` stack facts | Downward stack, eight-byte alignment. | Retain the processor geometry. |
| `portmacrocommon.h:173-218` regions/attributes | Global RNR0-3; stack RNR4; configurable RNR5 onward; RBAR AP/XN and memory attributes. | Implemented with `FAP-ARMV8M-RBAR-SH`; constructor fixes RNR5 to the RO/XN current slot and disables RNR6 onward. |
| `portmacrocommon.h:235-385` `xMPU_SETTINGS` | MAIR0, region pairs, 54-word image, flags; wrappers-v2 system-call stack and optional ACL are additional kernel storage. | Map processor fields to private context storage; do not copy system-call stack/ACL into the Context contract. |
| `port.c:1533` `pxPortInitialiseStack()` MPU branch | Writes r4-r11, copied core frame, PSP, PSPLIM, CONTROL and basic EXC_RETURN; returns one-past active words. | Implemented `fiber_port_context_init()` in boot ownership; zero scratch values, preserve live r9, seal metadata and reference the exact private return veneer. No FP transfer or hardware-frame write onto user PSP during construction. |
| Same constructor, `xRunPrivileged` | Reference can seed CONTROL 2 or 3 and task privilege flags. | Base Fiber profile constructs unprivileged Thread CONTROL 3 and zero runtime flags. No new public privilege-switch API. |
| `port.c:1015` `prvSetupFPU()` | CP10/CP11 full access; ASPEN and LSPEN set. | Implemented private `fiber_port_fpu_prepare()`, `require_configured()` and `require_ready()`; readback/barriers and explicit lazy/eager policy. Constructor does not call them or enable the FPU. |
| `port.c:928` `prvSetupMPU()` | MAIR0 attributes, global RNR0-3, MemManage enable and `ENABLE|PRIVDEFENA`. | Exact disjoint linker-image builder implemented in slice 2; hardware programming, MemManage enable and complete readback are implemented by slice-3 first SVC. PRIVDEFENA is already reference policy, not a Fiber invention. |
| `port.c:1889` `vPortStoreTaskMPUSettings()` | Encodes MAIR0, task stack and optional regions; avoids overlapping a privileged-SRAM stack region; invalidates unused pairs. | Implemented strict exclusive-end encoder and fixed unprivileged raw-stack/current-slot pairs; misalignment/overflow is rejected rather than rounded. Unlike C55, RLAR.PXN is rejected. Heterogeneous region API remains deferred. |
| `port.c:2166` priority setup, `portasm.c:255/272` mask helpers | Probe priority bits; validate BASEPRI/PRIGROUP; SVCall highest, PendSV lowest; save/restore BASEPRI with barriers. | Retain selected-port policy and strict readback. Preserve incoming PRIMASK during priority probing. Do not import SysTick ownership. |
| `port.c:1749` `xPortStartScheduler()` | Checks vector slots 11/14, sets priorities/MPU, starts timer/kernel state, enters first task. | Split processor preparation into existing forward operations; retain direct-vector proof and discard timer/ready-list/critical-nesting ownership. |
| `portasm.c:234` `vStartFirstTask()` | VTOR->MSP, enable IRQ/fault handling, SVC start. | Implemented strict rewind-only helper and exact owned SVC #70 site; clear stale PendSV and require clear FPCA/masks rather than accepting dirty startup CONTROL. |
| `portasm.c:49` protected first restore | MPU disable, MAIR0, RNR4 and optional RNR8/12 alias blocks, MPU enable; PSP/PSPLIM/CONTROL/EXC_RETURN, core copy, r4-r11, cursor rewind, BASEPRI clear, return. | Implemented that transfer backbone with strict readbacks. Only a basic initial image is accepted; no VFP transfer occurs in first restore. |
| `portasm.c:289` protected PendSV | Conditional high/low FP copies, integer/core copies, special state, scheduler, MPU replacement, inverse restore. | Separate staged PendSV source with preflight before mutable cursor access, frozen reverse ABI, protected current publication and full readback. Independent qualification required. |
| `portasm.c:522` `SVC_Handler`, `port.c:1108` C dispatch | Select raw MSP/PSP; decode stacked PC at core word 6; route wrapper/start/yield services. | Exact B8/MSP first-start provenance retained; BC/AC PSP admission and owned SVC71/72 sites added. Only71 returns from C dispatch. |
| `portmacrocommon.h:405-415`, `port.c:1040` yield | Reference SVC102 starts, SVC105 yields and privileged code pends PendSV. | Deliberate Fiber 70/71/72 namespace adaptation; public yield remains unprivileged and only requests PendSV. |
| `portasm.c:187/204/219` privilege helpers | Read/clear/set nPRIV. | Use only the necessary private validation/restore semantics; no general-purpose privilege elevation surface. |
| `port.c:1236/1382/1392`, `mpu_wrappers_v2_asm.c` | Kernel API entry/exit, separate system-call stack, FP materialization and temporary privilege elevation; wrappers dispatch kernel APIs by SVC. | Audited and removed from the proposed library backend, not stubbed. Fiber's narrow owned services do not execute those APIs or require that system-call stack. |
| `port.c:906/2026/2252+` access permissions/buffer authorization/ACL | FreeRTOS kernel-object and syscall permissions. | Removed with kernel API ownership; retain strict MPU encoding and frame-address validation, not kernel-object access APIs. |
| SecureContext, TF-M, PAC/BTI branches | Conditional handle, companion calls, keys, CONTROL policy or provider integration. | Not part of this exact no-companion/no-PAC manifest; separate roadmap cohorts, not silently excluded from the overall roadmap. |
| Tick/tickless, task deletion, queues, ready-priority macros, SMP locks | Kernel and scheduling policy. | Removed from this backend. Selected single-core dispatch remains user-scheduler-owned. |

### Constructor And Integrity Adaptation

The M33 reference writes integer words 0..7, copied core words 8..15, PSP/PSPLIM
at 16/17, CONTROL at 18 and EXC_RETURN at 19, then returns the cursor at 20.
The implementation preserves that order and the 54-word backing capacity. It
deliberately clears the full backing, replaces reference debug markers with zero
seeds while preserving live r9, fixes unprivileged CONTROL=3 and seeds basic
`0xFFFFFFBC`. The initial raw PSP is `stack_top - 32`; low FP state is not seeded
and no extended frame is manufactured. No SecureContext slot, PAC key, VPR or
wrappers-v2 syscall stack is copied into the context.

The general integrity path first proves the context lies wholly inside the
privileged RW range, then validates immutable metadata and exact expected
MAIR0/MPU pairs. The seal covers boot metadata, MAIR0 and all region pairs;
it excludes the mutable protected union, cursor and runtime flags. Only the
first-start validator reads the basic union, after proving its active cursor
is word 20. Later runtime validation must not call this initial-only validator
or reinterpret extended words as basic PSP/PSPLIM/CONTROL fields.

All default images use SH=0 and MAIR0 Normal attribute 0 (`0xFF`), with Device
attribute 1 (`0x04`) available only to the private exact encoder. Global RNR0/1/2
map privileged flash RO, unprivileged flash RO and syscall flash RO; RNR3 maps
privileged RW/XN SRAM. Per-context RNR4 maps only the raw unprivileged stack
RW/XN; RNR5 maps the separate current slot RO/XN for both privilege levels.
RNR6 onward is disabled. The linker and C checks require a disjoint, exactly
32-byte slot immediately below privileged RW SRAM. Startup must zero that slot
separately from privileged BSS. No actual STM32 memory address is selected here.

The no-PXN RLAR validator follows existing scalar M33 MPU policy: callers pass
only AttrIndx 0 or 1, and the encoder adds EN after all checks. It rejects bit 4,
caller-supplied EN, other attribute indexes, invalid SH, alignment/extent errors
and out-of-range region numbers without changing the output pair. Physical
admission remains 112 usable aligned PSP bytes after redzone/canary handling,
not the size of privileged protected storage or the 320-byte logical descriptor.

Private FPU helpers access only the current Non-secure CPACR/FPCCR bank. They
preserve unrelated bits, use barriers/readback, enforce ASPEN and the selected
LSPEN policy, and keep configured-policy checks distinct from first-start
LSPACT=0 readiness. Secure startup must already permit Non-secure FP access;
these helpers do not change SAU/ITNS/NSACR or create a Secure companion.

### Staged Fixture Contract

The private construction API in `fiber_port_boot.h` defines:

```text
fiber_port_context_init(ctx, stack_begin, stack_end, entry, arg)
fiber_port_context_compute_seal(ctx)
fiber_port_context_seal_check(ctx)
fiber_port_context_validate_initial_restore(ctx)
fiber_port_mpu_load_linker_layout(layout)
fiber_port_mpu_linker_layout_check(layout)
fiber_port_mpu_try_encode_exact_region(start, end, region, rbar_attrs, rlar_attrs, out)
fiber_port_mpu_build_global_regions(image)
fiber_port_fpu_prepare()
fiber_port_fpu_require_configured()
fiber_port_fpu_require_ready()
```

A linked staged fixture must supply all twelve `__fiber_mpu_*_start__/end__`
symbols for privileged flash, unprivileged flash, unprivileged syscalls,
privileged SRAM, the current-context slot and unprivileged RAM. The board/fixture
linker places `.fiber_port_privileged_code`, `.fiber_port_unprivileged_code`,
`.fiber_port_syscalls`, `.fiber_port_privileged_data` and the exact 32-byte
`.fiber_current_context_slot` section; the leaf fragment checks, not places, them.

Remaining object dependencies are `fiber_panic`,
`fiber_port_unprivileged_task_return` and the exact
`FIBER_PORT_CONTEXT_COHORT_SYMBOL`. Fixtures must provide no-return panic code in
privileged flash and a no-return task-return symbol in syscall flash with the
declared sensitive/general-register attributes. A fixture-only
`FIBER_PORT_CONTEXT_COHORT_DEFINE()` built from the same selected dictionary
supplies the exact cohort and storage provider. Do not weaken or remove the
boot relocation to make a staged link convenient, and do not ship these test
providers as production handlers. No scheduler/forward-runtime dependency is
introduced. Tesla owns the maintained constructor fixtures/runner separately.

### Protected FP Transfer Trace

The relevant instruction-level audit of the pinned MPU branch is:

```text
SAVE, EXC_RETURN.bit4 == 0:
  r2 = raw PSP + 32
  vstmia protected_cursor!, {s16-s31}
  vldmia r2, {s0-s16}       ; temporary registers carry s0-s15/FPSCR words
  vstmia protected_cursor!, {s0-s16}
  r2 -= 32
SAVE, either form:
  stmia protected_cursor!, {r4-r11}
  ldmia raw_PSP, {r4-r11}; stmia protected_cursor!, {r4-r11}
  mrs PSPLIM; mrs CONTROL
  stmia protected_cursor!, {PSP, PSPLIM, CONTROL, EXC_RETURN}
  store active one-past cursor

SELECT / MPU:
  BASEPRI threshold; DSB/ISB; scheduler bridge
  disable MPU; MAIR0; RNR4 and optional RNR8/12 alias blocks; enable MPU

RESTORE, either form:
  ldmdb saved_cursor!, {PSP, PSPLIM, CONTROL, EXC_RETURN}
  msr PSP; msr PSPLIM; msr CONTROL
  ldmdb saved_cursor!, {r4-r11}; stmia PSP!, {r4-r11}
  ldmdb saved_cursor!, {r4-r11}
RESTORE, EXC_RETURN.bit4 == 0:
  vldmdb saved_cursor!, {s0-s16}; vstmia advancing_PSP!, {s0-s16}
  vldmdb saved_cursor!, {s16-s31}
  store backing-start cursor; exception return
```

Here the final temporary s16 value represents the copied FPSCR word; the
original s16-s31 were already preserved and are restored last. Do not replace
this with a second FPSCR slot, add a VPR slot, or move the low-FP block ahead of
the core hardware frame. The basic branch omits all three conditional FP
instructions on each side and uses the same integer/special-state ordering.

Fiber's BASEPRI/PRIMASK envelope deliberately differs from the bare reference:
keep the scheduler threshold through MPU replacement, assert PRIMASK before
disabling the MPU, publish current only while disabled, then enable/read back
the selected image and restore masks in the established order. Record these
hardening differences in generated-code comparisons rather than calling the
entire handler byte-identical.

## M33 Banking And ISA Adaptation

Both selected roles execute in Non-secure state. Ordinary `MRS/MSR PSP`,
`PSPLIM`, `CONTROL`, `BASEPRI` and ordinary SCS addresses refer to the current
Non-secure bank. `FIBER_PORT_TARGETS_NS_BANK=0` in the siblings means no explicit
alternate-bank instructions, not Secure execution. Do not replace these with
Secure code accessing `PSP_NS` or the Secure view's alternate NS SCS aliases.

The hardware Security Extension remains present even though reference
`configENABLE_TRUSTZONE=0` disables the fiber-owned companion mechanism. Secure
startup/attribution must allow Non-secure FP access and provide the matching
NS vector/memory environment. This port does not configure SAU/ITNS/NSACR,
Secure priorities or a Secure vector table, and it does not manufacture a
SecureContext handle slot. PSPLIM is real Mainline state, not the ignored M23
Non-secure slot.

M33 is Armv8.0-M Mainline: minor version zero and no C55 `RLAR.PXN` capability.
The implemented exact encoder rejects bit 4 in RLAR attributes instead of
copying the C55 allowed-mask expression.
Keep RBAR.XN and normal AP/shareability encodings. No MVE/VPR, PAC instructions,
BTI policy, M7 errata workaround, or v8.1-only instruction may leak from the
comparison into the M33 scalar-FP build.

### Corrected Semantics For The Initial M33 Identity

- Exception entry clears SPSEL in the targeted bank; entry checks may expect
  CONTROL low bits 0 at privileged startup or 1 after unprivileged Thread
  interruption, before an intervening CONTROL write. This is not permanent RAZ.
- Privileged Armv8-M Handler `MSR CONTROL` can set SPSEL. Synthetic first restore
  writes 3 and must read back 3. Runtime protected FP saves actual Handler
  CONTROL, accepts only nPRIV=1 with defined SPSEL/FPCA bits, and compares the
  written value with the full supported mask 7 after restore.
- A24 separately corrects seven privileged Armv8-M first-SVC paths: those write
  2 and must read back 2, not 0. Do not import their obsolete post-write check
  into this unprivileged MPU profile or change valid entry checks to 2/3.
  Earlier matrix receipts do not qualify that correction; use the parent's
  newly qualified checkpoint before starting the implementation slice.
- EXC_RETURN, not live Handler FPCA/SPSEL, identifies interrupted Thread/PSP
  basic `0xFFFFFFBC` or extended `0xFFFFFFAC` state. Initial SVC origin is the
  exact Non-secure Thread/MSP/basic token `0xFFFFFFB8`.
- First-start readiness rejects LSPACT. Runtime configured-policy checks allow
  valid lazy preservation before the first FP transfer materializes it.
- Runtime SVC reads the core frame at raw PSP, uses the active cursor/live
  PSPLIM, and must not read poisoned inactive basic-union special fields.
- Prove the minimum core extent before reading xPSR, then prove the complete
  frame/padding extent. Validate live PSP bounds rather than equality with a
  historical protected PSP. Restore permits the exact owned yield continuation,
  not arbitrary syscall-section PCs.
- The current slot is a separate 32-byte RO/XN aperture, read-only for both
  privilege levels, disjoint from privileged RW and all other enabled regions.
  The comparison places it immediately below privileged SRAM. Startup zeros
  that section separately; publication occurs only in the masked MPU-disabled
  window. No Armv7-style overlapping higher-priority overlay is permitted.
- Preserve source-sensitive/general-register attributes and mandatory build
  counterflags. Public allocating facades retain storage expectations via the
  established cohort mechanism; direct type-only allocators require the explicit
  expectation header. Linker KEEP must preserve all contributions under GC/LTO.

These are existing architectural corrections to preserve, not evidence that
the planned M33 implementation has passed them.

## Required Proof And Implementation Gates

Types/dictionary, construction/map/integrity, private FPU helpers, first-start
and private running SVC/PendSV sources are now implemented. Independent maintained
qualification is separate from the object-build evidence below; the remaining
runtime gates stay open. Existing
sibling PASS labels do not satisfy these gates. No test runner or central
matrix branch is added by this implementation slice.

1. **Type/manifest slice:** unique port/layout/storage identities are implemented;
   reject C55, scalar-M33, no-MPU, Secure, MVE and PAC/BTI substitutions. Compile public
   storage as C/C++ without CMSIS. Assert every basic/extended offset, cursor,
   54-word backing, region pair, outer size/alignment and 8/16 distinction.
2. **Compiler/CMSIS negatives:** missing/wrong core, MPU, VTOR, FPU presence/use,
   priority bits, soft ABI, unsupported FP precision, Secure CMSE, MVE/PAC/BTI,
   invalid/foreign region manifests and overridden derived traits. Retain the
   actual compiler flags/macros and real CMSIS inclusion evidence.
3. **Construction/MPU slice:** exact basic seeds and r9 preservation, deterministic
   unused backing, no FP instructions in the complete pre-FPU call graph;
   112-byte usable PSP policy plus raw redzone/canary checks. Reject wraparound,
   invalid/overlapping/alignment ranges, foreign context/entry placement, PXN,
   malformed attributes (including reserved RBAR.SH=1) and missing linker
   symbols before unsafe accesses. Accept architectural Normal-memory SH=0/2/3.
4. **FPU policy slice:** CP10/CP11, ASPEN and both lazy/eager LSPEN policies with
   readback; inactive first start versus valid runtime LSPACT. No hidden FP,
   instrumentation or unconstrained library call in sensitive helpers.
5. **First-start SVC slice (implemented; execution qualification pending):** preserve the reference basic MPU restore for both
   region counts; exact vector/opcode/call-site/frame provenance; write-3/read-3
   Handler CONTROL behavior; raw MSP/PSP bounds and hardware-frame copy order.
   Reject the obsolete post-write comparison with 0; distinguish the privileged
   sibling write-2/read-2 case. First restore must not execute FP transfers.
6. **Running-transfer slice (source present; qualification pending):** basic/extended saves and inverse restores, both cursor
   forms, copied FPSCR and s16-s31, malformed cursor/EXC_RETURN/CONTROL negatives,
   lazy state, minimum-frame-before-xPSR checks and inactive-union poisoning.
   Test exact yield continuation, private return service, wrong SVC sites,
   stack-depth changes, MPU readback and scheduler CPU/MPU preservation.
7. **Link/ABI slice:** exactly eight forward operations; frozen reverse ABI;
   strong slots 11/14; separate handler archive extraction; privileged,
   unprivileged and syscall placement; GC/LTO retention; public consumer and
   private component stale-cohort negatives across 8/16, core and FP roles.
   No kernel wrapper, SecureContext/TF-M, or new common API dependency.
8. **Generated-code grid:** independently build the actual pinned M33 reference
   and new Fiber profile for hard/softfp, 8/16, lazy/eager where applicable,
   first at O2/Os and then the required O0/Og/O2/Os/O3 and final O2-LTO/Os-LTO
   freeze grid. Audit ordered instructions and final ELF dependencies, not
   merely source token presence or comparison with M55 assembly.
9. **Execution evidence:** scoped M33 emulator cases must exercise actual
   instructions and production paths where claimed, especially entry versus
   post-write CONTROL and FP/lazy/protected transitions. Matching board FP
   isolation, vector, priority and stress evidence stays separate; defer it
   explicitly when unavailable and never label emulator results hardware proof.

### Focused Header Evidence

During the earlier header-only slice, after the shareability correction,
standalone stdin-only checks with STM32
GNU Arm GCC/G++ 14.3.1 passed:

- Eight real `core_cm33.h` dictionary syntax checks: C11/C++17, 8/16 regions,
  hard/softfp, using the exact M33/SP flags above and warnings as errors.
- Four public type-only syntax checks: C11/C++17 and 8/16 regions, without
  CMSIS or build-selection facts, using soft ABI to prove that public storage
  does not depend on private FP compilation policy.
- Fifty-two intended-diagnostic negative checks for missing/contradictory core,
  MPU/VTOR/FPU/priority/architecture/Thumb facts, unsupported FP values, Secure,
  MVE/PAC/BTI, derived-fact/runtime overrides, BASEPRI and own/foreign manifests.
  All six foreign region-manifest cases also reject direct public type inclusion.
- Two real compiler-policy negatives: soft ABI derives `__FPU_USED=0` and is
  rejected; `-mfpu=fpv5-d16` derives a non-SP-only FP mask and is rejected.

The real-CMSIS harness supplied a minimal IRQ enum and device facts, with CMSIS
deriving `__FPU_USED`; it bypassed this checkout's unrelated H7 `mcu_core.h`
umbrella. Deliberately inconsistent facts were injected only for negative
checks. These were `-fsyntax-only` probes, not retained test fixtures or evidence
of executed MPU/exception semantics. No object, executable, runtime source,
central-matrix edit or runtime selection route was created. Independent
maintained fixture and parent integration results must be recorded separately.

### Focused Constructor Object Evidence

Slice 2 compiled the actual `fiber_port_boot.c` with STM32 GNU Arm GCC 14.3.1,
the real local `core_cm33.h` through the maintained manifest device fixture, and
the exact M33 scalar-SP compiler flags above. All 16 combinations of O2/Os,
hard/softfp, 8/16 regions and lazy/eager passed with warnings as errors and the
sensitive-build counterflags. Disassembly scans found no FP instructions in the
boot objects. Undefined-symbol inspection found only the twelve linker
boundaries, panic, task-return continuation and exact cohort described above;
there was no unexpected library or scheduler dependency.

Artifacts from this bounded check are retained at:

```text
%TEMP%/fiber-c3fp-boot-owner-e29f833a5a8d4ca9981bda43d20c391c
```

Leaf source hashes at the slice-2 handoff:

| File | SHA-256 |
| --- | --- |
| `fiber_port_boot.c` | `F7633CAB81446B33AB30756FC71C313167E240887A275BC95F90099817A2EBEA` |
| `fiber_port_boot.h` | `3528063594457985B105AB3A54BBEBA7708197FF546D713C740D676CC6451127` |
| `fiber_port_linker_contract.ld` | `8010DBA94E856CB4C98FB46FCCEA0470FF3DA854099E602ABF56A396F623975F` |

These object checks are not linked-image, host-behavior, emulator, hardware,
whole-call-graph or exhaustive optimization evidence. The constructor and linker
fixtures/runner are owned independently by Tesla; their outcomes and the parent's
combined qualification must be recorded separately. No full matrix was run by
this implementation worker.

### Maintained Constructor Qualification

The independent maintained runner passed eight configurations: O2/Os,
hard/softfp and 8/16 regions. It executed 4176 ARM calls, including 1216 expected
panic paths, and 32 calls of the unmodified pinned FreeRTOS constructor. It
checks numeric initial backing, exact maps/seals/bounds, C++ linkage and 34
linker negatives. The isolated reference constructor's bytes and relocations
are compared with its actual full-source object before execution.

Strict hostile-flags checks initially found instrumentation leaking through
forced-inline helpers. Canonical inline-sensitive annotations on the shared
geometry helpers and this profile's r9 reader close that observed gap without
weakening the proof. Explicit Python optimization guards and ten maintained
guard negatives prevent assertion removal from producing false qualification.

```text
Focused receipt:
  %TEMP%/fiber-cm33f-mpu-constructor-qualification/
  cm33f-mpu-constructor-77e392f364f842409fd48595630d0882
```

This is constructor/linker and generated-code evidence, not MPU enforcement,
FP exception execution, hardware or complete runtime qualification. The parent
combined matrix remains a separate receipt. The first-start SVC slice consumes
these boot helpers; the constructor receipt does not qualify that handler. No
CPU extraction is included here.

The later A27/A28 follow-up protects all seven local inline helpers and the
shared EXC_RETURN predicate. Its dedicated five-profile helper runner tests
ordinary and general-register-only C/C++ callers, compiled annotation-removal
mutants and numeric predicate behavior. It is separate from constructor proof.
The final constructor parent replay at
`%TEMP%/fiber-c3fp-final-guards-parent/cm33f-mpu-constructor-84c163ac489846668dd0556202b4c36f`
passes the same 4176 ARM calls / 1216 expected panics / 34 linker negatives,
with 32 Python guard controls. Those include optimized compiled imports in an
ordinary interpreter and traceback counterfeits; assertions cannot silently
disappear. Input hashes remain stable. The earlier ten-control receipt above
is historical, not the final test-harness hardening claim.

### Slice 3: First-start/SVC #70 Only

This subsection and its local receipts describe the historical first-start-only
slice before the running-transfer addition below. Its old five-function export
count, rejected running origins and fixture-owned return/PendSV symbols are not
the current integration contract.

The new private header exposes exactly `fiber_port_prepare_first_start`,
`fiber_port_svc_dispatch`, `fiber_port_start_first_context`,
`fiber_port_restore_first_context_from_svc`, `SVC_Handler`, and the data-label
declaration `fiber_port_svc_start_return_site`. All C and naked bridges carry the
canonical sensitive/general-register contract. Local helpers remain private.
The source retains the existing exact-cohort expectation but defines no cohort
provider or bundle anchor. It does not implement any additional operation of the
frozen forward/reverse ABI.

This component **requires `FIBER_REWIND_MSP=1`**. The selected dictionary rejects
zero; this is an explicit unsupported policy, not a preserve-MSP implementation.
The SVC frame must end exactly at the active vector's initial MSP. Preparation
requires privileged Thread/MSP, CONTROL 0, clear PRIMASK/BASEPRI/FAULTMASK,
disabled MPU and the selected hardware region count. It reuses the boot seal,
initial protected-image, linker-layout and FPU-policy validators. It prepares
CP10/CP11 and ASPEN/LSPEN without executing FP instructions, probes/restores one
NVIC priority byte under preserved PRIMASK, validates BASEPRI/PRIGROUP, sets
SVCall highest and PendSV lowest, sets STKALIGN and clears inherited pending
PendSV. There is no PendSV handler or scheduler in this slice.

Before vector-slot reads, the full 2048-byte span beginning at aligned VTOR must
lie in linker-owned privileged read-only flash. This conservatively covers the
nine-bit architectural exception-number space, even for a device implementing
fewer external interrupts. SVC slot 11 must name this strong handler; initial MSP
must be aligned and lie inside privileged SRAM with room for the basic frame.
VTOR/initial-MSP sampling is repeated. The final naked start repeats CPU/mask,
vector and MSP checks while masked, rewinds MSP, clears pending PendSV, and
executes the owned SVC #70 instruction. Peripheral vector contents, external IRQ
enablement and a sufficiently deep disjoint MSP stack remain integration-owned.

The handler accepts only actual IPSR 11 and exact basic Thread/MSP Non-secure
origin `0xFFFFFFB8` before loading the assembly-visible current pointer. The C
dispatcher repeats origin, CONTROL, mask, FPU, MPU and layout checks. It proves
the complete aligned 32-byte MSP frame range before reading PC/xPSR, requires
Thread Thumb/no-padding frame shape, the exact return label, and instruction
bytes `46 DF`. Running PSP origins, extended frames, SVC #71/#72, arbitrary
privileged SVC sites and malformed frames fail closed before MPU installation.

With PRIMASK asserted, the dispatcher builds/programs/reads back global RNR0-3
and enables MemManage faults while MPU_CTRL remains zero. The naked first
restore follows actual pinned `ARM_CM33_NTZ/non_secure/portasm.c:49-142`:
disable MPU with barriers, write MAIR0, use RNR4 and optional RNR8/12 alias blocks,
enable MPU with PRIVDEFENA, and read back the complete global/per-context image.
Then it restores PSP, PSPLIM and CONTROL from the validated basic image with
readbacks, specifically **write 3 / read 3** for live Handler CONTROL, copies the
eight core-frame words onto raw PSP, restores r4-r11, resets the protected cursor
to word zero, clears/readbacks BASEPRI, unmasks PRIMASK and returns through
`0xFFFFFFBC`. No VFP/MVE instruction or extended-image transfer is present.

The staged execution fixture must supply the already-required exact constructor
cohort provider, privileged panic, syscall-section no-return continuation, and
the actual four-byte `fiber_internal_runtime_current_context_slot` at the start
of the existing 32-byte aperture. It publishes the first pointer before calling
the start bridge. This slice does not select or publish it. A fixture must own
its reset/vector/bootstrap, startup zeroing, Secure attribution/NS FP access and
fail-stop PendSV slot; it must not link a runtime provider or duplicate the owned
SVC/start symbols. The syscall-section return continuation is still fixture-only:
a returning task is not supported until the later running-service slice.

Local GCC 14.3.1 build/code-generation evidence is retained at:

```text
C:\Users\admin\AppData\Local\Temp\fiber-c3fp-svc70-752d6a1b084542b2be1b4aca5c8178eb
```

- O2/Os x hard/softfp x 8/16 regions x eager/lazy: 16 SVC objects and 16
  staged ELF links using only the existing constructor fixture's providers.
- O2-LTO/Os-LTO x hard/softfp x 8/16 regions: eight additional staged ELF links
  with eager policy; all 24 linked ELFs have zero undefined symbols.
- Four C++17 private-header checks cover hard/softfp x 8/16 regions.
- Sixteen bidirectional 8/16 SVC-only mixed-object links fail with the exact
  unresolved selected-cohort diagnostic across hard/softfp, O2/Os and non-LTO/LTO.
  The SVC retain is an expectation, not a production provider definition.
- Eight actual, unmodified pinned M33 `portasm.c` objects cover O2/Os x
  hard/softfp x 8/16. Ordered first-restore comparisons pass for all 16 local
  variants, including exact alias-block counts, special/core/integer transfer
  order, cursor reset and BASEPRI clear. Reference and implementation first
  restores contain no FP transfers. The implementation additionally verifies
  live Handler CONTROL write-3/read-3 and exposes no SVC71/72 instruction.
- The SVC object exports exactly the five declared functions plus the start
  return-site label. Non-LTO SVC disassembly has no FP instructions,
  instrumentation, sanitizer, stack-protector or memory-library dependencies.

These are local build/code-generation checks, not maintained execution results
or a complete parity gate. Parent-owned actual-M33 execution, negative
provenance/readback controls, maintained generated-reference comparisons and
integration qualification remain required before runtime-selectable promotion.

### Slice 4: Private Running Services And Protected PendSV

The four-file source addition leaves `FIBER_PORT_RUNTIME_SELECTABLE=0`, the
constructor, identities, storage geometry and public/generic API unchanged.
It defines no generic forward adapter, production cohort provider, first-context
selector, runtime bundle anchor or selection route. It is not a
complete runtime. The private header alone imports the existing reverse-call
ABI; no public header gains common runtime dependencies.

The SVC object now defines seven functions: the existing five first-start/SVC
functions, `fiber_port_yield_from_thread` and the boot-declared
`fiber_port_unprivileged_task_return`. It defines the start, yield and return
`fiber_port_svc_*_return_site` labels. The naked handler accepts only IPSR11 and
exact B8/MSP or BC/AC/PSP tokens before obtaining the raw frame. Its current-slot
load remains naked assembly only. The dispatcher is deliberately not noreturn:
owned #71 masks briefly, pends/readbacks PendSV, restores PRIMASK and returns;
owned #72 invokes the terminal frozen reverse call. Running #70 rejects.
Running-frame validation uses the sealed boot bounds, live PSP/PSPLIM, cursor
word zero and permanent word-53 guard, not stale inactive basic fields. It
proves 32 bytes before reading xPSR and then the complete 32/104-byte frame plus
optional alignment padding. Opcode reads require an immutable privileged or
syscall extent; #71/#72 require their exact owned continuation. First-start
admission additionally requires the real strong PendSV vector in slot14, after
the unchanged complete vector-span proof. The #70 start and first-restore
assembly and strict `FIBER_REWIND_MSP=1` semantics are retained.

The PendSV object defines these six transfer functions and one cold private
component guard:

- `fiber_port_context_validate_restore`
- `fiber_port_pendsv_validate_save_current`
- `fiber_port_scheduler_pick_next_from_pendsv`
- `fiber_port_mpu_switch_to_context`
- `fiber_port_mpu_validate_active_context`
- `PendSV_Handler`
- `fiber_port_arm_cm33f_mpu_pendsv_handler_component_v1_anchor`

Cold `fiber_port_prepare_first_start` directly retains reverse ABI v1 for its
own SVC object, then calls this actual PendSV component guard. The guard retains
reverse v1 and the exact context cohort in the PendSV object independently of
the constructor. Its privileged placement is checked alongside the bridges.
Both reads share their object's explicit privileged function section with the
actual handler, so handler-root-only links must retain the corresponding v1
dependency even when the cold first-start entry is not a fixture root. There is
no reverse-v1 read in the running SVC dispatcher, save/selection/MPU bridges or
naked PendSV path. This is staged private component coverage, not a full-runtime
provider/bundle or a change to the frozen reverse ABI.

Its only direct current-slot access is the naked assembly load. Before reading
the mutable cursor or writing the image, the handler calls the save preflight
with `(current, raw_PSP, EXC_RETURN)` on an aligned MSP call frame. C validates
the trusted metadata/seal, running cursor, permanent guard, frame/PC/canary,
live CONTROL/PSPLIM/masks/FPU policy and complete active MPU image. Permitted
saved/pre-save PCs are application flash or the exact owned yield continuation,
never privileged flash or arbitrary syscall instructions.

The actual pinned M33 MPU+FP branch (`portasm.c:289-410`) determines the copy
order: conditional high16 and copied low17 words, integer8, copied core8,
special4; the inverse restores high16 last. Low17 carries s0-s15 and FPSCR, not
the reserved hardware FP word. Basic cursor20 and extended cursor53 classify
the current representation; word20 aliases extended S4 and is not a permanent
zero guard. Word53 is checked for both saved forms and before saving. Restore
returns the cursor to word zero. This is a representation contract, not a claim
that ordinary cessation of FP instructions clears Thread FPCA or provides an
extended-to-basic lifecycle through the five public operations.

Selection uses the frozen reverse candidate call under BASEPRI and checks the
captured CPU state and every MPU region before accepting the result. Selection
does not publish. PRIMASK then covers MPU disable, MAIR/context-region writes,
the frozen reverse publication call, MPU enable and full readback. BASEPRI is
cleared/read back before inverse transfer; the successful resume path makes no
C call after restoring callee-saved general registers. Terminal readback-failure
branches may still call panic after restoration and never resume that context.
Compared with the pinned reference, the frame
copy order is preserved while the preflight, CPU/map checks, masks, ownership
publication and readbacks are intentional hardening differences. Per-region C
writes replace the reference's alias-block MPU programming on this running path.
All C helpers use the canonical sensitive/general-register-only bundle; only
the naked extended PendSV branches contain the explicit FP transfers.

Initial local GCC 14.3.1 compilation passed 48 actual ARM objects: boot, SVC
and PendSV across O2/Os, hard/softfp, 8/16 regions and eager/lazy policy, with
warnings as errors. Evidence root:

```text
C:\Users\admin\AppData\Local\Temp\fiber-c3fp-running-local-f9eb89d6d8604c1fbaa16f5f9aad7d7f
```

These object builds do not establish execution, negative-control sensitivity,
reference-branch parity, LTO behavior or full-runtime integration. Maintained
first-start, running execution and generated-reference qualification are owned
separately and must use this source cohort rather than historical sibling PASS
receipts. No board was programmed.

The subsequent cold reverse-v1 guard was checked independently for each actual
SVC/PendSV object, without linking the constructor. O2/Os x hard/softfp x 8/16
regions x non-LTO/LTO compiled 32 objects. Handler-root-only `--gc-sections`
links passed 64 times with a strong v1 provider and rejected 64 v2-only providers
with exactly the missing `fiber_internal_runtime_port_abi_v1_anchor` diagnostic,
covering both provider orders. All non-v1 imports were deliberately satisfied
by linker `defsym` stubs; only the v1/v2 anchor providers were real separate
objects. Thus the test isolates retained link dependencies, not executable
handler behavior or whole-runtime compatibility. Positive ELFs contain the
actual handler and have no undefined symbols. Evidence, command log, temporary
replay script and input hashes are retained at:

```text
C:\Users\admin\AppData\Local\Temp\fiber-c3fp-component-retain-6e645329d83b47168e48937fdb832eec
```

This guard supersedes the earlier six-export PendSV surface: the object now
also exports the cold private component anchor. It adds no read to a hot path,
and does not promote this staged profile or supply a runtime bundle/provider.
