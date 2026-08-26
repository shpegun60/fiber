# ARM_CM33_MPU Non-secure FreeRTOS Parity Ledger

## Status

Slices 1-3 of the explicit build-selected `ARM_CM33_MPU/non_secure` profile
freeze public storage, traits, MPU geometry, exact cohort identity, sealed
context construction, linker-derived global MPU images, and the protected first
SVC transition. The selected port now owns one strong `SVC_Handler`, validates
the active vector slot and first SVC provenance, installs and reads back the
four global MPU pairs while disabled, then restores MAIR0, the selected
context's RBAR/RLAR pairs, `PSP`, `PSPLIM`, `CONTROL`, and the protected basic
frame before exception return.

This remains a deliberately staged profile: there is no `PendSV_Handler`,
scheduler selection, eight-function forward runtime ABI, public MPU-management
API, SecureContext, TF-M, or hardware-support claim. The original SVC
`EXC_RETURN` is passed explicitly from the C dispatcher into naked restore;
the naked code revalidates the original `0xFFFFFFB8` SVC-origin token before
the selected context's own `EXC_RETURN` deliberately replaces `LR`. The normal
C call return address is never used as exception-return authority.

The reference is the no-TrustZone ARMv8-M Mainline source group, not the
TrustZone-capable `ARM_CM33/non_secure` source group. That distinction changes
the protected context layout.

## Pinned Reference

```text
FreeRTOS commit: a50edad08b29052631aa469d4df6e6ec7ff68878
FreeRTOS CMake port: GCC_ARM_CM33_NTZ_NONSECURE
Reference directory: portable/GCC/ARM_CM33_NTZ/non_secure
```

| Reference file | SHA-256 | Fiber disposition through slice 3 |
| --- | --- | --- |
| `portmacro.h` | `F0D3FE9D1ADAA0894EE3A03F14152ADD4B115DF8AF144B5912FEA3EDD23FBE0B` | M33/Mainline identity and no-MVE policy mapped to the selected manifest. |
| `portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` | MPU region roles, RBAR/RLAR/MAIR dictionary, `xMPU_SETTINGS`, and `MAX_CONTEXT_SIZE` audited. |
| `port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` | `pxPortInitialiseStack()`, `vPortStoreTaskMPUSettings()`, and `prvSetupMPU()` adapted into sealed construction and in-memory global-image encoding. |
| `portasm.c` | `DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5` | First restore and PendSV save/program/restore order recorded for later assembly proof. |
| `mpu_wrappers_v2_asm.c` | `00B42952962E48F8C9421F5EC66BBCE9E02465760560728FEE2D743CE1706F3E` | Deferred to a future optional MPU-wrapper ABI. It is not copied as a stub. |

## Exact Reference Configuration

```text
configENABLE_MPU = 1
configENABLE_TRUSTZONE = 0
configRUN_FREERTOS_SECURE_ONLY = 0
configENABLE_FPU = 0
configENABLE_MVE = 0
configENABLE_PAC = 0
configENABLE_BTI = 0
configNUMBER_OF_CORES = 1
configTOTAL_MPU_REGIONS = 8 or 16
```

The Fiber selected manifest is deliberately equally narrow:

```text
FIBER_PORT_BUILD_SELECTED = 1
FIBER_PORT_ARMV8M_MAINLINE = 1
FIBER_PORT_CM33_MPU_TOTAL_REGIONS = 8 or 16
CMSIS __CORTEX_M = 33
CMSIS __MPU_PRESENT = 1
CMSIS __VTOR_PRESENT = 1
```

The profile rejects a Secure CMSE build, an FP register ABI, active FPU use,
MVE, PAC, and BTI. Those are distinct context cohorts, not toggles for this
layout.

## Frozen Storage And Frame

FreeRTOS uses this selected no-TrustZone configuration:

```text
xMPU_SETTINGS
    ulMAIR0
    xRegionsSettings[portTOTAL_NUM_REGIONS]
    ulContext[MAX_CONTEXT_SIZE == 21]
    ulTaskFlags
```

The first 20 context words are active. Word 20 is not SecureContext state;
it is the one-past cursor target returned by `pxPortInitialiseStack()`. The
reference no-TrustZone `portasm.c` consumes the final four active words with:

```text
ldmdb cursor!, {PSP, PSPLIM, CONTROL, EXC_RETURN}
```

The Fiber representation preserves that exact shape:

```text
FiberContext
    protected_context_cursor      Fiber adaptation of FreeRTOS pxTopOfStack
    mair0                         FreeRTOS ulMAIR0
    mpu_regions[4 or 12]          FreeRTOS xRegionsSettings
    protected_context             FreeRTOS ulContext[21]
    runtime_flags                 Fiber adaptation of ulTaskFlags
    boot                          Fiber immutable sealed metadata
```

`FiberPortProtectedContext` is exactly 84 bytes:

```text
word  0..7   r4..r11
word  8..15  copied basic hardware frame: r0..r3, r12, LR, PC, xPSR
word 16      PSP
word 17      PSPLIM
word 18      CONTROL
word 19      EXC_RETURN
word 20      cursor_limit, one-past save/restore target
```

There is no xSecureContext word in this no-TrustZone profile. A physical
SecureContext slot and any Secure companion remain separate future artifacts.

The context storage differs by MPU capacity but not by transfer semantics:

| MPU regions | Per-context RBAR/RLAR pairs | `protected_context` offset | `boot` offset | `sizeof(FiberContext)` |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 4 | 40 | 128 | 216 |
| 16 | 12 | 104 | 192 | 280 |

The exact layout version and retained context-cohort symbol differ between the
8- and 16-region manifests. Mixing their objects must therefore fail later
cohort/link checks rather than silently reusing incompatible offsets.
The immutable feature mask also includes the Non-secure execution role, as in
the existing ARM_CM23_NTZ and ARM_CM33_NTZ cohorts.

## MPU Region Mapping

The FreeRTOS ARMv8-M MPU region roles are retained:

```text
hardware RNR 0  privileged flash
hardware RNR 1  unprivileged flash
hardware RNR 2  unprivileged syscall flash
hardware RNR 3  privileged SRAM
hardware RNR 4  current fiber stack, stored at ctx->mpu_regions[0]
hardware RNR 5..N-1  configurable pairs, stored at ctx->mpu_regions[1..]
```

Thus the per-context image has four RBAR/RLAR pairs for an 8-region MPU and
twelve pairs for a 16-region MPU. The selected port has separate macro names
for hardware region numbers and context-array indexes, preventing the invalid
`ctx->mpu_regions[4]` access that an ambiguous `STACK_REGION` name would cause
for the four-pair 8-region cohort.

The global in-memory image has exactly four pairs, indexed by hardware region
numbers `0..3`. The common `fiber_internal_runtime_current_context_slot` is a
single 32-bit object inside the privileged-SRAM linker range; it is not a fifth
global MPU aperture. This follows the ARMv8-M reference layout, whose global
region 3 protects kernel SRAM.

## Slice-2 Construction And Linker Policy

`fiber_port_context_init()` is port-private construction surface, not a newly
activated public runtime operation. It requires:

```text
FiberContext              fully contained in privileged SRAM
common current slot       exactly one 32-bit object in privileged SRAM
raw task stack            fully contained in unprivileged RAM
task entry                Thumb address in unprivileged flash only
task return continuation  selected-port symbol in syscall flash only
```

The raw stack range must be non-empty and have 32-byte-aligned exclusive
boundaries. `fiber_port_mpu_try_encode_exact_region()` then emits an RBAR/RLAR
pair without rounding the caller's range outward. It encodes an exclusive end
as `(end - 1) & RLAR_ADDRESS_MASK`, after proving the endpoint is exactly
representable. This is intentionally stricter and less ambiguous than relying
on the reference linker's inclusive end-symbol convention.

Construction reserves the common red zone inside the raw stack mapping,
initializes `PSPLIM` to the usable `stack_base`, writes the canary when enabled,
and requires at least the physical 40-byte M33-MPU PSP frame budget. It fills
the exact 20 active protected words, places `protected_context_cursor` at the
final one-past `cursor_limit`, assigns MAIR0 (`normal=0xFF`, `device=0x04`),
enables only the stack pair at context index zero, and disables all configurable
pairs. The word layout is FreeRTOS-compatible, but Fiber intentionally seeds
scratch registers with zero instead of FreeRTOS debug marker values and copies
the live `r9` value rather than the reference's marker. This preserves a
platform/static-base ABI while keeping deterministic initial state; it does not
change the saved-word order or restore semantics. Immutable boot metadata,
MAIR0, and every RBAR/RLAR pair are sealed; the protected saved
registers/cursor and runtime flags remain mutable for the future protected
PendSV owner.

`fiber_port_mpu_build_global_regions()` builds, but does not write, these
four FreeRTOS-derived global images:

```text
image[0]  privileged flash, privileged read-only
image[1]  unprivileged flash, read-only
image[2]  unprivileged syscall flash, read-only
image[3]  privileged SRAM, privileged read-write and XN
```

`fiber_port_linker_contract.ld` is an application-owned assertion fragment.
It requires twelve exact boundaries for those four global regions, the
contained current-slot object, and unprivileged RAM. It rejects missing ranges,
non-32-byte MPU boundaries, a slot that is not exactly one pointer inside
privileged SRAM, and every overlap among the fixed code/RAM regions. It never
chooses STM32 addresses itself. It also requires the selected protected-code,
syscall, protected-data, and current-slot output sections to stay within their
respective ranges. The integration must place `fiber_panic()` in privileged
flash too; construction validates that exact target before accepting a layout.

## Function And Macro Ledger

| FreeRTOS symbol or family | Fiber disposition through slice 3 |
| --- | --- |
| `portARCH_NAME`, Mainline identity, byte alignment, BASEPRI traits | Implemented as selected-port manifest and trait facts. |
| `portTOTAL_NUM_REGIONS`, `portSTACK_REGION`, configurable region range | Implemented as the explicit 8/16-region type and macro contract. |
| `MPURegionSettings_t`, `ulMAIR0`, `xMPU_SETTINGS.ulContext`, `ulTaskFlags` | Implemented as `FiberPortMpuRegionRegisters`, `mair0`, `FiberPortProtectedContext`, and `runtime_flags`; Fiber adds sealed immutable boot metadata. |
| `MAX_CONTEXT_SIZE == 21` | Implemented exactly as 20 active words plus final `cursor_limit`. |
| `pxPortInitialiseStack()` | Implemented as `fiber_port_context_init()`: FreeRTOS-compatible no-TrustZone protected layout plus one-past cursor. Fiber deliberately uses zero scratch seeds and preserves live r9 instead of FreeRTOS debug markers. |
| `vPortStoreTaskMPUSettings()` | Implemented for the default Fiber policy: exact raw stack pair at context index 0; all configurable pairs disabled until a future optional MPU API exists. |
| `prvSetupMPU()` | The construction helper `fiber_port_mpu_build_global_regions()` builds the four pairs. Slice 3 writes and reads them back in `fiber_port_mpu_program_global_image_while_disabled()` before naked per-context restore. |
| `vStartFirstTask()` | Implemented as `fiber_port_start_first_context()`: validates the direct SVC vector and initial MSP, clears stale PendSV, resets MSP, then invokes SVC 70. |
| `vRestoreContextOfFirstTask()` | Implemented as `fiber_port_restore_first_context_from_svc()`: MPU off, MAIR0, RNR 4/8/12 pair blocks, exact MPU enable, active-image readback, protected frame restore, and exception return. |
| `SVC_Handler` / `vPortSVCHandler_C()` | Implemented as the direct strong `SVC_Handler` plus fail-closed `fiber_port_svc_dispatch()`. Only SVC 70 first start and SVC 72 task return are recognized; 71 is reserved until PendSV exists. |
| MPU `PendSV_Handler` | Deferred to a separately audited save/select/program/restore slice. |
| `xIsPrivileged`, `vRaisePrivilege`, `vResetPrivilege`, syscall dispatch | Deferred with the optional MPU application policy ABI; no no-op public stubs are exported. |
| `mpu_wrappers_v2_asm.c`, ACL, system-call stack | Deferred as optional MPU-wrapper functionality. The basic selected CPU profile does not pretend to implement FreeRTOS queue/wrapper policy. |
| SecureContext, TF-M, PAC, BTI, FPU, MVE | Absent by construction. Each needs a distinct selected-port or optional ABI cohort. |

## Slice-3 Proof

The compile matrix must prove all of the following before this slice is
accepted:

```text
type-only C and C++ storage compiles without CMSIS
the build-selected public facade resolves exactly this complete type
the full M33 MPU manifest compiles at -O2 and -Os for 8 and 16 regions
one exact cohort symbol is emitted per manifest and the two spellings differ
all context, boot, MPU pair, and cursor-limit offsets are static-asserted
hardware MPU region numbers and context-image indexes are distinct and pinned
sealed construction emits only port-private code in privileged code sections
the construction object has the exact linker-boundary/cohort dependency surface
synthetic 8/16-region linker images retain privileged, unprivileged, syscall,
current-slot, and stack sections with section GC enabled at -O2, -Os, and LTO
the linker fragment rejects a missing syscall-flash boundary
construction remains separate from runtime and emits no SVC, PendSV, `msr`, or
MPU-register write instruction
Secure CMSE, missing MPU/VTOR, FPU, MVE, PAC/BTI, wrong core, invalid region
count, runtime-selectable override, and selector mode fail closed
the runtime has exactly one strong SVC handler, no PendSV handler, no forward
runtime ABI, and no optional MPU API
the protected first-start runtime compiles for 8 and 16 regions at `-O2`,
`-Os`, and LTO; it retains exactly the required strong symbols and code/data
sections under section GC
synthetic vectors retain strong SVC in slot 11, and a competing strong SVC
handler fails link
generated assembly proves explicit SVC 70/72, MPU/MAIR0/RNR/RBAR/RLAR writes,
`PSP`/`PSPLIM`/`CONTROL`/`BASEPRI` restore, and explicit SVC `EXC_RETURN`
transfer and `0xFFFFFFB8` provenance revalidation in naked restore
pinned FreeRTOS generated-assembly parity covers first start, MPU activation,
and protected special/general/completion restore at `-O2` and `-Os`
```

SVC generated-assembly parity is now claimed only for the mechanisms listed
above. PendSV generated parity and board validation remain absent by design;
the matrix proves there is no placeholder `PendSV_Handler` that could imply
otherwise.

## Next Slice

The next implementation slice is protected PendSV save/select/MPU-
replace/restore. It must consume the sealed 20-active-word plus `cursor_limit`
image without changing its geometry, preserve the direct SVC ownership already
introduced here, and add paired generated-assembly, archive/ELF/cohort, and
negative handler proof before becoming runtime-selectable.
