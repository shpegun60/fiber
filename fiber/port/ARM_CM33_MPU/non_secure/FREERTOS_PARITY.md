# ARM_CM33_MPU Non-secure FreeRTOS Parity Ledger

## Status

This is slice 1 of the explicit build-selected `ARM_CM33_MPU/non_secure`
profile. It freezes public storage, traits, MPU geometry, and exact cohort
identity only. It does not yet provide context construction, MPU register
writes, SVC, PendSV, any forward runtime ABI symbol, or a hardware-support
claim.

The reference is the no-TrustZone ARMv8-M Mainline source group, not the
TrustZone-capable `ARM_CM33/non_secure` source group. That distinction changes
the protected context layout.

## Pinned Reference

```text
FreeRTOS commit: a50edad08b29052631aa469d4df6e6ec7ff68878
FreeRTOS CMake port: GCC_ARM_CM33_NTZ_NONSECURE
Reference directory: portable/GCC/ARM_CM33_NTZ/non_secure
```

| Reference file | SHA-256 | Slice-1 disposition |
| --- | --- | --- |
| `portmacro.h` | `F0D3FE9D1ADAA0894EE3A03F14152ADD4B115DF8AF144B5912FEA3EDD23FBE0B` | M33/Mainline identity and no-MVE policy mapped to the selected manifest. |
| `portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` | MPU region roles, RBAR/RLAR/MAIR dictionary, `xMPU_SETTINGS`, and `MAX_CONTEXT_SIZE` audited. |
| `port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` | `pxPortInitialiseStack()` and MPU image construction recorded for later slices. |
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
0  privileged flash
1  unprivileged flash
2  unprivileged syscall flash
3  privileged RAM
4  current fiber stack
5..N-1  configurable per-fiber regions
```

Thus the per-context image has four RBAR/RLAR pairs for an 8-region MPU and
twelve pairs for a 16-region MPU. The slice freezes MAIR0, RBAR/RLAR encoding,
region numbering, and the required `MPU_CTRL` bits. It does not yet write MPU
registers; a later linker/global-image slice must establish the memory-domain
contract before that is permitted.

## Function And Macro Ledger

| FreeRTOS symbol or family | Fiber slice-1 disposition |
| --- | --- |
| `portARCH_NAME`, Mainline identity, byte alignment, BASEPRI traits | Implemented as selected-port manifest and trait facts. |
| `portTOTAL_NUM_REGIONS`, `portSTACK_REGION`, configurable region range | Implemented as the explicit 8/16-region type and macro contract. |
| `MPURegionSettings_t`, `ulMAIR0`, `xMPU_SETTINGS.ulContext`, `ulTaskFlags` | Implemented as `FiberPortMpuRegionRegisters`, `mair0`, `FiberPortProtectedContext`, and `runtime_flags`; Fiber adds sealed immutable boot metadata. |
| `MAX_CONTEXT_SIZE == 21` | Implemented exactly as 20 active words plus final `cursor_limit`. |
| `pxPortInitialiseStack()` | Deferred. It must seed the exact protected image and set `protected_context_cursor` to `cursor_limit`. |
| `vPortStoreTaskMPUSettings()` and global MPU setup | Deferred to the linker/global-image slice. |
| `vRestoreContextOfFirstTask()` | Deferred to a separately audited first-start slice. |
| MPU `PendSV_Handler` | Deferred to a separately audited save/select/program/restore slice. |
| `xIsPrivileged`, `vRaisePrivilege`, `vResetPrivilege`, syscall dispatch | Deferred with the optional MPU application policy ABI; no no-op public stubs are exported. |
| `mpu_wrappers_v2_asm.c`, ACL, system-call stack | Deferred as optional MPU-wrapper functionality. The basic selected CPU profile does not pretend to implement FreeRTOS queue/wrapper policy. |
| SecureContext, TF-M, PAC, BTI, FPU, MVE | Absent by construction. Each needs a distinct selected-port or optional ABI cohort. |

## Slice-1 Proof

The compile matrix must prove all of the following before this slice is
accepted:

```text
type-only C and C++ storage compiles without CMSIS
the build-selected public facade resolves exactly this complete type
the full M33 MPU manifest compiles at -O2 and -Os for 8 and 16 regions
one exact cohort symbol is emitted per manifest and the two spellings differ
all context, boot, MPU pair, and cursor-limit offsets are static-asserted
Secure CMSE, missing MPU/VTOR, FPU, MVE, PAC/BTI, wrong core, invalid region
count, runtime-selectable override, and selector mode fail closed
no runtime source, strong handler, forward ABI, or optional MPU API exists yet
```

No generated SVC/PendSV assembly parity or board validation is claimed until
the corresponding source exists. That omission is deliberate and tested as
absence, not hidden behind a placeholder implementation.

## Next Slice

The next implementation slice may add sealed construction and the linker/global
MPU image. It must preserve the 20-active-word plus `cursor_limit` semantics,
build regions 4 through N-1 using the pinned RBAR/RLAR/MAIR rules, and add
generated-assembly proof before activating any first-start or PendSV path.
