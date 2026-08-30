# ARM_CM55_MPU Non-secure FreeRTOS Parity Ledger

## Status

This is slice 4 of the explicit build-selected `ARM_CM55_MPU/non_secure`
ARMv8.1-M Mainline profile. It freezes public storage, selected-port traits,
the exact protected frame shape, cohort identity, sealed construction, and
linker-derived global MPU image. `fiber_port.c` owns the staged protected
SVC/PendSV engine: strict first-start SVC, private SVC 71 yield, complete protected
PendSV save/select/MAIR0-plus-context-MPU replacement/restore, and strong
slots 11 and 14. It consumes frozen reverse ABI v1 for scheduler selection and
current publication, but exposes no forward runtime ABI symbol, global
selector route, optional MPU API, or hardware-support claim.

The reference is the MPU branch selected by `configENABLE_MPU = 1` inside the
Non-secure `GCC/ARM_CM55_NTZ/non_secure` source group. It is not the separate
TrustZone-capable `GCC/ARM_CM55/non_secure` port and is not an MVE, PAC, or
SecureContext profile.

## Pinned Reference

```text
FreeRTOS commit: a50edad08b29052631aa469d4df6e6ec7ff68878
FreeRTOS CMake port: GCC_ARM_CM55_NTZ_NONSECURE
Reference directory: portable/GCC/ARM_CM55_NTZ/non_secure
```

| Reference file | SHA-256 | Current disposition |
| --- | --- | --- |
| `portmacro.h` | `B7F94C8C21A4B583837C10F00ED93A1EA8C5801DEA8A3AD6C6DB13A49F947420` | M55 identity and `configENABLE_MVE` policy mapped to the selected manifest. |
| `portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` | MPU region roles, RBAR/RLAR/MAIR dictionary, `xMPU_SETTINGS`, and `MAX_CONTEXT_SIZE` audited. |
| `port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` | Protected `pxPortInitialiseStack()` and fixed MPU-image construction are implemented. |
| `portasm.c` | `DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5` | First start/activation/restore and protected PendSV save/select/program/restore are assembly-paired. |
| `mpu_wrappers_v2_asm.c` | `00B42952962E48F8C9421F5EC66BBCE9E02465760560728FEE2D743CE1706F3E` | Deferred to a future optional MPU-wrapper ABI; no Fiber stub exists. |

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

The Fiber manifest is equally narrow:

```text
FIBER_PORT_BUILD_SELECTED = 1
FIBER_PORT_ARMV81M_MAINLINE = 1
FIBER_PORT_CM55_MPU_TOTAL_REGIONS = 8 or 16
CMSIS __CORTEX_M = 55
CMSIS __MPU_PRESENT = 1
CMSIS __VTOR_PRESENT = 1
```

The profile rejects Secure CMSE, active FPU use, an FP register ABI, MVE, PAC,
and BTI. It retains ARMv8.1-M `RLAR.PXN` for a future configurable-region ABI;
the fixed initial and global images do not use that bit. Scalar M55, scalar-FP
M55, MVE-FP M55, TrustZone/SecureContext, TF-M, PAC/BTI, and future MPU-FP/MVE
profiles are distinct cohorts.

## Frozen Storage And Frame

For this exact configuration FreeRTOS uses:

```text
xMPU_SETTINGS
    ulMAIR0
    xRegionsSettings[portTOTAL_NUM_REGIONS]
    ulContext[MAX_CONTEXT_SIZE == 21]
    ulTaskFlags
```

The first 20 words are active. Word 20 is the one-past context cursor target,
not register state. The no-TrustZone/no-PAC M55 MPU restore consumes the final
four active words as `[PSP][PSPLIM][CONTROL][EXC_RETURN]`; it copies the basic
hardware frame through privileged context storage rather than keeping the
software frame on an unprivileged PSP stack.

Fiber freezes the same shape:

```text
FiberContext
    protected_context_cursor      Fiber adaptation of pxTopOfStack
    mair0                         FreeRTOS ulMAIR0
    mpu_regions[4 or 12]          FreeRTOS xRegionsSettings
    protected_context             FreeRTOS ulContext[21]
    runtime_flags                 Fiber adaptation of ulTaskFlags
    boot                          Fiber immutable metadata
```

`FiberPortProtectedContext` is exactly 84 bytes:

```text
word  0..7   r4..r11
word  8..15  copied basic hardware frame: r0..r3, r12, LR, PC, xPSR
word 16      PSP
word 17      PSPLIM
word 18      CONTROL
word 19      EXC_RETURN
word 20      cursor_limit, one-past target
```

There is no `xSecureContext` word, FP/MVE state, PAC-key state, or VPR slot in
this `C55M` cohort. The exact layout version and cohort symbol differ between
8- and 16-region manifests, so their private objects cannot be mixed later.

| MPU regions | Per-context RBAR/RLAR pairs | `protected_context` offset | `boot` offset | `sizeof(FiberContext)` |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 4 | 40 | 128 | 216 |
| 16 | 12 | 104 | 192 | 280 |

## MPU Region Mapping

The M55 FreeRTOS branch assigns hardware regions as follows:

```text
0  privileged flash
1  unprivileged flash
2  unprivileged syscall flash
3  privileged RAM
4  current fiber stack
5..N-1  configurable per-fiber regions
```

Fiber reserves the same `RNR 4` origin and 8/16 region geometry. The exact
current-slot aperture policy, linker boundaries, and per-context default image
are frozen by construction. The strict first SVC programs the four global
regions while the MPU is disabled; its naked restore then programs MAIR0 and
the selected context's RNR 4/8/12 pairs before the sole enable transition.

## Function And Macro Ledger

| FreeRTOS symbol or family | Fiber disposition |
| --- | --- |
| `portARCH_NAME`, M55 identity, byte alignment, BASEPRI traits | Implemented as selected-port manifest and trait facts. |
| `portTOTAL_NUM_REGIONS`, stack/configurable region range | Implemented as explicit 8/16-region type and macro contract. |
| `MPURegionSettings_t`, `ulMAIR0`, `xMPU_SETTINGS.ulContext`, `ulTaskFlags` | Implemented as `FiberPortMpuRegionRegisters`, `mair0`, `FiberPortProtectedContext`, and `runtime_flags`; Fiber adds immutable boot metadata. |
| `MAX_CONTEXT_SIZE == 21` | Implemented exactly as 20 active words plus `cursor_limit`. |
| `pxPortInitialiseStack()` | Implemented as `fiber_port_context_init()`: it seeds the protected image and sets `protected_context_cursor` to `cursor_limit`. |
| `vPortStoreTaskMPUSettings()` and global MPU setup | The fixed linker/global image and stack/current-slot pairs are implemented; first SVC programs the permanent four-region image. Configurable per-fiber regions remain deferred to an optional MPU policy ABI. |
| `vStartFirstTask()` / `vRestoreContextOfFirstTask()` | Implemented as `fiber_port_start_first_context()` and `fiber_port_restore_first_context_from_svc()`. The assembly preserves the MPU disable/MAIR0/RNR 4-8-12/enable and protected-frame copy ordering, with strict Fiber provenance and readback checks. |
| MPU `PendSV_Handler` | Implemented as the private protected engine: exact 20-word save/copy/special-register image, reverse-ABI selection under BASEPRI, PRIMASK-protected MAIR0/context-pair replacement, and inverse restore. |
| `xIsPrivileged`, privilege transitions, syscall dispatch | Deferred with the optional MPU application policy ABI; no no-op public stubs exist. |
| `mpu_wrappers_v2_asm.c`, ACL, system-call stack | Deferred as optional wrapper functionality. |
| SecureContext, TF-M, FPU, MVE, PAC, BTI | Absent by construction; each requires a different profile or optional ABI. |

## Slice-4 Proof

The compile matrix proves:

```text
type-only C and C++ storage compiles without CMSIS
8- and 16-region exact manifests compile at -O2 and -Os
one exact C55M cohort symbol is emitted per manifest and the spellings differ
all context, boot, MPU pair, and cursor-limit offsets are static-asserted
sealed construction plus protected SVC/PendSV runtime compile at -O2/-Os and normal/LTO synthetic ELF links
all linker boundaries and selected privileged/unprivileged sections are proven
a missing syscall boundary fails the linker contract
slots 11 and 14 retain exactly one strong SVC/PendSV handler; competing strong SVC/PendSV handlers fail link
M55 MPU first-start, activation, protected PendSV save, special-word save,
MPU replacement, and inverse restore are paired with FreeRTOS at -O2/-Os
Secure CMSE, missing MPU/VTOR, wrong core/selected profile, FPU, MVE, PAC/BTI,
invalid region count, runtime-selectable override, and selector mode fail closed
the forward runtime ABI and optional MPU application APIs remain absent
```

PendSV preflights the running pointer, seal, live PSP frame, canary,
PSPLIM/CONTROL/EXC_RETURN state, and active MPU image before loading the mutable
cursor. Scheduler policy is called under BASEPRI through reverse ABI v1, with a
full CPU/MPU snapshot/readback around the callback. The selected MAIR0 and
RNR 4/8/12 context pairs are replaced only while PRIMASK protects the
MPU-disabled interval, then the exact inverse protected frame is restored.

No forward ABI, global selector, optional MPU policy, or board validation is
claimed. The next slice may activate this proven private engine through the
frozen forward ABI and archive/cohort proofs without changing frame geometry
or handler ownership.
