# ARM_CM33 TF-M Non-Secure Parity Ledger

This directory is one exact build-selected Cortex-M33 Non-secure profile for a
TF-M v2.0 Secure image. It is not the fiber-owned SecureContext profile.

## Pinned References

```text
_reference/FreeRTOS-Kernel
  commit: a50edad08b29052631aa469d4df6e6ec7ff68878

  portable/GCC/ARM_CM33_NTZ/non_secure/
  portable/ThirdParty/GCC/ARM_TFM/
```

Pinned artifact identities:

```text
ARM_CM33_NTZ/non_secure/port.c:
  BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A
ARM_CM33_NTZ/non_secure/portasm.c:
  DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5
ARM_CM33_NTZ/non_secure/portasm.h:
  185477BF5A84B9B61927E4A0894427A4F471C448840DBF521F312B6F52D03B6C
ARM_CM33_NTZ/non_secure/portmacro.h:
  F0D3FE9D1ADAA0894EE3A03F14152ADD4B115DF8AF144B5912FEA3EDD23FBE0B
ARM_CM33_NTZ/non_secure/portmacrocommon.h:
  324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2
ThirdParty/GCC/ARM_TFM/README.md:
  43EAC6335CBC2B3B90FA53817B844774B5DCCDC8D477308C2E83128F83B4EE0A
ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c:
  9A6242DB2128A3220495C6739078959CF56D56649F1FFB2634C6430603938901
```

The pinned FreeRTOS `ARM_TFM` directory deliberately does not provide another
SVC/PendSV implementation. Its README requires copying the matching NTZ CPU
port and adds the TF-M OS-wrapper adapter. Fiber preserves the same split:

```text
ARM_CM33_NTZ CPU mechanics
  -> copied and independently proven as the C3TF profile

TF-M integration
  -> separate initialization and mutex objects
```

## Exact Role

```text
Cortex-M33 / ARMv8-M Mainline
Non-secure privileged fiber runtime
TF-M owns the Secure image and PSA veneers
MPU = disabled
FPU = disabled
MVE = disabled
fiber-owned SecureContext = absent
PAC/BTI = absent
```

`FIBER_PORT_CONTEXT_ABI_PORT_ID == 0x43335446` is ASCII `C3TF`.
The frame layout remains the NTZ ten-word layout and therefore keeps feature
mask `0x82`; TF-M integration changes the selected profile identity, not the
saved frame shape.

```text
word  0  PSPLIM
word  1  EXC_RETURN = 0xFFFFFFBC
word  2  r4
word  3  r5
word  4  r6
word  5  r7
word  6  r8
word  7  r9
word  8  r10
word  9  r11
word 10  r0       hardware frame
word 11  r1
word 12  r2
word 13  r3
word 14  r12
word 15  LR
word 16  PC
word 17  xPSR
```

## CPU Port Mapping

| FreeRTOS artifact | Fiber artifact | Disposition |
| --- | --- | --- |
| copied `ARM_CM33_NTZ/portmacro.h` | `fiber_portmacro.h` | All architecture, stack, EXC_RETURN, PSPLIM, BASEPRI, VTOR, Security Extension, and no-FPU/no-MVE facts are retained under the selected-port vocabulary. |
| `pxPortInitialiseStack` | `fiber_port_context_init()` and `fiber_port_init_context_frame()` | Same 18-word initial frame; Fiber adds boot sealing, address checks, canary, exact word checks, and cohort retention. |
| `vStartFirstTask` | `fiber_port_start_first_context()` | Same MSP/SVC transition with stricter origin, mask, vector, and readback checks. |
| `vRestoreContextOfFirstTask` | strong `SVC_Handler` | Same PSPLIM/EXC_RETURN/PSP/CONTROL semantics; Fiber restores the full seeded software frame and validates provenance. |
| non-MPU `PendSV_Handler` | strong `PendSV_Handler` | Same PSPLIM, EXC_RETURN, and r4-r11 save/restore geometry. |
| `vTaskSwitchContext()` | `fiber_port_scheduler_pick_next_from_pendsv()` | User scheduler bridge under the port BASEPRI envelope. |
| interrupt mask helpers | port-local BASEPRI/PRIMASK helpers | Previous state is preserved and read back rather than assumed. |
| tick, queues, ready lists, delay lists | absent | Scheduler policy is not imported. |
| FreeRTOS SecureContext | absent | TF-M owns the Secure image; the two models are intentionally mutually exclusive. |

`tools/freertos_asm_parity.ps1` compiles this profile independently at `-O2`
and `-Os` and compares first start, first restore, and PendSV against the pinned
CM33 NTZ object. Sharing a reference does not allow this profile to inherit the
plain NTZ proof.

## TF-M Integration Mapping

The external `tfm_ns_interface_init()` symbol remains owned by the TF-M
v2.0.0 Non-secure interface library. Fiber does not provide a decorative stub.
A build that selects this profile without the TF-M interface must fail link.

| TF-M / FreeRTOS operation | Fiber operation | Disposition |
| --- | --- | --- |
| application calls `tfm_ns_interface_init()` at the beginning | `fiber_port_tfm_initialize()` or automatic call from `fiber_port_runtime_prepare_start()` | Idempotent one-shot initialization. The automatic path runs before CPU first-start preparation; an application may call the same API earlier. |
| `os_wrapper_mutex_create()` using a FreeRTOS semaphore | `os_wrapper_mutex_create()` with one static port-owned mutex | No heap, queue, or FreeRTOS object dependency. TF-M v2.0 uses one global interface mutex. |
| `os_wrapper_mutex_acquire()` | owner-checked cooperative acquire | Every timeout may acquire an immediately free mutex. `OS_WRAPPER_WAIT_FOREVER` retries a busy mutex through `fiber_port_runtime_schedule()`; zero or finite nonzero timeouts return `OS_WRAPPER_ERROR` when waiting would be required because this profile does not own a clock. |
| `os_wrapper_mutex_release()` | owner-checked cooperative release | A non-owner or invalid handle returns `OS_WRAPPER_ERROR`. |
| `os_wrapper_mutex_delete()` | unlocked static-object reset | Deleting an invalid or owned mutex returns `OS_WRAPPER_ERROR`. |
| FreeRTOS semaphore blocking list | absent | The user scheduler must eventually select the owner while a waiter cooperatively yields. |

The four exported wrapper spellings exactly match TF-M v2.0.0
`interface/include/os_wrapper/mutex.h`:

```c
void *os_wrapper_mutex_create(void);
uint32_t os_wrapper_mutex_acquire(void *handle, uint32_t timeout);
uint32_t os_wrapper_mutex_release(void *handle);
uint32_t os_wrapper_mutex_delete(void *handle);
```

The wrapper preserves the required result values:

```text
OS_WRAPPER_SUCCESS      0
OS_WRAPPER_ERROR        0xFFFFFFFF
OS_WRAPPER_WAIT_FOREVER 0xFFFFFFFF
```

## Paranoid Differences

Fiber additionally validates:

- pre-start TF-M initialization runs in privileged Thread/MSP with PRIMASK,
  BASEPRI, and FAULTMASK clear;
- `tfm_ns_interface_init()` preserves IPSR, PRIMASK, BASEPRI, FAULTMASK,
  CONTROL, and PSPLIM;
- initialization cannot recurse and a failed attempt remains failed;
- the mandatory runtime object retains the TF-M integration bundle, so static
  archive extraction cannot silently omit initialization or mutex symbols;
- mutex operations run only in unmasked Thread mode;
- acquire/release ownership is tied to the current `FiberContext`;
- recursive acquire, wrong-owner release, deletion while owned, unsupported
  finite timeout, and invalid handles fail deterministically;
- this profile defines no SecureContext gateway, slot, handler, or companion
  artifact.

## Required Proofs

Before this profile is accepted, the matrix must prove:

- type-only C and C++ storage headers compile without CMSIS;
- exact `C3TF` context cohort and the unchanged ten-word geometry;
- all eight mandatory forward ABI functions and strong SVC/PendSV handlers;
- exact generated assembly parity with CM33 NTZ at `-O2` and `-Os`;
- exact TF-M v2.0 external symbol surface;
- automatic initialization ordering and retained integration bundle;
- normal and LTO archive extraction, `--gc-sections`, vector slots 11/14,
  competing-handler rejection, and stale-cohort rejection;
- link failure when `tfm_ns_interface_init()` is absent;
- absence of every fiber-owned SecureContext symbol;
- invalid Secure/FPU/MVE/wrong-core manifests fail closed.

Status after those proofs is `compile/assembly/archive/ELF validated`. It is not
a TF-M service, Secure-image, or STM32 hardware runtime claim. A real claim
requires a matching TF-M v2.0 Secure image, generated NS interface and veneers,
PSA calls from multiple fibers, vector/PSPLIM readback, and board trap tests.
