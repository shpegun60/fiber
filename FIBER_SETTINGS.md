# Fiber Settings Ownership

`fiber/port/fiber_settings.h` contains application policy defaults. It is not a
CPU-description header. The selected `fiber_portmacro.h` owns architectural
facts and may reject any build flag that would change its SVC, PendSV, or saved
frame ABI.

## ARM_CM7/r0p1 User Policy

The concrete Cortex-M7 port intentionally exposes only settings that represent
a real integration or performance decision.

| Setting | Default | Purpose |
| --- | ---: | --- |
| `FIBER_ENABLE_CPACR` | `1` | Let fiber enable CP10/CP11. With `0`, the application must enable them before `fiber_start()` and readback validation still applies. |
| `FIBER_FPU_LAZY` | `0` | `0` uses deterministic eager FP stacking; `1` enables the FreeRTOS-like lazy `LSPEN` policy. |
| `FIBER_REWIND_MSP` | `1` | Restore MSP from the validated initial vector value before first SVC. Set `0` only when the integration intentionally preserves the current MSP. |
| `FIBER_SWITCH_STRICT_BARRIERS` | `1` | Use the conservative DSB/ISB switch sequence. `0` is an opt-in performance mode. |
| `FIBER_SWITCH_MASK_IRQS` | `1` | Preserve and temporarily set PRIMASK while publishing the PendSV request. `0` permits immediate PendSV entry after the ICSR write. |
| `FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH` | `0` | Recompute the sealed boot hash on every selected restore. Structural, canary, frame, and ownership checks remain mandatory when this is `0`. |
| `FIBER_STACK_ALIGN` | `8` | Stack range alignment. The selected port rejects values below the AAPCS 8-byte requirement. |
| `FIBER_STACK_CANARY` | `1` | Check the low-stack software canary on every scheduler selection. |
| `FIBER_CANARY_VALUE` | `0xDEADBEEF` | Software canary pattern when canary checking is enabled. |
| `FIBER_STACK_REDZONE_BYTES` | `32` | Unusable low-stack area between the raw range and the PSP lower bound. |
| `FIBER_BOOT_EXTRA_BYTES` | port-derived | Minimum area required for the largest saved context. It may only be increased; compile-time checks reject a smaller value. |
| `FIBER_ENABLE_UNALIGNED_TRAP` | `0` | Opt in to `CCR.UNALIGN_TRP`; this can reject otherwise supported unaligned accesses in application code. |
| `FIBER_ENABLE_DIV0_TRAP` | `1` | Enable integer divide-by-zero UsageFault trapping where supported. |

The concrete port also exposes integration values in its own
`fiber_portmacro.h`:

| Setting | Default | Purpose |
| --- | ---: | --- |
| `FIBER_SCHEDULER_BASEPRI` | first safe nonzero preemption priority | Masks scheduler-aware interrupts while the user scheduler hook runs. The value must use only implemented NVIC priority bits; with eight implemented bits, bit 0 must remain clear because it is necessarily subpriority. |
| `FIBER_SVC_START_NUMBER` | `70` | SVC immediate reserved for first context start. The handler validates both opcode and immediate. |
| `FIBER_PENDSV_VECTOR_DIRECT` | `0` | `1` means vector 14 points directly to `fiber_pendsv`; `0` validates the application wrapper. |
| `FIBER_SVC_VECTOR_DIRECT` | `0` | `1` means vector 11 points directly to `fiber_svc`; `0` validates the application wrapper. |

## Mandatory ARM_CM7/r0p1 Facts

These are fixed port contract, not settings:

- initial `EXC_RETURN` is exactly `0xFFFFFFFD`;
- an active FP context uses the corresponding exact extended encoding
  `0xFFFFFFED`;
- first start clears `CONTROL.FPCA`;
- FPU and extended-frame support come from compiler and CMSIS silicon facts;
- the Cortex-M7 r0p0/r0p1 BASEPRI errata workaround is always compiled;
- PendSV is set to the lowest implemented priority;
- SVCall is set to priority zero;
- vector routing, priority-bit probing, PRIGROUP compatibility, CPUID, and
  errata policy validation are mandatory;
- the port does not own SysTick and does not rewrite application PRIGROUP.

Old validation-disable macros are rejected rather than silently ignored. A
production build cannot turn off restore validation, vector validation, exact
`EXC_RETURN` validation, stack bounds, canary checks, or current-context
ownership.

## Stack Minimum

For Cortex-M7 with the FPU enabled, the maximum suspended context is:

```text
software r4-r11 + EXC_RETURN     36 bytes
high FP s16-s31                  64 bytes
hardware extended FP frame      72 bytes
hardware base frame              32 bytes
optional alignment word           4 bytes
                                      ---
maximum saved context            208 bytes
```

The fixed one-frame top guard is 104 bytes. It is not a nesting count because
nested Handler-mode exceptions use MSP. The selected-port minimum
PSP region is 312 bytes. With the default 32-byte low red zone, the raw stack
range must provide at least 344 bytes, plus any bytes lost while aligning an
unaligned raw range. Real fibers also need space for their normal C/C++ call
depth and local objects; this architectural minimum is not an application stack
size recommendation.

## Performance Mode

The conservative defaults are the production bring-up baseline. The H7 board
has also completed long-running normal-mode stress with:

```c
#define FIBER_FPU_LAZY 1
#define FIBER_SWITCH_MASK_IRQS 0
#define FIBER_SWITCH_STRICT_BARRIERS 0
```

Treat that combination as target-specific performance policy. Re-run normal,
FPU, and trap validation after changing it or changing optimization flags.

## Transitional Inputs

`FIBER_FORCE_SAVE_FPU`, `FIBER_VTOR_USE_NS`, `FIBER_RUN_NONSECURE`,
`FIBER_INITIAL_EXC_RETURN`, and `FIBER_BOOT_CLEAR_FPCA` remain temporarily for
the non-production `transitional_v8m` implementation. They are not evidence of
M23/M33/M55, TrustZone, Non-secure, MVE, PAC, or BTI runtime support. Native
ports must replace them with fixed selected-port traits and scenario-specific
context layouts.
