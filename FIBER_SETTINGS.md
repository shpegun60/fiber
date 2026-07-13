# Fiber Settings Ownership

`fiber/port/fiber_settings.h` contains only application policy that can change
without changing the selected CPU-port ABI. CPU capabilities, frame layout,
EXC_RETURN, FPCA handling, stack alignment, vector-bank selection, and switch
barriers belong to the selected `fiber_portmacro.h`.

Under `V2_OPAQUE_CONTEXT_CONTRACT.md`, `FIBER_REWIND_MSP` remains a selected
port runtime-start policy. Common code and future per-context layouts do not
store or interpret its MSP plan.

## User Policy

| Setting | Default | Purpose |
| --- | ---: | --- |
| `FIBER_FPU_LAZY` | `0` | `0` selects deterministic eager FP stacking; `1` enables lazy `LSPEN` behavior on an FPU port. |
| `FIBER_REWIND_MSP` | `1` | Restore MSP from the validated initial vector value before first SVC. Set `0` only when the integration intentionally preserves current MSP. |
| `FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH` | `0` | Recompute the sealed boot-record hash on every restore. Structural, canary, frame, and ownership checks remain mandatory at `0`. |
| `FIBER_STACK_CANARY` | `1` | Validate the runtime-owned low-stack canary before every restore. |
| `FIBER_STACK_REDZONE_BYTES` | `32` | Reserve a selected-port-aligned low-stack region below the PSP lower bound. |

Every user-policy boolean in this file and `fiber_platform_policy.h` is
compile-time validated. The compile matrix contains a negative probe for each
one and for the selected-port numeric integration constraints listed below.
It also performs a complete common-runtime plus concrete CM7 port build,
relocatable link, and selected-port ABI symbol audit with
`__NVIC_PRIO_BITS=8`.

## Platform Policy

`fiber/fiber_platform_policy.h` owns fault behavior that affects the complete
application, not only fibers:

| Setting | Default | Purpose |
| --- | ---: | --- |
| `FIBER_ENABLE_UNALIGNED_TRAP` | `0` | Enable `CCR.UNALIGN_TRP` where implemented. |
| `FIBER_ENABLE_DIV0_TRAP` | `1` | Enable integer divide-by-zero UsageFault trapping where implemented. |
| `FIBER_CLEAR_STICKY_FAULT_STATUS_ON_START` | `0` | Clear existing CFSR/HFSR/DFSR evidence before first start. Keep `0` when prior fault evidence must survive startup. |
| `FIBER_ENABLE_CONFIGURABLE_FAULTS` | `1` | Enable available MemManage, BusFault, and UsageFault handlers through SHCSR. |

## Selected-Port Integration

The concrete port may expose integration values that are validated against its
CPU contract:

| Setting | CM7 default | Purpose |
| --- | ---: | --- |
| `FIBER_SCHEDULER_BASEPRI` | first safe nonzero preemption priority | Protect the user scheduler hook. Only implemented preemption-priority bits are accepted. The default masks every configurable priority except priority zero. An override may leave higher-urgency ISRs running, but those ISRs must not touch scheduler state or call fiber APIs. |
| `FIBER_SVC_START_NUMBER` | `70` | Reserved first-start SVC immediate. The handler validates opcode and immediate. |
| `FIBER_PENDSV_VECTOR_DIRECT` | `0` | `1` means vector 14 points directly to `fiber_pendsv`; `0` validates a naked tail-branch wrapper. |
| `FIBER_SVC_VECTOR_DIRECT` | `0` | `1` means vector 11 points directly to `fiber_svc`; `0` validates a naked tail-branch wrapper. |

The non-production `transitional_v8m` port additionally accepts explicitly
named bring-up inputs:

- `FIBER_TRANSITIONAL_V8M_RUN_NONSECURE`
- `FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK`

They do not provide a production support claim. Runtime still requires the
corresponding `FIBER_ALLOW_UNVALIDATED_*` opt-in.

## Mandatory Port Facts

The concrete `ARM_CM7/r0p1` port fixes these invariants:

- stack alignment is 8 bytes;
- initial and maximum saved-context geometry is exported by the port, including
  its high-FP software area and architectural alignment word;
- initial EXC_RETURN is exactly `0xFFFFFFFD`;
- an active FP context uses the exact extended encoding `0xFFFFFFED`;
- first start clears `CONTROL.FPCA` when the selected port has an FPU;
- CP10/CP11 are enabled and read back before first start;
- FPU context support requires both compiler FP generation and a CMSIS silicon
  FPU declaration; CMSIS `__FPU_USED`, when present, must agree;
- the Cortex-M7 r0p0/r0p1 BASEPRI errata workaround is always compiled;
- PendSV request publication and every port context boundary use mandatory
  DSB/ISB serialization;
- PendSV priority, SVCall priority, vector routing, priority-bit probing,
  PRIGROUP compatibility, CPUID, and errata policy checks are mandatory;
- canary encoding is runtime-owned and cannot be overridden.

## Exact Stack Minimum

The initial synthetic frame is built down from `stack_top`. After SVC restores
it, PSP equals `stack_top`; no separate top guard is required. The minimum
usable PSP region is the largest context the selected port can actually save.

For Cortex-M7 with an active FP context:

```text
software r4-r11 + EXC_RETURN     36 bytes
high FP s16-s31                  64 bytes
hardware extended FP frame      72 bytes
hardware base frame              32 bytes
optional alignment word           4 bytes
                                      ---
maximum saved context            208 bytes
```

With the default 32-byte red zone, an already aligned static stack needs at
least 240 bytes. A non-FP CM7 build needs 72 usable bytes and 104 bytes with the
default red zone. Unaligned raw begin/end addresses can lose additional bytes
during normalization. These are architectural minima, not recommendations for
normal C/C++ call depth or local objects.

## Removed Configuration

The following old names are compile errors. They either changed a CPU fact,
duplicated a canonical port trait, or pretended mandatory safety behavior was a
tuning option:

```text
FIBER_ENABLE_CPACR
FIBER_FORCE_SAVE_FPU
FIBER_VTOR_USE_NS
FIBER_RUN_NONSECURE
FIBER_INITIAL_EXC_RETURN
FIBER_BOOT_CLEAR_FPCA
FIBER_STACK_ALIGN
FIBER_CANARY_VALUE
FIBER_EXC_LEVELS_ON_PSP
FIBER_BOOT_EXTRA_BYTES
FIBER_SWITCH_MASK_IRQS
FIBER_SWITCH_STRICT_BARRIERS
FIBER_CORTEX_M7_R0P1_ERRATA_837070
FIBER_FORCE_PRIGROUP
FIBER_TUNE_SYSTICK
FIBER_TUNE_SVCALL
FIBER_VALIDATE_EXCEPTION_SETUP
FIBER_VALIDATE_VECTOR_WIRING
FIBER_VALIDATE_PENDSV_VECTOR
FIBER_VALIDATE_SVC_VECTOR
FIBER_VALIDATE_BASEPRI_PRIORITY_MASK
FIBER_VALIDATE_PRIORITY_GROUPING
FIBER_VALIDATE_M7_R0P1_ERRATA_POLICY
FIBER_VALIDATE_SVC_PRIORITY
FIBER_PORT_TRAITS_LEGACY_BRIDGE
FIBER_HAS_*
FIBER_USE_PSPLIM_REGISTER
```

Common runtime code consumes only canonical `FIBER_PORT_*` traits. A stale
integration therefore fails at compile time instead of silently selecting a
different context ABI. Canonical selected-port traits are outputs: predefining
one through compiler flags is also a compile error.
