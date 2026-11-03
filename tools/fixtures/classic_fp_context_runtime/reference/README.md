# Pinned CM4F Final-ELF Reference

This is a link-only fixture, not a runnable FreeRTOS kernel or a completed
parity gate. Compile the unmodified
`portable/GCC/ARM_CM4F/port.c` from pin
`a50edad08b29052631aa469d4df6e6ec7ff68878`, using that checkout's real
`include/` headers and `portable/GCC/ARM_CM4F/portmacro.h`. Do not copy or replace
upstream handler bodies. This directory supplies only application configuration,
link roots, unavailable-kernel boundaries, a vector table and a linker script.

## Build Contract

Use `-mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard`,
`-std=gnu11 -ffreestanding -fno-builtin -fno-common`, and
`-ffunction-sections -fdata-sections`. Add this directory, the pinned `include/`
directory and the pinned CM4F port directory to the include path. No CMSIS or
Fiber header is consumed by this reference fixture.

Compile `main.c`, `providers.c`, `startup.S` and the actual pinned `port.c`.
Link with the compiler driver, this `link.ld`, `-nostdlib`,
`-Wl,--gc-sections,--no-undefined,--fatal-warnings,-z,noexecstack`, and a
retained map file. The explicit non-executable stack policy also accommodates
the unchanged upstream naked-assembly object's absent GNU-stack note without
disabling fatal warnings; check the resulting GNU_STACK flags.
Use matching `-O2` or `-Os` at compilation and final link. For native LTO use
`-flto` throughout, including the final executable link. Use the matching
`gcc-ar` and `gcc-nm` for slim-LTO objects. The archive variant puts only the
actual upstream port object into an archive; application roots, boundary
providers and startup remain outside it. No `--whole-archive`, manufactured
upstream providers, per-function optimization overrides or counterflag fallback
is needed.

The intended eight distinct reference builds are optimization (O2/Os) x native
LTO (off/on) x port linkage (direct/archive). Each final ELF may be paired with
both actual consumers, both Fiber FP policies and both validation policies.
Keep these associations explicit; do not describe them as 64 upstream modes.

The reference threshold is `0x80` and kernel interrupt priority is `0xFF`.
`configPRIO_BITS` and `__NVIC_PRIO_BITS` are deliberately not synthesized:
the pinned scheduler entry probes the implemented priority-bit mask at runtime.
That path is linked, not executed here. The parent execution fixture's reported
eight implemented priority bits describe its QEMU model, not STM32G4 hardware;
no measured priority-bit count is supplied by this link-only image.

## Retained Definitions And Boundaries

- `reference_code_roots` contains typed pointers to the actual
  `pxPortInitialiseStack` and `xPortStartScheduler`. Its kept section naturally
  extracts the port object from an archive. The real scheduler entry retains
  `prvPortStartFirstTask`, `vPortEnableVFP`, and the actual timer setup path.
- Vector slots 11, 14 and 15 point directly to the upstream `vPortSVCHandler`,
  `xPortPendSVHandler` and `xPortSysTickHandler`. No Fiber-name aliases or fake
  transfer bodies are defined. The table has the maximum architectural
  256-entry span; this is not a measured external-IRQ count for a board/model.
- `reference_header_facts` records real header/compiler type, alignment, FP ABI
  and priority facts. It is not a frozen instruction fingerprint or an
  independently sufficient frame oracle.
- `pxCurrentTCB` is an explicitly null opaque `TaskHandle_t volatile` link
  boundary. There is no fake initialized TCB, task stack or kernel state.
- `vTaskSwitchContext`, `xTaskIncrementTick` and `reference_assert_failed` are
  non-IPA, general-register-only fail-stop boundaries. They record a distinct
  code via `reference_fail_stop` and execute `udf #90`, without successful
  returns or scheduler/tick emulation. Upstream's real weak
  `vPortSetupTimerInterrupt` is not overridden.
- Reset and all unused nonreserved vectors also fail-stop. Reset does not
  initialize RAM, call `xPortStartScheduler`, or run a task. The linker reserves
  a 4 KiB MSP area within a 64 KiB RAM window; no execution or machine-memory
  qualification is implied.

Final-LTO analysis must retain and follow actual local helper bodies/call
targets, allowing legitimate local binding/name decoration rather than forcing
static upstream helpers to become public. Actual SVC/PendSV definitions and
their Thumb vector addresses must remain strong, unique and attributable to
the upstream object. Reject missing bodies, unresolved imports or replacement
providers. Unreferenced upstream entry points may be garbage-collected; this
is not a claim of whole-port closed-body coverage.

## Intentional Differences And Limits

The pinned `xPortStartScheduler` explicitly enables ASPEN and LSPEN ("lazy save
always"). It remains unmodified in every reference image. Fiber eager mode is
an intentional initialization-policy divergence, not an invented upstream
eager configuration. Eager consumer rows still pair with this lazy reference
and must disclose that distinction. Shared conditional FP transfer mechanisms
can be compared without claiming equal initialization policies.

FreeRTOS task lists, scheduler selection, tick behavior, heap, synchronization
and application execution are excluded. Fiber's initialization/seal checks,
saved initial R9 policy, SVC service number, common publication and additional
frame/provenance guards are adaptations, not byte-equality requirements.
This fixture alone proves none of their semantics. The parent gate must retain
actual final-ELF disassembly, source/object maps, dependency and tool hashes,
before/after input checks and independently defined causal controls. Building
this fixture does not execute the reference under QEMU or on hardware.
