# Pinned CM7 r0p1 Final-ELF Reference

This is a link-only reference fixture, not a runnable FreeRTOS kernel or a
whole-provider parity proof. The parent gate's captured bounded final-ELF
receipt is recorded in `PORT_ARCHITECTURE_AUDIT.md#post-context-cm7-fp-runtime`.
Compile the unmodified
`portable/GCC/ARM_CM7/r0p1/port.c` from pin
`a50edad08b29052631aa469d4df6e6ec7ff68878`, using that checkout's real
`include/` headers and `portable/GCC/ARM_CM7/r0p1/portmacro.h`. Do not copy or
replace upstream handler bodies. The fixture supplies only configuration,
ordinary C link roots, unavailable-kernel boundaries, vectors and a linker
script. It neither selects nor executes any Fiber production provider.

## Build Contract

Use explicit `-mcpu=cortex-m7 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard`,
`-std=gnu11 -ffreestanding -fno-builtin -fno-common`, and
`-ffunction-sections -fdata-sections`. The final CPU/FP attributes and complete
compiler command must establish Cortex-M7/FPv5-D16; ARMv7E-M preprocessor facts
alone cannot distinguish M4 from M7. Add this directory, the pinned `include/`
directory and the pinned CM7/r0p1 port directory to the include path. No CMSIS
or Fiber header is consumed by this reference fixture.

With the current GCC 14.3.1 toolchain, these C objects and the final ELF report
`Tag_CPU_name: "7E-M"`, while the startup object reports `"Cortex-M7"`.
Do not manufacture a different final CPU-name attribute. Require the explicit
M7 compiler arguments together with `Tag_CPU_arch: v7E-M` and the actual
FPv5/hard-ABI attributes. The readelf spelling `FPv5/FP-D16 for ARMv8` names the
FP attribute encoding, not an ARMv8-M CPU-architecture claim.

Compile `main.c`, `providers.c`, `startup.S` and the actual pinned `port.c`.
Link with the compiler driver, this `link.ld`, `-nostdlib`,
`-Wl,--gc-sections,--no-undefined,--fatal-warnings,-z,noexecstack`, and a
retained map file. The explicit non-executable stack policy accommodates
unchanged upstream naked-assembly objects without GNU-stack notes; retain
fatal warnings and inspect the resulting GNU_STACK flags.

Match `-O2` or `-Os` at compilation and final executable link. Native LTO uses
`-flto` throughout. Use the matching `gcc-ar` and `gcc-nm` for slim-LTO objects.
Archive only the actual upstream port object; keep application roots, providers
and startup outside the archive. Natural references must extract it without
`--whole-archive`, synthetic upstream providers, per-function optimization
overrides or counterflag fallback.

The eight reference builds are O2/Os x native LTO off/on x direct/archive port
linkage. A final ELF may be explicitly paired with multiple consumer and FP
policy rows, but that is not multiple upstream execution modes.

## Kept Code And Unavailable Boundaries

- The kept `reference_code_roots` contains typed pointers to the actual
  `pxPortInitialiseStack` and `xPortStartScheduler`. The real scheduler entry
  retains `prvPortStartFirstTask`, `vPortEnableVFP` and upstream timer setup.
- Vector slots 11, 14 and 15 point directly to actual upstream
  `vPortSVCHandler`, `xPortPendSVHandler` and `xPortSysTickHandler`. No Fiber-name
  aliases or replacement transfer bodies exist. The 256-entry table is the
  maximum architectural span, not a measured board/model external-IRQ count.
- `reference_header_facts` records real type sizes, alignment, compiler FP/ABI
  and threshold facts. It is neither an instruction fingerprint nor an
  independently sufficient frame oracle. No CPU revision is inferred from it.
- `pxCurrentTCB` is an explicitly null opaque `TaskHandle_t volatile` link
  boundary. No initialized TCB, task frame, ready list or kernel state exists.
- `vTaskSwitchContext`, `xTaskIncrementTick` and `reference_assert_failed` are
  non-IPA, general-register-only fail-stop boundaries. They record distinct
  codes through `reference_fail_stop` and execute `udf #90`; no stub returns a
  success result or emulates scheduler/tick behavior. Upstream's real weak
  `vPortSetupTimerInterrupt` is not overridden.
- Reset and unused nonreserved vectors also fail-stop. Reset does not
  initialize RAM, invoke the scheduler or enter a task. The linker reserves
  4 KiB for MSP within a generic 64 KiB RAM window; the flash/RAM placement is a
  link fixture, not a qualified H7 memory map.

Require strong unique upstream SVC/PendSV definitions and their actual Thumb
vector targets. Final LTO may internalize the C-rooted initializer/scheduler:
allow LOCAL only with exact prelink GLOBAL upstream ownership, kept typed-root
targets and retained real bodies; never accept WEAK definitions or missing
bodies. Upstream static helpers may remain local. Unreferenced entry points
may be garbage-collected: this is not whole-provider closed-body coverage.

## Priority And Intentional Differences

Use threshold `0x80` and kernel priority `0xFF`. Do not synthesize
`configPRIO_BITS` or `__NVIC_PRIO_BITS`: the actual scheduler entry contains the
upstream implemented-priority-mask probe, but this fixture never executes it.
Eight implemented priority bits, when reported by the parent QEMU fixture,
are model facts, not STM32H7 hardware facts or measurements from this ELF.

The unmodified upstream scheduler enables ASPEN and LSPEN ("lazy save always")
in every tuple. An eager Fiber policy is an explicit initialization-policy
divergence, not an upstream eager configuration.

The pinned PendSV body contains the erratum-837070 sequence
`cpsid i; msr BASEPRI; dsb; isb; cpsie i` before `vTaskSwitchContext`, followed
by a clear-to-zero BASEPRI write after that call. Its `portmacro.h` raising
helpers use `cpsid i; msr BASEPRI; isb; dsb; cpsie i`; retain that distinct
barrier ordering when inspecting generated code. These upstream sequences
unconditionally re-enable interrupts rather than restoring previous PRIMASK.
Fiber's selected `ARM_CM7/r0p1` implementation preserves/restores incoming
PRIMASK around synchronized BASEPRI writes and restores its saved scheduler
BASEPRI. Record these as intentional adaptations, not byte-equality failures.
Building this reference neither identifies affected silicon nor demonstrates
erratum occurrence, workaround effectiveness or interrupt timing on hardware.

FreeRTOS scheduler/task-list policy, ticks, tickless idle, heap, synchronization
and application execution are excluded. Fiber's initial-R9 policy, seals,
SVC service, publication and additional provenance/frame checks are separate
adaptations. The parent proof must retain actual final-ELF bytes/disassembly,
source/object maps, dependency/tool identities, before/after hashes and
independent semantic controls. No QEMU or board execution is implied here.
