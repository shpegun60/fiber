# ARM_CM4 FreeRTOS Parity Record

## Reference

The primary local reference is `_reference/FreeRTOS-Kernel/portable/GCC/ARM_CM4F`:

- `portmacro.h`
- `port.c`

This concrete port covers Cortex-M4 and Cortex-M4F. FPU context support is
selected from compiler and CMSIS facts; no-FPU M4 builds retain the core-only
save/restore path. Both profiles are compile/link-covered only until hardware
validation is recorded.

## Native Fiber Files

```text
fiber_portmacro.h
fiber_port_types.h
fiber_port_boot_types.h
fiber_port_boot.h
fiber_port_boot.c
fiber_port.c
fiber_port_exception.c
```

## Adopted Mechanics

- PSP-based Thread context and PendSV save/restore of r4-r11 plus EXC_RETURN.
- Conditional s16-s31 save/restore when EXC_RETURN reports an extended FP frame.
- SVC exception-return first start.
- BASEPRI scheduler critical section, vector checks, priority-bit probing, and
  PRIGROUP validation.
- CPACR/FPCCR setup and read-back checks when the selected build uses an FPU.

## Fiber Adaptations

- The user scheduler hook replaces `vTaskSwitchContext()`.
- Restore-target integrity, exact EXC_RETURN, canary, bounds, and frame-headroom
  checks run before the port restores PSP.
- Tick, SysTick ownership, MPU wrappers, and FreeRTOS task/scheduler state are
  intentionally excluded from the cooperative fiber port.
- `FiberPortBoot` is port-private and can later use a target-specific hardware
  integrity engine.

## Deferred Work

- Hardware validation on STM32F3/F4/G4/L4-class Cortex-M4 and Cortex-M4F boards.
- Separate performance and lazy-FPU evidence after conservative FPU policy is
  validated on each target family.
