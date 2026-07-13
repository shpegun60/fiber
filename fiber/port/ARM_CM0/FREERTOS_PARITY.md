# ARM_CM0 FreeRTOS Parity Record

## Reference

The local reference is `_reference/FreeRTOS-Kernel/portable/GCC/ARM_CM0`:

- `portmacro.h`
- `port.c`
- `portasm.c`
- `portasm.h`

This port covers Cortex-M0 and Cortex-M0+ using the ARMv6-M Thumb-1 context
path. It is compile/link-covered only until a matching STM32 target passes the
hardware validation checklist.

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

- PSP-based Thread context and PendSV restore path.
- SVC exception-return first start.
- PRIMASK scheduler critical section because ARMv6-M has no BASEPRI.
- Lowest-priority PendSV, highest-priority SVCall, vector routing checks, and
  pending-PendSV cleanup before first start.
- Thumb-1 staging of r8-r11 through low registers.

## Fiber Adaptations

- The user scheduler hook replaces `vTaskSwitchContext()`.
- The port validates every selected restore context before the assembly restore.
- Tick, SysTick ownership, queues, task lists, MPU wrappers, and FreeRTOS task
  control blocks are intentionally outside this cooperative fiber port.
- `FiberPortBoot` remains port-private and may evolve independently from the
  other ports.

## Deferred Work

- Hardware validation on STM32F0/G0/C0/L0/U0/WB0-class Cortex-M0/M0+ devices.
- M0/M0+ MSP rewind policy validation on each board startup implementation.
