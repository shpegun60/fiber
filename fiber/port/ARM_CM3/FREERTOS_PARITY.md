# ARM_CM3 FreeRTOS Parity Record

## Reference

The local reference is `_reference/FreeRTOS-Kernel/portable/GCC/ARM_CM3`:

- `portmacro.h`
- `port.c`

This port covers Cortex-M3 using the ARMv7-M mainline context path. It is
compile/link-covered only until a matching STM32 target passes hardware
validation.

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
- SVC exception-return first start.
- BASEPRI scheduler critical section around the scheduler bridge.
- Lowest-priority PendSV, highest-priority SVCall, vector routing checks,
  priority-bit probing, and PRIGROUP validation.

## Fiber Adaptations

- The user scheduler hook replaces `vTaskSwitchContext()`.
- Restore-target integrity and stack-frame checks are mandatory before restore.
- Tick, SysTick ownership, MPU wrappers, and FreeRTOS task/scheduler state are
  intentionally not part of the cooperative fiber runtime.
- `FiberPortBoot` is port-private and can use a different integrity mechanism
  in a future ARM_CM3 revision.

## Deferred Work

- Hardware validation on an STM32F1-class Cortex-M3 target.
- Board-specific vector-table and MSP rewind validation.
