# ARM_CM0 FreeRTOS Parity Record

Paired generated-object evidence for both M0/no-VTOR and M0+/VTOR builds is
mandatory under `../../../FREERTOS_ASM_PARITY.md`; this ledger supplies the
port-specific source classification behind those executable checks.

This is the exhaustive mechanism ledger for the privileged Cortex-M0/M0+
selected port. The pinned FreeRTOS directory contains both non-MPU and optional
MPU/unprivileged branches. This profile deliberately implements only the
privileged ARMv6-M branch; every MPU family is explicitly deferred rather than
silently ignored. No FreeRTOS source text is copied into fiber.

## Thumb-1 Vector-Load Constraint Repair

The raw initial-MSP load now uses GCC ARM low-register operands (`=l` / `l`).
The previous general-register operands could select high registers that Thumb-1
LDR cannot encode. This is a Fiber vector-validation helper correction, not a
change to the reference's register save/restore sequence. Address zero still
uses a volatile assembly load rather than an invalid C null dereference.

`tools/test_thumb1_vector_constraints.ps1` covers both privileged and MPU
profiles at O0/Og/O2/Os/O3, native LTO, both r9 contracts and both VTOR states.
Its eighty ELF cases pass 4,800 focused checks, with four compiled old-constraint
controls. Whole-port parity and constructor-r9 qualification remain separate;
no exception or hardware execution claim follows from those focused probes.

## Reference

```text
tree:   _reference/FreeRTOS-Kernel
commit: a50edad08b29052631aa469d4df6e6ec7ff68878
files:  portable/GCC/ARM_CM0/portmacro.h
        portable/GCC/ARM_CM0/port.c
        portable/GCC/ARM_CM0/portasm.h
        portable/GCC/ARM_CM0/portasm.c
```

Native fiber source group:

```text
fiber/port/ARM_CM0/fiber_portmacro.h
fiber/port/ARM_CM0/fiber_port_types.h
fiber/port/ARM_CM0/fiber_port_boot_types.h
fiber/port/ARM_CM0/fiber_port_boot.h
fiber/port/ARM_CM0/fiber_port_boot.c
fiber/port/ARM_CM0/fiber_port.c
fiber/port/ARM_CM0/fiber_port_exception.c
```

The port is compile/link-covered for M0 and M0+. It is not hardware-validated
until matching STM32 boards pass the runtime checklist.

## `portmacro.h` Ledger

| FreeRTOS item family | Fiber mapping | Decision |
| --- | --- | --- |
| Primitive compatibility aliases and `StackType_t` | Fixed-width C types and selected `FiberContext` | Adapted; kernel aliases are not exported. |
| Tick types, delay constants, tick period, atomic tick traits | User scheduler | Excluded from CPU port. |
| `portARCH_NAME` | `FIBER_PORT_NAME` and exact build selection | Adapted. |
| stack growth/alignment | selected ARMv6-M traits | Reimplemented. |
| used/inline/compiler barrier attributes | `fiber_compiler.h` and local macros | Adapted. |
| `portYIELD`, NVIC PendSV register/bit | `fiber_schedule()` and selected `PENDSVSET` | Adapted to cooperative scheduling. The direct request requires exact privileged Thread/PSP `CONTROL` state before touching ICSR. |
| ISR yield macros | None | Excluded until an ISR-safe scheduler API exists. |
| PRIMASK set/restore and interrupt enable/disable | selected-port C/asm helpers | Reimplemented. Nonzero `FIBER_SCHEDULER_BASEPRI` is a compile error because ARMv6-M has no BASEPRI. |
| critical nesting API | None public | Excluded; PendSV uses a saved PRIMASK envelope only around the scheduler hook. |
| task function macros | plain `entry_t` | Adapted without compatibility macros. |
| tickless and ready-priority macros | User scheduler/platform | Excluded. |
| `xPortIsInsideInterrupt` | direct IPSR checks | Adapted. |
| `portNOP` | None | Excluded. |

## MPU Macro Families

The following FreeRTOS `configENABLE_MPU == 1` families do not belong to this
privileged context ABI and are deferred to a future exact `ARM_CM0_MPU` port:

```text
portPRIVILEGED_* / portUNPRIVILEGED_* / portSTACK_REGION
portFIRST_CONFIGURABLE_REGION through portTOTAL_NUM_REGIONS
portMPU_REGION_SIZE_256B through portMPU_REGION_SIZE_4GB
all strongly-ordered, device, normal-memory, shareability/cacheability traits
all privileged/unprivileged access-permission and execute-never traits
portSVC_RAISE_PRIVILEGE, portSVC_SYSTEM_CALL_EXIT, portSVC_YIELD
MPU wrapper, system-call, ACL, and kernel-object access macros
```

`portSVC_START_SCHEDULER` maps to fiber's mandatory first-start SVC. The other
FreeRTOS SVC services are excluded from privileged ARM_CM0 because it never
runs an unprivileged Thread context.

## `port.c` Constant Ledger

| FreeRTOS item family | Fiber mapping | Decision |
| --- | --- | --- |
| SysTick registers/bits, 24-bit limit, missed-count factor | User scheduler/platform | Excluded. |
| SHPR2/SHPR3 and PendSV/SysTick priorities | selected exception source | PendSV/SVCall part adapted; SysTick excluded. |
| VTOR and vector slots 11/14 | selected active-vector-source helper | Adapted. VTOR-less M0 validates the architecture/platform base at zero; M0+ uses VTOR when present. |
| initial xPSR, EXC_RETURN, PC/LR/xPSR frame offsets, padding bit | selected frame ABI and validators | Reimplemented. |
| MPU type/control/RBAR/RASR registers and all MPU masks/range helpers | future `ARM_CM0_MPU` | Deferred as one complete feature family. |
| CONTROL privilege constants | future `ARM_CM0_MPU` | Deferred; privileged ARM_CM0 uses Thread/PSP without unprivileged policy. |
| task-return address | `fiber_internal_task_return()` | Replaced by a panic target. |

## `port.c` / `portasm.c` Function Ledger

| FreeRTOS function/path | Fiber path | Decision |
| --- | --- | --- |
| non-MPU `pxPortInitialiseStack` | selected context init and frame builder | Adapted with exact Thumb-1 layout, sealed metadata, Thumb PC, return panic target, and saved `r9`. |
| MPU `pxPortInitialiseStack` variant | future `ARM_CM0_MPU` | Deferred. |
| `prvTaskExitError` | `fiber_internal_task_return()` | Replaced. |
| `vRestoreContextOfFirstTask` / `vStartFirstTask` | `fiber_port_start_first_context()` plus strong `SVC_Handler` | Adapted to scheduler-selected mandatory SVC start. |
| `SVC_Handler` / `vPortSVCHandler_C` non-MPU start service | strong `SVC_Handler` | Adapted and hardened. Fiber validates IPSR 11, exact F9 EXC_RETURN, MSP origin/alignment, xPSR.T, zero stacked IPSR, absent `STACKALIGN`, nonzero aligned PC, SVC opcode, and immediate. |
| MPU SVC dispatch, privilege raise/reset, syscall exit and yield | future `ARM_CM0_MPU` | Deferred. |
| non-MPU `PendSV_Handler` | strong `PendSV_Handler` | Adapted with Thumb-1 staging of `r8-r11`. Fiber validates IPSR 14, exact FD EXC_RETURN, PSP origin/alignment, current context, save headroom, and xPSR `STACKALIGN` padding. |
| MPU `PendSV_Handler` and MPU programming | future `ARM_CM0_MPU` | Deferred. |
| `ulSetInterruptMask`, `vClearInterruptMask` | saved PRIMASK scheduler envelope | Reimplemented. |
| `xPortStartScheduler` | `fiber_start()` plus selected startup operations | Split; tick setup and kernel scheduler state are excluded. |
| `vPortEndScheduler` | None | Excluded. |
| `vPortYield`, `vPortEnterCritical`, `vPortExitCritical` | `fiber_schedule()` and internal PRIMASK envelope | Adapted only where needed; no public critical nesting API. |
| `SysTick_Handler`, timer setup, tickless sleep | User scheduler/platform | Excluded. |
| `xPortIsInsideInterrupt` | IPSR preconditions | Adapted. |
| `prvGetMPURegionSizeSetting`, `prvSetupMPU`, `vPortStoreTaskMPUSettings` | future `ARM_CM0_MPU` | Deferred. |
| `xPortIsPrivileged`, buffer/kernel-object authorization, grant/revoke ACL functions | future optional MPU ABI | Deferred. |

## Paranoid Additions

Restore validation is mandatory and checks context extent, immutable structure,
canary, saved SP/frame extent, exact EXC_RETURN, xPSR.T, stacked IPSR, stacked
PC floor/alignment, and optional code-address policy. PendSV validates current
before reading its metadata. SVC/PendSV reject foreign exception provenance.
The handler save upper bound includes the optional hardware alignment word
reported by xPSR bit 9. The external scheduler must preserve PRIMASK, CONTROL,
and port-owned state.

## Intentionally Outside This Port

```text
FreeRTOS task lists and priority scheduler
tick and tickless idle
queues and synchronization
ISR-safe wake/yield API
MPU and unprivileged execution
BASEPRI
FPU context
```

## Remaining Evidence

```text
STM32F0/G0/C0/L0/U0/WB0-class normal switching
VTOR-present and VTOR-absent startup policy
first SVC and later PendSV provenance
PRIMASK and malformed-frame traps
long-run stack/canary behavior
```

## A32 Raw Compiler Closure

The selected C group and every reachable local helper now carry the canonical
sensitive/GRO policy. Raw, annotated inline MRS/barrier/WFE primitives replace
unannotated CMSIS call sites. The priority helpers retain ARMv6-M CMSIS's word
accesses, byte masks and shifts (`core_cm0.h`, `__NVIC_SetPriority` and
`__NVIC_GetPriority`); they do not substitute ARMv7-M byte accesses. Only valid
architectural interrupt numbers are admitted. The initial-MSP LDR retains its
Thumb-1 low-register output/base constraints.

The three naked blocks differ only by one `.ltorg` after each final unconditional
panic-loop branch. No transfer instruction, frame/type layout, mask policy,
startup validation or eight-operation boundary changed. The MPU profile's six
naked bodies remain unchanged. Normal unsectioned O2 native lowering with these
three pools removed reproduces four exact literal-LDR range errors for each
VTOR dialect. Independently matched unreachable 8192-byte pressure controls pass
with the pools and reject with only the pools removed; they are not execution
or timing tests.

Qualified copied-input evidence (roots beneath `%TEMP%`):

- `fiber-sensitive-port-closure-c119d2f8e42441af96ec4d16ca3ba1cf`:
  CM0/CM0MPU, both VTOR values, O0/Og/O2/Os/O3, normal and genuine slim-LTO
  sectioned/unsectioned groups; 120 cells, 628 controls, zero input/copy drift.
  Inline-only annotation-removal controls at O2/Os retain GRO and must compile
  before the classifier rejects real transitive instrumentation. Common cold
  API exemptions remain confined to their exact function/counter extents.
- `fiber-constructor-r9-ee8ebea01eed4ef682fb439445910529`:
  both ports, 32 ordinary/reserved-R9 production tuples plus ten compiled
  controls, 42 ELFs, 168 calls and 336 bounded GPR restores; zero input drift.
  Reserved ABI uses `-ffixed-r9` throughout; ordinary borrowing is not a
  static-base defect. This is not exception/MPU execution qualification.
- `fiber-cm0-parity-inputs-261d5983e5ae4b14b917c35861171e52`,
  `O2-qualified/CM0-FOCUSED` and `Os-qualified/CM0-FOCUSED`:
  three configurations, six actual objects and 18 ordered mechanisms per
  optimization, zero source drift, against pinned FreeRTOS
  `a50edad08b29052631aa469d4df6e6ec7ff68878`. Existing named validation,
  scheduler and protected-frame differences remain; this is not byte equality.
- `fiber-cm0-classic-inputs-b246e9fd896b4632add1bfb0440b2a82/`
  `fiber-classic-audit-4958672cccfc4b598ddb832ab21a76c9`:
  84 linked ARM ELFs and 842 focused guard checks, 90 copied files unchanged.
  CM0/CM0MPU use the repaired sources; the other classic groups are preserved
  comparison inputs, not a fresh qualification of concurrent worktree changes.

The raw gate is an additional stronger software-freeze policy, not a replacement
for documented translation-unit counterflags. External memory helpers and
application callbacks retain their separate transitive/GRO integration proof.
These offline results do not establish hardware switching or isolation.

## Bounded Seven-Mode Parity

The subsequent Context-owned implementation has a separate captured
`tools/test_cm0_freeze_parity.ps1` PASS for non-MPU M0/VTOR=0 and M0+/VTOR=1.
Five ordinary optimization modes produce twenty paired objects and thirty
mechanism comparisons. The complete ordinary plus final-linked O2/Os LTO
grid, direct/archive, produces twenty-eight final pairs, fifty-six positive
ELFs and eighty-four compiled actual-source controls. The unchanged pinned
CM0 `port.c` and `portasm.c` provide the upstream side, not copied bodies.

The exact sources, independent rehash, limitations and retained FAIL attempts
are recorded in
`PORT_ARCHITECTURE_AUDIT.md#cm0-bounded-optimization-and-final-elf-parity`.
Existing `-Cm0Only` O2/Os inventories remain unchanged and still include MPU.
This new focused gate does not execute the CPU, interpret constructor bodies,
qualify CM0+ VTOR=0/MPU, establish closed-function equivalence or replace the
remaining global/hardware requirements.
