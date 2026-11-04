# Pinned CM0 Reference Final-Twin Producer

This standalone producer is separate from the frozen classic final-image
readers. It closes source, recipe, compilation, owning-object protocols and
same-object direct-link twins. It does not yet close the five roots after
final relocation. Producer success is not final native/reference parity,
whole-runtime semantic proof, LTO coverage or a hardware claim.

## Exact Scope

The pinned reference is `a50edad08b29052631aa469d4df6e6ec7ff68878`.
Only these ordinary-AAPCS, p2/b0, soft/no-FPU/no-MPU profiles are admitted:

```text
cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default
cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default
cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default
```

Each requires an independent build at `-O0`, `-Og`, `-O2`, `-Os` and `-O3`.
Mode, CPU and declared VTOR capability come from closed build inputs, not
inference from identical generated instructions. These synthetic profiles
do not identify a particular STM32 device, memory map or board.

Five translation units are linked directly, without an intermediate `-r`:

1. Pinned `portable/GCC/ARM_CM0/port.c`.
2. Pinned `portable/GCC/ARM_CM0/portasm.c`.
3. Typed fail-stop providers.
4. Typed reference consumer.
5. Thumb-1 fixture startup.

The selected headers are the real `portmacro.h` and `portasm.h`. Discovered
kernel and toolchain dependencies are captured and compared with actual
compilation dependencies. The base configuration retains its inline infinite
loop `configASSERT`; substituting an assertion callback would change the C
dispatcher protocol. MPU, FPU and TrustZone are explicitly zero. The raw
threshold value zero means BASEPRI is not applicable, not equivalence to a
classic-FP interrupt-priority configuration.

For no-VTOR profiles, this fixture explicitly disables the upstream dormant
`xPortStartScheduler()` handler-installation check, which would otherwise
dereference the VTOR register. The VTOR-present profile retains that check.
This is a declared fixture recipe difference. Independent final vector
placement is checked for all profiles; neither check proves active runtime
vector routing.

## Owning Roots

| Root | Owning Translation Unit |
| --- | --- |
| `vStartFirstTask` | `portasm.c` |
| `SVC_Handler` | `portasm.c` |
| `vPortSVCHandler_C` | `port.c` |
| `vRestoreContextOfFirstTask` | `portasm.c` |
| `PendSV_Handler` | `portasm.c` |

The existing source-transcribed CM0 protocol matches all five complete
owning-object bodies. The C dispatcher and first-restore function are not
replaced by fixture stubs or hidden behind the outer SVC root. Other callees
and kernel/task semantics remain outside this bounded root set.

Linker `KEEP` retains the complete five input sections, not artificially
enlarged function symbols. In this reference, literal pools can lie outside
`st_size`; they remain separately owned section bytes. Their mappings and
relocations must not disappear merely because a root's function extent ends.
A future final-root reader must independently bind those pools, applied
function-pointer Thumb tags, local branches and register transfers. The
producer alone does not satisfy that obligation.

## Non-Executable Fixture

`pxCurrentTCB` has the real opaque `TaskHandle_t volatile` type and starts as
NULL. No TCB layout, task, scheduler queue, tick or reset initialization is
simulated. Kernel providers and reset/fault entry points fail stop; the image
is never executed by this gate. The retained consumer contains correctly
typed constructor/scheduler and five transfer-root references, plus ten
numeric header facts. Missing FP compiler builtins are handled locally in
the consumer, not fabricated as CPU capability macros.

The 256-word table is linked at zero. Slots 11, 14 and 15 resolve to the real
strong upstream `SVC_Handler`, `PendSV_Handler` and `SysTick_Handler`.
An ordinary final image and a `--emit-relocs` image use the exact same five
objects. Allocated sections and load images must match between these twins;
native and reference load images are never required to match each other.

All global required-cell counters remain integer zero. Final-root,
final-parity, policy-equivalence, CPU-execution, board and global-freeze flags
remain false even after producer success.

## Invocation

```text
python -B tools/fixtures/cm0_final_image/reference_run.py \
  --gcc <arm-none-eabi-gcc> --git <git> --freertos <pinned-worktree> \
  --inventory <closed-inventory> --profile CM0|CM0PLUS|CM0PLUSVTOR \
  --mode O0|Og|O2|Os|O3 --output-dir <fresh-external-directory>
```

Output must be fresh, outside the repository and disjoint from the pinned
reference. Original/captured inputs, generated inputs, source membership,
objects before/after both links, terminal command results and artifact
membership/hashes are closed. A failed attempt remains a failed receipt;
retries use new directories.

## Remaining Obligation

Final relocation-aware five-root validation, private retained-byte negative
tests and native/reference final mechanism joins are a separate next slice.
No producer result silently promotes an object-level proof to that scope.
