# Pinned CM3 Reference Final-Twin Producer

This separate, opt-in producer admits only
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default`, in
O0/Og/O2/Os/O3. Its source group is CM3, ARMv7-M, soft/no-FPU, no-MPU,
VTOR1, ordinary AAPCS, priority bits4 and raw BASEPRI16. It never executes
Arm code or supplies a working kernel. No measured PASS is asserted here.

The unchanged reference is FreeRTOS commit
`a50edad08b29052631aa469d4df6e6ec7ff68878`, selected
`portable/GCC/ARM_CM3/port.c` and `portmacro.h`. There is no `portasm.c`
or separate C SVC dispatcher in this port. Actual `port.c` owns all three
transfer roots: local `prvPortStartFirstTask`, global `vPortSVCHandler`
and global `xPortPendSVHandler`. A synthetic provider must not replace one.

Exactly four TUs are compiled directly: pinned port, typed fail-stop kernel
providers, typed consumer and startup. The opaque current-TCB pointer is null
BSS. `vTaskSwitchContext` and `xTaskIncrementTick` fail-stop, not simulate
scheduling. Reset/fault also fail-stop. SysTick remains in vector slot15;
slots11/14 name the strong upstream SVC/PendSV definitions. No image is run.

The generated config includes copied `freeze_base_FreeRTOSConfig.h`, sets
both already-shifted interrupt thresholds to literal16, priority bits4 and
handler installation check1. The generic base's inline infinite-loop assert
is unchanged and enabled. No FP builtins, CMSIS device header or architectural
overrides are synthesized. Numeric facts describe this fixture, not a board.

The existing CM3 checker matches every token in all three owning-object
protocols, including local literal islands, branches, guards and tail NOPs:
O0 exactly1 per root, other modes0. A body/token hash is evidence, not an
oracle. Complete owning-section hashes, mapping symbols and REL records are
recorded with original symbol offsets and `st_size`; pools/padding do not
enlarge a function. Applied final-root relocation proof remains deferred.

Ordinary and emit-relocs final links use the same exact four objects and
script. Actual compile dependencies must equal discovery, and all dependencies
must bind copied/generated/system captures. Managed commands, compiler and
worker identities, DLLs, parser files, pin/worktree identity, source and fixture
memberships, seven ordered object checkpoints and artifact membership/hashes
are retained. Exact bytes or whole-file Git-LF/worktree-CRLF are accepted for
pinned sources; mixed newline or semantic edits are not. Every failed attempt
needs its own retained receipt and fresh retry directory. Late sealing failure
must persist FAIL, never leave a stale PASS.

The producer reuses immutable classic envelope methods, not patched globals.
The exact loaded source buffers and dependencies are captured. Structural
final checks cover ABI, definitions, vector/header facts and same-implementation
load/allocated-section twins, not full final-root instruction semantics.

```text
python -B tools/fixtures/cm3_final_image/reference_run.py \
  --gcc <qualified-arm-none-eabi-gcc> --git <qualified-git> \
  --freertos <clean-pinned-checkout> --inventory <qualified-inventory> \
  --profile CM3 --mode O2 --output-dir <fresh-external-directory>
```

Required global counters stay integer0. Final-root preservation, final native/
reference composition, complete objects, general C/callee/kernel semantics,
runtime stack/EXC_RETURN values, handler/MMIO routing, CPU/board, archives/LTO
and global freeze are not established. Production code, ABI, feature/default
matrix and hardware state are unchanged. Pure controls are not build cells;
actual measurements belong in separately closed execution evidence.
