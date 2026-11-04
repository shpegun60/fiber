# Native CM3 Final-Twin Producer

## Scope

The first CM3 final-image slice extends the explicit native producer's
selection, not runtime or assembly. It admits exactly
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default` at the five
ordinary modes O0/Og/O2/Os/O3. Compiler flags begin with
`-mcpu=cortex-m3 -mthumb -mfloat-abi=soft` and the selected optimization.
Hard/softfp, FP instructions/attributes, MPU, security, changed R9 ABI,
other priority/threshold configurations and LTO are outside this gate.

The native interface remains nine TUs: three common Context units, three
concrete CM3 port units, one application-owned cohort expectation, the
consumer and startup. Transfer roots remain in index-3 `fiber_port.c`;
boot and exception validation retain their actual separate providers.
No kernel callbacks are synthesized as successful running services.

The fixed admission model requires source group CM3, ARMv7-M, VTOR present,
NVIC priority bits4, BASEPRI16 and ordinary AAPCS, with the exact defines:

```text
FIBER_PORT_ARMV7M=1
FIBER_PORT_BUILD_SELECTED=1
FIBER_SCHEDULER_BASEPRI=16
```

Final soft-float ABI bits must be exactly `0x200`; a generic non-CM0
hard-FP fallback is forbidden. Prelink attributes require Cortex-M3's
7-M/v7/Microcontroller/Thumb-2 facts without FP/VFP/MVE/PAC/BTI claims.
The build uses its captured `core_cm3.h`, not an M4/M7 device fixture.

## Evidence Boundary

Selection must capture every profile-specific helper before loading it.
The existing CM0 and classic-FP routes remain explicit and unchanged;
unknown profiles do not fall through to an arbitrary admission model.
The immutable captured inventory supplies authoritative source/cohort facts.
The new pure helper does not infer a target from a suspect object's bytes.

The three complete native protocols come from the existing fixed CM3
checker, not learned hashes or selected instruction subsequences. Original
literal islands, every instruction and branch, and mode-specific tail NOPs
remain bound: O0 exactly one, other ordinary modes zero. No shared decoder
allowlist is widened by this producer extension.

The ordinary and emit-relocs images link the same exact nine objects and
script. Full dependency/tool/parser/input hashes, seven ordered object
checkpoints, maps/provider origins, allocated/load-image twins, strong
handlers/vectors, cohort expectation and VTOR startup literal checks remain
the producer's responsibility. Artifact finalization must fail closed.

This producer alone does not establish relocation-aware CM3 final-root
preservation or native/reference final mechanism composition. The pinned
FreeRTOS CM3 reference adapter, its separate final reader and a 3+3-root
mechanism join are subsequent gates. Its static/local first-start root
and synthesized EXC_RETURN must not be confused with CM0's C dispatcher
or CM4/CM7 FP paths.

## Invocation And Limits

```text
python -B tools/fixtures/classic_final_image/run.py \
  --gcc <qualified-arm-none-eabi-gcc> --cmsis <CMSIS-Core-Include> \
  --inventory <qualified-captured-inventory> \
  --profile CM3 --mode O2 --output-dir <fresh-external-directory>
```

Measured PASS counts belong in the architecture audit only after actual
execution. Pure model controls are not build cells or ELF mutations.
Required global counters stay integer zero. General C/callee/kernel
semantics, executed MMIO/handler routing, other cohorts, archives/final LTO,
CPU/board and global freeze remain unproved. No production code, ABI,
feature admission, default matrix or hardware state changes. Local evidence
must not be relabelled as hosted exact-commit CI or hardware validation.
