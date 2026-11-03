# Classic Context Runtime Execution

This first execution cohort is **CM0 on QEMU microbit**, with the actual
Context owner and the unchanged `ARM_CM0` backend. It is not a Cortex-M0+
model, STM32 peripheral simulation, hardware qualification, or evidence for
the other classic CPU profiles. The maintained QEMU 8.2.2 environment has no
separate Cortex-M0+ CPU; G0 execution remains separate work.

The runner uses public Context operations in one consumer and public Fiber V1
operations in the other. Pure Context links omit the legacy shim, Fiber
lifecycle and optional configuration provider. Fiber links add its real
lifecycle and configuration providers, not replacement CPU operations.
Only the memory-map hooks and panic terminal are application integration.
No board access, provisioning or network installation is performed.

## Execution And Evidence

The positive grid uses O2/Os, ordinary and final-linked LTO, direct port objects
and static port archives, and both production hash/map 0/0 and validation 1/1
policies. The startup object supplies weak default exception aliases. Actual
mandatory provider references must extract the strong port handlers even when
those weak aliases already satisfy the vector symbol names. The linker retains
the build-owned exact context and public allocating-consumer expectations.

Each positive firmware initializes `.data` and `.bss`, reads CPUID part `C20`,
checks the active fixed vector source and slots 11/14, starts the second worker
first, performs one self-selection and switches in both directions. Both
workers complete at least sixteen public yields. The dispatcher checks current
identity, its user pointer, Thread-mode first selection, later PendSV IPSR 14
and the PRIMASK critical envelope. Workers check their argument, current
identity, Thread CONTROL/PRIMASK/IPSR, PSP/MSP separation, stack bounds,
external sentinels, canaries and priority readback.

The Thumb-1 probe gives each worker different r4-r11 values, including r9,
then calls the selected public yield API. A separate direct-PendSV request
inside the same seeded probe has no intervening C callee that could mask a
bad register restoration with its own push/pop. It checks those registers,
SP/PSP and a stack cookie after continuation, before restoring its caller's
original callee-saved registers. Each completed probe therefore includes a
public yield and a direct exception-path supplement. This does not redefine
the ordinary-versus-reserved-r9 constructor contract. No FP, MPU or TrustZone
state is involved in this CM0 cohort.

First SVC transfer is established by the real public start, loaded strong
vector, unchanged handler and successful Thread/PSP continuation. The printed
SVC field names vector slot 11; it is not a directly sampled SVC-entry LR/IPSR
trace. Later dispatcher IPSR 14 is sampled during real PendSV execution.
The separate paired O2/Os gate compiles the pinned FreeRTOS reference and
checks generated architecture operations. Execution is not a claim that the
different complete implementations are byte-identical or fully equivalent.

## Rejections And Controls

The fixture defines named cases in `fixture.h`. Applicable cases cover missing
dispatch, NULL first/next results, entry return, pre-start/masked yield,
dispatcher CPU-state disturbance, corrupted canary/EXC_RETURN, and Fiber
double initialization, closed configuration and object/stack overlap.
Separate actual exception requests exercise the pre-start wrong SVC immediate,
a running SVC from PSP and PendSV before runtime start.

Expected panic acceptance requires exactly the specified `PANIC:<code>`
record and exit 64. The deliberate unhandled-UDF case has the distinct
`FAIL:CM0-FAULT` record and exit 65; it is infrastructure classification, not
an acceptable substitute for any expected panic. Semantic oracle failures use
`FAIL:CM0-ORACLE`, a preceding exact hexadecimal `REASON` record, and exit 66.
Timeouts, signals, duplicate or malformed records and a correct marker with
the wrong exit status are failures.

Compiled causal controls target actual PendSV register restoration and common
current publication. They must build and link, then fail the semantic oracle;
an unrelated compile error or CPU fault cannot satisfy them. ELF checks cover
the loaded vector/handler identities, real provider surfaces, current/anchor
ownership, exact cohort expectations and pure-Context dependency separation.

## Running

Use explicit installed tools and an existing isolated WSL QEMU prefix:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools/test_classic_context_runtime.ps1 `
  -ArmGcc $env:ARM_NONE_EABI_GCC `
  -CmsisCore $env:CMSIS_CORE_INCLUDE `
  -FreeRtosRoot $env:FREERTOS_KERNEL_REFERENCE `
  -QemuRoot $env:FIBER_CONTROL_QEMU_ROOT `
  -WslDistro Ubuntu-24.04 -BuildRoot C:/q/absent-job-directory
```

The exact output directory must not exist. Failure artifacts are retained.
Python must be unoptimized and use the pinned ELF reader from the audit
requirements. `-DevelopmentSmoke` is incomplete development evidence, never
a complete-suite qualification. The matrix dispatch selects no development
subset and requires explicit QEMU configuration for execution.

Retain the source/dependency inventory, clean pinned reference identity, tools,
resolved QEMU shared-library hashes, commands, ELFs, maps, disassembly, terminal
records, compiled-control diagnostics and final drift checks. A receipt must
identify its captured bytes; source changes require another applicable run.
Current qualification results belong in `PORT_ARCHITECTURE_AUDIT.md`, not in
an inferred promise derived from this fixture's presence.
