# Fiber

Small cooperative fiber switcher for STM32/Cortex-M projects.

The context switch is requested from Thread mode with `fiber_schedule()` and is
performed by PendSV through an application-provided scheduler hook. The
selected port owns strong `PendSV_Handler()` and `SVC_Handler()` definitions;
the application must not provide competing handlers or wrapper functions. The
active v2 runtime start is FreeRTOS-like: `fiber_start()` enters the first
context through SVC and an exception return.

## Architecture Direction

The five-function cooperative API is the active v2 porting and validation
baseline while CPU context storage is selected-port-owned. `fiber_core.h`
completes `FiberContext` through one selected public type-only port header, and
`FiberEntryFn` is the named entry type with `entry_t` kept as a compatible
alias. Each current port owns its `FiberPortBoot` record, hash implementation,
stack geometry, restore
validation, and first-start preparation. The current physical layout remains
`sp + FiberPortBoot` for compatibility, but `fiber_core.c` and the common
scheduler bridge use only callable port ABI functions and do not dereference
that layout. A future port may therefore change its boot record or use a
hardware-backed integrity implementation without changing the common core.
See `V2_OPAQUE_CONTEXT_CONTRACT.md` for the frozen boundary and migration
sequence. See `V2_RUNTIME_PORT_BOUNDARY_CONTRACT.md` for the active CPU-neutral
eight-function forward ABI, frozen reverse ABI v1, and exclusive selected-port
SVC/PendSV ownership. Both directional ABIs and strong handler ownership are
implemented. The matrix proves CM7 static-archive extraction, vector-slot
resolution, duplicate-handler failure, section-GC retention, and LTO retention.
It also proves the exact selected-port unresolved reverse surface, C-hidden and
generated-assembly-load-only current-slot access, and both runtime ABI v1/v2
mismatch directions. The exact selected-profile/context object-cohort anchor,
build-owned expectation, and stale private-object negative links are active.
The current H7 CubeIDE Debug and Release manifests also compile the expectation
outside the port source group, retain its read-only linker section, and pass the
final-ELF cohort and vector audit. Refreshed H7 board evidence remains the
outstanding validation requirement.

`CONTEXT_FIBER_ARCHITECTURE.md` freezes the post-port-freeze separation of this
runtime into a processor execution-context engine, a portable stackful Fiber
lifecycle, and C++ Task/Kernel policy layers. The existing selected ports become
Context backends; they are not rewritten into direct Boost.Context-style jumps.
The document is a future migration contract only. Current v2 symbols, frame
layouts, handlers, directional ABIs, and validation claims are unchanged.
After that extraction, supporting another processor means adding one complete
Context backend and its conformance evidence; Fiber and C++ kernel sources stay
unchanged. Applications that use only the portable kernel and service APIs are
source-portable across accepted backends; board, HAL, linker, and peripheral
integration remains platform-specific.

The five functions in `fiber_core.h` are the complete portable common API.
Future MPU/unprivileged, SecureContext, or TF-M support may add explicit
selected-port integration headers and sources. Those extensions are not
included by `fiber_core.h`, are absent from ports that do not implement them,
and do not expand the mandatory eight-function common-to-port runtime ABI. Every
production profile must provide a safe default that runs the same feature-blind
application source without any extension call; optional headers are for
deliberate non-portable profile integration only.

`TRUSTZONE_SECURE_CONTEXT_CONTRACT.md` defines the future TrustZone
SecureContext lifecycle: a selected TrustZone port attaches Secure state to a
specific fiber before `fiber_start()`, then owns all Secure save/load work at
switch time. It is a design contract only; no current port exports that API.

This portability guarantee covers the fiber lifecycle and context-switch
mechanics. Code that directly calls PSA, TF-M, Secure gateway, or another
profile-only service still depends on that service. Applications requiring the
same operation across profiles keep it behind a separate application-level
service interface; fiber feature ABIs are not general service APIs.

`CPP_KERNEL_ARCHITECTURE.md` records the future layers above the Context engine:
a portable Fiber lifecycle and a reference C++ scheduler with compile-time
cooperative or preemptive policy, portable synchronization rules, an explicit
ISR reschedule boundary, and lwIP adapters. During v2 port completion that
design continues to consume the existing scheduler hook. Queues, ticks, and
network policy never enter the CPU-port ABI.

`ARM_CM4_MPU` is a complete exact build-selected port after implementation
slice 5. It freezes the pinned FreeRTOS 53-word protected FP context, constructs
an exact per-fiber default MPU image, and owns all eight runtime operations,
strong SVC/PendSV handlers, and unprivileged yield/return services for 8- and
16-region M4F/M7F manifests. PendSV copies basic and optional FP hardware state
into privileged context storage, runs the external scheduler under BASEPRI,
replaces and reads back the per-context MPU image under PRIMASK, then restores
the selected context. Portable-application archive links, exact MPU sections,
cohort identity, vectors, section GC, and normal/LTO modes are compile/ELF
covered. Global auto/profile selection remains deliberately absent, and M4F
and M7F hardware support claims require separate board validation.

`ARM_CM23_NTZ` implementation slices 1-5 freeze the exact privileged,
non-MPU, Non-secure Cortex-M23 context contract from the pinned FreeRTOS NTZ
port. It adds the otherwise missing PSPLIM placeholder word, giving a ten-word
software frame with `EXC_RETURN` at index 1, builds the matching sealed initial
context, adds a strong fail-closed SVC first start, and implements the exact
non-MPU PendSV save/select/restore path plus `runtime_schedule`. The ignored
initial PSPLIM slot contains `stack_base`; every ordinary PendSV save replaces
it with zero without accessing PSPLIM. An exact build-selected M23 manifest now
has static-archive, cohort, vector, section-GC, and normal/LTO ELF coverage.
Auto/profile selection deliberately remains on `transitional_v8m`, and this
profile still has no hardware claim. See
`fiber/port/ARM_CM23_NTZ/non_secure/FREERTOS_PARITY.md`.

`ARM_CM33_NTZ/non_secure` slices 1-4 freeze the corresponding Cortex-M33
Mainline NTZ non-MPU/no-FPU layout, construct its sealed initial context, and
implement a paranoid FreeRTOS-derived SVC first start plus the exact
PSPLIM-aware PendSV save/select/restore path and `runtime_schedule`. The static
archive, strong handlers, vector slots, section GC, and normal/LTO links are
covered. Global auto-selection and a hardware claim remain absent. This keeps
M33F, MPU, SecureContext, and TF-M behavior separate instead of hiding it
behind a permissive generic v8-M path. The exact generated-assembly mapping is
recorded in
`fiber/port/ARM_CM33_NTZ/non_secure/FREERTOS_PARITY.md`.

`ARM_CM33F_NTZ/non_secure` slices 1-4 freeze the separate FP-capable cohort,
implement port-owned FPU setup/readback, strict first-start SVC, and a complete
FP-aware PendSV runtime. FreeRTOS keeps a new FPU task on the same 72-byte
basic initial frame; the port reserves a 212-byte maximum for dynamic
`s16-s31` plus extended hardware state. Hard-float and softfp construction,
SVC, and basic/extended FP PendSV code are paired against the pinned FreeRTOS
source at `-O2/-Os`. The profile is build-selected only and has
`FIBER_PORT_RUNTIME_SELECTABLE == 1`: it exports strong `SVC_Handler` and
`PendSV_Handler` plus all eight forward operations. It remains hardware
unvalidated and intentionally excludes MPU, SecureContext, TF-M, MVE, PAC,
and BTI APIs. See
`fiber/port/ARM_CM33F_NTZ/non_secure/FREERTOS_PARITY.md`.

## Project Setup

Add the repository root to the include path, then include the public API:

```c
#include "fiber/fiber_core.h"
```

Compile the common runtime sources into the application:

```text
fiber/fiber_core.c
fiber/fiber_runtime_state.c
fiber/fiber_panic.c
```

The common runtime and selected port include the internal
`fiber/fiber_runtime_port_abi.h` reverse boundary themselves; it is not a
separate translation unit.

Then compile exactly one matching port source group:

```text
Cortex-M0/M0+: fiber/port/ARM_CM0/fiber_port.c
               fiber/port/ARM_CM0/fiber_port_boot.c
               fiber/port/ARM_CM0/fiber_port_exception.c
Cortex-M3:     fiber/port/ARM_CM3/fiber_port.c
               fiber/port/ARM_CM3/fiber_port_boot.c
               fiber/port/ARM_CM3/fiber_port_exception.c
Cortex-M3 MPU: fiber/port/ARM_CM3_MPU/fiber_port.c
               fiber/port/ARM_CM3_MPU/fiber_port_boot.c
Cortex-M4F/M7F MPU:
               fiber/port/ARM_CM4_MPU/fiber_port.c
               fiber/port/ARM_CM4_MPU/fiber_port_boot.c
Cortex-M4/F:   fiber/port/ARM_CM4/fiber_port.c
               fiber/port/ARM_CM4/fiber_port_boot.c
               fiber/port/ARM_CM4/fiber_port_exception.c
Cortex-M7/F:   fiber/port/ARM_CM7/r0p1/fiber_port.c
               fiber/port/ARM_CM7/r0p1/fiber_port_boot.c
               fiber/port/ARM_CM7/r0p1/fiber_port_exception.c
v8-M fixture:  fiber/port/transitional_v8m/fiber_port_transitional_v8m.c
               fiber/port/transitional_v8m/fiber_port_boot.c
               fiber/port/transitional_v8m/fiber_port_exception.c

M23 NTZ runtime:
               fiber/port/ARM_CM23_NTZ/non_secure/fiber_port_types.h
               fiber/port/ARM_CM23_NTZ/non_secure/fiber_port_boot_types.h
               fiber/port/ARM_CM23_NTZ/non_secure/fiber_portmacro.h
               fiber/port/ARM_CM23_NTZ/non_secure/fiber_port.c
               fiber/port/ARM_CM23_NTZ/non_secure/fiber_port_boot.c

M33 NTZ full build-selected runtime source group:
               fiber/port/ARM_CM33_NTZ/non_secure/fiber_port_types.h
               fiber/port/ARM_CM33_NTZ/non_secure/fiber_port_boot_types.h
               fiber/port/ARM_CM33_NTZ/non_secure/fiber_portmacro.h
               fiber/port/ARM_CM33_NTZ/non_secure/fiber_port_boot.h
               fiber/port/ARM_CM33_NTZ/non_secure/fiber_port_private.h
               fiber/port/ARM_CM33_NTZ/non_secure/fiber_port.c
               fiber/port/ARM_CM33_NTZ/non_secure/fiber_port_boot.c

M33F NTZ full build-selected FPU runtime source group:
               fiber/port/ARM_CM33F_NTZ/non_secure/fiber_port_types.h
               fiber/port/ARM_CM33F_NTZ/non_secure/fiber_port_boot_types.h
               fiber/port/ARM_CM33F_NTZ/non_secure/fiber_portmacro.h
               fiber/port/ARM_CM33F_NTZ/non_secure/fiber_port_boot.h
               fiber/port/ARM_CM33F_NTZ/non_secure/fiber_port_private.h
               fiber/port/ARM_CM33F_NTZ/non_secure/fiber_port.c
               fiber/port/ARM_CM33F_NTZ/non_secure/fiber_port_boot.c
```

Every build-selected target must also compile this source separately from any
precompiled selected-port archive, using the same selected private include
path and CPU/ABI flags:

```text
fiber/port/fiber_port_context_cohort_expectation.c
```

Keep its input section in a read-only linker output section:

```ld
KEEP(*(.fiber_port_context_cohort_expectation))
```

The selected runtime object defines the exact profile/context symbol; boot,
exception, and the build-owned expectation object retain matching relocations.
That identity includes the implemented NVIC priority-bit count and every bit of
the effective scheduler BASEPRI threshold, in addition to frame, FPU, security,
and selected-port traits. A threshold or priority-width mismatch is therefore
a link-time cohort mismatch, not merely a startup policy difference.
This makes both mixed private objects and a complete precompiled port archive
from a different exact cohort fail to link. Without the separately compiled
expectation plus `KEEP`, the latter whole-archive compatibility check is not
active. This guard does not identify arbitrary source revisions that preserve
the same declared exact cohort identity.

The current STM32H7 host application tree, which lives outside this repository,
implements this rule in both CubeIDE Debug and Release manifests. Both final
ELFs have one exact CM7 cohort, one four-byte read-only expectation section,
strong selected-port SVC/PendSV handlers, and vector slots 11/14 resolving to
those handlers. This is integration evidence, not a hardware runtime claim.

Do not add every port source directory to a production target. The compile
matrix deliberately compiles selector-guarded alternatives to audit selection,
then relocatably links the result to prove a single complete port ABI.
`transitional_v8m` is a compile-only bring-up fixture, not a production port.
It will be deleted when concrete v8-M and ARMv8.1-M ports replace it.

The port header boundary is split in two layers: `fiber/port/fiber_port_select.h`
selects the Cortex-M profile, while `fiber/port/fiber_port_selected.h` completes
only the selected public `FiberContext` storage type. CPU traits, constants, and
inline mechanics live in the concrete selected `fiber_portmacro.h`; it is
private to selected port sources and deliberate low-level integration or test
code. Common runtime code uses the opaque callable `fiber_port_runtime_abi.h`
boundary and does not include the selected CPU contract.

Cross-file implementation declarations are additionally isolated in the
concrete port's `fiber_port_private.h`. `fiber_core.c` now calls exactly the
eight CPU-neutral operations in `fiber_port_runtime_abi.h`; it does not transport
MSP values or call selected-port-private startup, validation, scheduler, SVC, or
PendSV helpers. This activation changes first-start ordering and requires a
fresh H7 hardware run before restoring the runtime-validation claim.

`fiber_port_private.h` is included only by that concrete profile's own role
files (`fiber_port.c`, `fiber_port_boot.c`, `fiber_port_exception.c`, and any
profile-specific assembly source). It is not selected by
`fiber_port_selected.h` and is not part of the user API. A capable profile keeps
mandatory MPU, CONTROL, PSPLIM, SecureContext, MVE, or security-domain mechanics
behind the same eight runtime operations in its private implementation. A
separate optional feature ABI exists only when board/profile integration needs
to customize the safe profile default.

The inverse internal dependency is frozen by
`V2_RUNTIME_PORT_BOUNDARY_CONTRACT.md`: selected ports may reach common
scheduler/current state only through `fiber_runtime_port_abi.h` v1. Optional
MPU, SecureContext, and TF-M APIs are separate selected-port headers and
sources. Ports without a feature export no placeholder API, and `fiber_core.h`
never includes those extensions. Context-mutating extensions link the separate
common lifecycle module documented in the boundary contract; base ports do not.
Portable application translation units include only `fiber_core.h`. Board,
linker, Secure-image, or profile integration may include an extension header to
replace a selected profile's default policy, accepting that this integration
code is not portable to profiles without that extension.
The selected `fiber_port_types.h` reached through `fiber_core.h` completes only
opaque `FiberContext` storage and must not expose feature operations. Concrete
port extension directories are private integration include paths, not part of
the exported portable include surface.

The common runtime sources also compile without CMSIS. Selected ports provide
the required CPU barrier and terminal panic-wait operations through the callable
ABI, so device headers and special-register access stay out of `fiber_core.c`,
runtime state, and the default panic fallback.

`tools/fixtures/portable_application.c` is the build-contract proof for the
portable tier. The compile matrix requires that it directly include only
`fiber_core.h`, contain no profile conditional or selected-port name, reference
exactly the five public API symbols, and link unchanged against every selected
build profile without an optional feature header.

The conservative default also requires the integration to define both selected
general-registers-only address-map hooks:

```c
int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end);
int fiber_addr_plausible_code(uintptr_t address);
```

They must accept only valid persistent RAM ranges and executable code addresses
for the actual linker map. `fiber_init()` always calls them for context storage,
the supplied PSP stack, and the entry point. The default does not call them
from the save/restore switch path. Define
`FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1` for a validation build that also
checks runtime context/stack addresses and every saved stacked PC. Hook
implementations must not use FP/MVE, allocate, block, or call fiber APIs.
Defining `FIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=1` enables weak accept-any
defaults for constrained bring-up only; it is not a production safety setting.

`FiberContext` objects and their PSP stack buffers require persistent storage.
Use static, global, or application-owned storage that outlives every context
restore. Automatic local buffers are intentionally not supported; reclaimable
storage is valid only after the application has permanently stopped that
context.

The public API is exactly `fiber_init()`, `fiber_current()`,
`fiber_scheduler_set_pick_next()`, `fiber_start()`, and `fiber_schedule()`.
Names such as `fiber_yield()`, `fiber_sleep_until()`, and `fiber_wake()` are
future application-scheduler design examples. They are not current library
exports.

For automatic ARMv7E-M public type selection, include the device CMSIS header
(normally the application's `main.h`) before `fiber_core.h`; it provides
`__CORTEX_M` so the facade can distinguish the concrete M4 and M7 source
groups. A build-selected integration supplies its selected type header through
the build include path instead.

The compile/link-covered `ARM_CM3_MPU` profile is build-selected only. Its
exact manifest defines `FIBER_PORT_BUILD_SELECTED=1` and
`FIBER_PORT_ARMV7M=1`, places `fiber/port/ARM_CM3_MPU` before `fiber/port` on
the include path, and compiles only the two MPU source files listed above.
It also requires the privileged/unprivileged linker ranges, exact 32-byte
current-context aperture, and cohort expectation `KEEP` contract documented in
`fiber/port/ARM_CM3_MPU/FREERTOS_PARITY.md`. Auto/profile selection never
infers MPU or unprivileged policy from `__MPU_PRESENT`. This profile has no
hardware support claim until its board isolation suite passes.

The compile/link-covered `ARM_CM4_MPU` profile uses the same exact
build-selected workflow. Its manifest defines `FIBER_PORT_BUILD_SELECTED=1`,
`FIBER_PORT_ARMV7EM=1`, and
`FIBER_PORT_CM4_MPU_TOTAL_REGIONS=8` or `16`; places
`fiber/port/ARM_CM4_MPU` first on the include path; and compiles only its two
port sources. Cortex-M4F and Cortex-M7F use distinct exact cohort identities,
and the M7 form retains the conservative r0p1 BASEPRI workaround. The required
MPU linker ranges and isolation contract are documented in
`fiber/port/ARM_CM4_MPU/FREERTOS_PARITY.md`. Auto/profile selection does not
infer this protected profile from MPU presence. Neither core has a hardware
support claim until its own isolation and FP switch suite passes.

The compile/ELF-covered `ARM_CM23_NTZ/non_secure` profile is also
build-selected only. Its manifest defines `FIBER_PORT_BUILD_SELECTED=1` and
`FIBER_PORT_ARMV8M_BASELINE=1`, places
`fiber/port/ARM_CM23_NTZ/non_secure` before `fiber/port` on the include path,
and compiles only `fiber_port.c` and `fiber_port_boot.c` with the common
runtime. The application separately compiles
`fiber_port_context_cohort_expectation.c` with the same private include path
and retains its input section with `KEEP`. The matrix proves static-archive
extraction, one exact cohort, strong handlers in vector slots 11/14,
section-GC, normal/LTO modes, and duplicate-handler rejection. Auto/profile
selection remains deliberately transitional, and no M23 hardware support claim
is made.

The v2 target is FreeRTOS-style ownership: each concrete selected port exports
the complete CPU interface for frame setup, first start, PendSV/SVC handlers,
exception setup, FPU traits, and architecture-specific critical-section policy.
Common runtime files should not keep architecture-specific fallback switch
assembly or CPU capability decisions for ports that are claimed as supported.
Configuration ownership, selected-port integration values, and global fault
policy from `fiber/fiber_platform_policy.h` are documented in
`FIBER_SETTINGS.md`.

Port selection defaults to automatic detection from compiler ARM architecture
macros. Production builds may select the profile explicitly, for example:

```c
#define FIBER_PORT_PROFILE FIBER_PORT_PROFILE_ARMV7EM
```

The selectable profile names are `FIBER_PORT_PROFILE_ARMV6M`,
`FIBER_PORT_PROFILE_ARMV7M`, `FIBER_PORT_PROFILE_ARMV7EM`,
`FIBER_PORT_PROFILE_ARMV8M_BASELINE`, `FIBER_PORT_PROFILE_ARMV8M_MAINLINE`, and
`FIBER_PORT_PROFILE_ARMV81M_MAINLINE`. Leave `FIBER_PORT_PROFILE` undefined for
auto-detection. When compiler ARM architecture macros are available, an
explicit profile must match them. `FIBER_PORT_SELECTION_ALLOW_MISMATCH` is only
for unusual toolchains or bring-up experiments where the compiler macros are
missing or known to be wrong. After the direct trampoline removal, every
selected profile must provide an SVC first-start symbol. STM32H7/Cortex-M7 is
the primary hardware-observed path and now builds through the concrete
`ARM_CM7/r0p1` source group. The current hardening changes still require the
documented board rerun; every other profile remains compile/link-covered only
until its own hardware validation is recorded.

`fiber_start()` initializes and validates PendSV/SVCall priority automatically.
Exception setup is private selected-port work performed through the frozen
runtime prepare boundary; applications must not call port diagnostics directly.

## Basic Example

```c
#include "app_core.h"
#include "main.h"

#include "fiber/fiber_core.h"

enum { STACK_SZ = 1024 };

__attribute__((aligned(8))) static uint8_t stack1[STACK_SZ];
__attribute__((aligned(8))) static uint8_t stack2[STACK_SZ];
__attribute__((aligned(8))) static uint8_t stack3[STACK_SZ];

static FiberContext f1;
static FiberContext f2;
static FiberContext f3;

static uint32_t counter1 = 0;
static uint32_t counter2 = 0;
static uint32_t counter3 = 0;

static FIBER_SCHEDULER_HOOK_ATTR
FiberContext *pick_next(FiberContext *current, void *)
{
	if (current == NULL) {
		return &f1;
	}

	if (current == &f1) {
		return &f2;
	}

	if (current == &f2) {
		return &f3;
	}

	if (current == &f3) {
		return &f1;
	}

	return &f1;
}

void fiber1_entry(void*)
{
	for (;;) {
		counter1++;
		fiber_schedule();
	}
}

void fiber2_entry(void*)
{
	for (;;) {
		counter2++;
		fiber_schedule();
	}
}

void fiber3_entry(void*)
{
	for (;;) {
		counter3++;
		fiber_schedule();
	}
}

void app_main(void)
{
	fiber_init(&f1, stack1, stack1 + sizeof(stack1), fiber1_entry, (void*)1);
	fiber_init(&f2, stack2, stack2 + sizeof(stack2), fiber2_entry, (void*)2);
	fiber_init(&f3, stack3, stack3 + sizeof(stack3), fiber3_entry, (void*)3);

	fiber_scheduler_set_pick_next(pick_next, NULL);

	fiber_start();

	for (;;) {
	}
}
```

`fiber_scheduler_set_pick_next()` must be called from Thread mode before
`fiber_start()`. A `NULL` hook traps with `'K'`; changing the hook after the
runtime-owned current context is published traps with `'k'`. `fiber_start()`
requires a configured hook and calls it once with `current == NULL`; the hook
must return the first initialized `FiberContext`. A missing hook traps with
`'K'`, and a `NULL` first context traps with `'N'`.

The scheduler callback is part of the exception-handler ABI. Define every hook
with `FIBER_SCHEDULER_HOOK_ATTR`. The first call runs from Thread mode before
SVC; later calls run from PendSV on MSP. A hook must not execute floating-point,
MVE, or other extended-context instructions, because the indirect function
pointer cannot make GCC propagate `general-regs-only` automatically. The hook
must also remain bounded, non-blocking, non-allocating, non-throwing, and must
not call `fiber_schedule()` recursively. It may use a critical section only if
it restores `PRIMASK`, `FAULTMASK`, `BASEPRI`, and `CONTROL` exactly before
returning; the runtime snapshots and validates those registers around every
first and PendSV scheduler call. The same restrictions apply to every function
reachable from the hook, not only to the top-level thunk.

`fiber_start()` first performs the common `K/k` lifecycle checks. The selected
port then validates and prepares privileged Thread/MSP state, PendSV/SVCall,
interrupt masks, CPU policy, and the startup MSP plan. The port-protected
scheduler call selects and validates the first context, common runtime publishes
it through the frozen reverse ABI, and the port performs the final SVC transfer.
The function does not return. The first scheduler hook call is protected with
the same port scheduler critical-section policy as PendSV: BASEPRI on
BASEPRI-capable ports, or saved PRIMASK on baseline ports. `fiber_start()`
resets the first-start CPU state to privileged Thread/MSP, optionally rewinds
MSP, executes
`svc #FIBER_SVC_START_NUMBER`, and the SVC handler enters the first fiber by
exception return on PSP. The helper clears any pending PendSV immediately before
enabling interrupts for SVC, so a stale scheduler exception cannot run before
the first PSP context exists. There is no direct trampoline fallback.

`fiber_current()` returns the runtime-owned current fiber. `fiber_schedule()`
does not choose a task by itself. It enters PendSV, saves the current context,
calls the configured scheduler bridge under the port critical section, and
restores the returned context. A missing hook, `NULL` returned context,
uninitialized context, corrupted boot seal, out-of-bounds saved stack pointer,
invalid EXC_RETURN, or insufficient software/hardware restore-frame headroom
traps through `FIBER_REQUIRE`. Idle must be represented by a real initialized
`FiberContext`, not by returning `NULL`.

On privileged non-MPU ports, `fiber_schedule()` additionally requires exact
privileged Thread/PSP state (`CONTROL[1:0] == 0b10`) before writing
`PENDSVSET`; a violated privilege or stack-selection invariant traps with
`'l'`. MPU/unprivileged ports use their selected SVC request path instead.

Save preflight and restore-target validation are mandatory and have no
performance-disable switch. PendSV validates the running context and live PSP
before reading its metadata or saving it; every scheduler-selected target is
validated once before restore. `EXC_RETURN` must match one of the exact encodings allowed by
the selected port; checking only the Thread/PSP bits is not sufficient. The
saved hardware frame must also contain `xPSR.T`, stacked Thread-mode IPSR state,
a PC with bit 0 clear, and enough space for the optional `xPSR.STACKALIGN` word.
When `FIBER_STACK_CANARY=1`, the low-stack canary is checked on every scheduler
selection independently of PSPLIM availability. The default also recomputes the
full immutable boot-record hash before each restore. A performance build may
disable that hash only explicitly; its fast check still validates boot-record
guards and structural relationships before any canary or saved-frame memory is
read. Restore validation also checks that the saved stacked PC is a selected
port-plausible executable address, in addition to its architectural frame bits.

The concrete CM7 PendSV verifies Handler identity and the complete active
`EXC_RETURN` encoding before saving a source context. If the interrupted Thread
context did not use PSP, or any other exception-return encoding is present, a
pre-start or foreign PendSV traps with `'j'` instead of saving invalid state.

Before writing the source software frame, PendSV also checks that the live PSP
is inside the current fiber stack bounds and has enough headroom for the core
frame plus any high-FP save. If not, it traps with `'d'` before writing below
`stack_base`.

## FPU Stress Example

Use floating-point work only when you explicitly want to test FPU save/restore
and the build is configured with the expected FPU compiler flags.

```c
void fiber_fpu_stress_entry(void*)
{
	volatile double acc = 0.0;

	for (;;) {
		acc += 1.0;
		fiber_schedule();
	}
}
```

## Exception Handlers

The selected port directly defines naked strong `SVC_Handler()` and
`PendSV_Handler()` symbols. The startup vector table may retain its normal weak
aliases; the selected strong definitions override them at link time. Remove or
exclude CubeMX/application strong definitions for these two handlers. A
competing definition is an intentional multiple-definition link failure.

The SVC handler validates the original handler LR/EXC_RETURN, MSP frame,
configured SVC instruction, and first restore context. PendSV preserves the
original EXC_RETURN while saving current state and restoring the context chosen
by the scheduler hook. There is no wrapper/direct routing mode. Defining any
removed `FIBER_*_WIRED` or `FIBER_*_VECTOR_DIRECT` macro is a compile error.

ABI-sensitive common functions and scheduler hooks use the canonical
`FIBER_API_ATTR_SENSITIVE` plus `FIBER_GENERAL_REGS_ONLY` bundle. If an
integration globally enables function instrumentation, stack protection,
profiling, or sanitizers, selected-port translation units must add equivalent
counter-options: `-fno-instrument-functions`, `-fno-stack-protector`,
`-fno-profile-arcs`, `-fno-test-coverage`, `-fno-sanitize=all`, and
`-mgeneral-regs-only`. CMSIS `always_inline` helpers cannot inherit a caller's
function attributes, so source attributes alone cannot prove the full port
call graph. The matrix audits both layers under adversarial compiler flags.

## Safety Defaults

- `FIBER_FPU_LAZY = 0`
- `FIBER_STACK_CANARY = 1`
- `FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH = 1`
- `FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH = 0`
- `FIBER_CLEAR_STICKY_FAULT_STATUS_ON_START = 0`
- `FIBER_ENABLE_CONFIGURABLE_FAULTS = 1`
- SVC first-start is mandatory for runtime-supported ports
- DSB/ISB context and PendSV-request barriers are mandatory port behavior
- FPU ports enable and read back CP10/CP11 before first start
- stack alignment, EXC_RETURN, FPCA handling, and canary encoding are
  selected-port/runtime facts, not user settings

For full linker-map validation set both
`FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH` and
`FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH` to `1`. A production integration may
set both to `0` only after `fiber_init()` has established immutable trusted
metadata; the mandatory structural, canary, PSP, saved-frame, EXC_RETURN, xPSR,
and Thumb-PC checks remain active.

`FIBER_VALIDATE_SCHEDULED_CONTEXT` and `FIBER_VALIDATE_CURRENT` were removed.
Defining either obsolete switch is a compile error because current ownership
and restore-context validation are mandatory invariants.

`fiber_schedule()` is a Thread-mode API. Calling it from an interrupt traps
through `FIBER_REQUIRE`. A real scheduler jump requires `PRIMASK == 0`, so the
switch cannot be silently delayed out of a masked interrupt region. On cores
with BASEPRI, a real scheduler jump also requires `BASEPRI == 0`. On cores with
FAULTMASK, `FAULTMASK` must also be clear.

The selected port's private start preparation, invoked by public
`fiber_start()`, runs the runtime exception setup check by default. The check
verifies:

- PendSV priority reads back as the lowest priority;
- SVCall priority reads back as highest priority;
- vector table entries route PendSV and SVC to the expected handlers;
- the selected port scheduler BASEPRI threshold matches the implemented NVIC
  priority bits;
- `AIRCR.PRIGROUP` is compatible with the scheduler `BASEPRI` threshold;
- affected Cortex-M7 r0p0/r0p1 cores require
  the always-enabled workaround owned by the concrete `ARM_CM7/r0p1` port;
- unvalidated v8-M Baseline/Mainline, v8.1-M, TrustZone bank targeting, MVE,
  and PAC/BTI scenarios require an explicit `FIBER_ALLOW_UNVALIDATED_*` opt-in
  before runtime use.

The vector check requires slots 11 and 14 to resolve directly to the selected
port's strong `SVC_Handler()` and `PendSV_Handler()`. SVC vector validation is
mandatory because SVC is the only first-start path. The SVC start path also
checks at runtime that the instruction is the configured
`SVC #FIBER_SVC_START_NUMBER`; a wrong SVC dispatch traps with `'u'`, and an
SVC that returns to `fiber_port_start_first_context()` traps with `'y'`.

The handler-side scheduler bridge follows FreeRTOS-style critical-section
discipline: BASEPRI-capable ports raise `BASEPRI` around the hook, while
BASEPRI-less ports save `PRIMASK`, disable interrupts, call the hook, and
restore `PRIMASK`. Returning with changed `PRIMASK`, `FAULTMASK`, `BASEPRI`, or
`CONTROL` is a panic condition; PSPLIM-owning ports also preserve and validate
`PSPLIM` across the callback.

The v8-M feature policy remains intentionally strict for future ports. The
transitional M23/M33/M55/MVE-FP profiles have compile-covered SVC first-start
mechanics, but runtime use remains policy-gated until the extra context state
their FreeRTOS ports require is implemented and validated. The separate exact
build-selected M23 and M33 NTZ ports do have complete strong SVC/PendSV runtime
objects, but remain hardware-unvalidated and do not make the broader
transitional profile safe:

```c
#define FIBER_ALLOW_UNVALIDATED_ARMV8M_BASELINE_RUNTIME 1
#define FIBER_ALLOW_UNVALIDATED_ARMV8M_MAINLINE_RUNTIME 1
#define FIBER_ALLOW_UNVALIDATED_ARMV81M_RUNTIME 1
#define FIBER_ALLOW_UNVALIDATED_TRUSTZONE_RUNTIME 1
#define FIBER_ALLOW_UNVALIDATED_MVE_RUNTIME 1
#define FIBER_ALLOW_UNVALIDATED_PACBTI_RUNTIME 1
```

Use those only for bring-up experiments after the selected port policy is
understood. They do not add FreeRTOS-level PSPLIM/CONTROL/secure-context/PAC-key
handling.

## H7 Lazy-FPU Mode

The STM32H7 / Cortex-M7 validation app previously passed long-running
switch/FPU stress with lazy stacking enabled:

```c
#define FIBER_FPU_LAZY 1
```

This remains an opt-in performance policy. Context barriers and PendSV request
serialization cannot be disabled. Re-run board validation after changing FPU
policy or compiler FP options.

## Portability Notes

The STM32H7 / Cortex-M7 path is the primary validation target. The core switch
matches the FreeRTOS PendSV pattern: save `r4-r11`, preserve `EXC_RETURN`, run
on PSP, and conditionally save `s16-s31` when an extended FP frame is active.
Auto selection maps STM32H7/Cortex-M7 to
`FIBER_PORT_NAME == "ARM_CM7/r0p1"`; Cortex-M4/M4F uses the separate concrete
`ARM_CM4` source group.

FreeRTOS routes Cortex-M7 through a dedicated `ARM_CM7/r0p1` port. The concrete
fiber CM7 scheduler-driven PendSV path raises `BASEPRI` around the scheduler
bridge, then restores the previous `BASEPRI` value before restoring the selected
fiber. The concrete port always enables a FreeRTOS-style guard around
handler-side `BASEPRI` writes for affected Cortex-M7 r0p1 parts. The
fiber helper preserves and restores the previous `PRIMASK` instead of blindly
executing `cpsie i`, so SVC/start critical sections stay closed while the
errata-safe `BASEPRI` write is serialized. Runtime startup checks that CPUID is
Cortex-M7 and keeps the affected r0p0/r0p1 policy fail-closed. The compile matrix
builds this branch, but real affected hardware validation is still required
before claiming r0p1 parity.

The initial synthetic exception frame stores `PC` with bit 0 clear. Thumb state
is carried by `xPSR.T`.

The ARMv7E-M first-start path enters that synthetic frame through SVC, not a
direct branch. It
requires a configured scheduler hook, requires no active interrupt masks,
verifies MSP setup, validates the restore context, checks SVC provenance,
exact incoming `EXC_RETURN`, stacked Thread/Thumb state, MSP-frame alignment,
and opcode/immediate value. It clears pending PendSV before opening interrupts
for SVC, enables IRQ and fault exceptions, clears BASEPRI in the SVC handler,
then restores PSP and returns through the selected context's `EXC_RETURN`.

The concrete CM7 port fixes its initial `EXC_RETURN` at `0xFFFFFFFDu`; it is not
an application override. The non-production v8-M fallback uses explicitly
scoped `FIBER_TRANSITIONAL_V8M_*` bring-up inputs, which do not provide
production TrustZone or Non-secure support.

Cortex-M23, no-FPU Cortex-M33, and FPU Cortex-M33F each have an exact
build-selected Non-secure non-MPU runtime profile with
compile/generated-assembly/ELF evidence but no hardware validation. Cortex-M55, MVE,
TrustZone/SecureContext companion, TF-M, and PAC/BTI scenarios remain
unsupported until their distinct FreeRTOS-style context mechanics are
implemented and hardware-validated.
`FIBER_PORT_USES_PSPLIM_REGISTER`
separates PSPLIM register access from the broader architecture profile so M23
security-domain variants cannot accidentally write a missing or wrong-bank
PSPLIM register when those ports are implemented.

On Cortex-M0/M0+, `FIBER_REWIND_MSP` may need to be disabled unless the platform
provides a reliable initial MSP source.

## Validation

Run the compile-only Cortex-M matrix after changing target gates or assembly:

```powershell
.\tools\compile_matrix.ps1
```

This compiles and relocatable-links every selected profile and verifies exactly
one definition of each port ABI symbol. It covers selector and build-selected
modes, strong selected-port handler ownership, archive extraction, vector-slot
resolution, section GC and LTO, v8-M bring-up scenarios, adversarial compiler
flags, and negative settings contracts. Before those checks it also compiles
the real pinned FreeRTOS portable objects and the matching Fiber objects with
the same compiler/CPU/FPU flags, then compares their generated SVC, PendSV,
masking, frame-transfer, FP, and MPU instruction order. The exact scope and all
accepted differences are normative in `FREERTOS_ASM_PARITY.md`. Set
`FREERTOS_KERNEL_REFERENCE` when the pinned checkout is not in the workspace
default `_reference/FreeRTOS-Kernel` location. Compile/disassembly coverage does
not replace hardware tests or promote a transitional profile to a
runtime-supported port.

See `FIBER_SETTINGS.md` for settings ownership, `DECISIONS.md` for the current
context-switch decision log,
`H7_RUNTIME_VALIDATION.md` for the STM32H7 hardware validation checklist, and
`FREERTOS_SUPPORT_PLAN.md` for the roadmap toward FreeRTOS-style Cortex-M
CPU-port support. See `FREERTOS_ASM_PARITY.md` for the paired generated-object
proof and rationale IDs.
