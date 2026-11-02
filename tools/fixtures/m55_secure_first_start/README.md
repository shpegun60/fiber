# C55S Staged First Start

This maintained test executes two real AN547 images with the staged C55S
first-start component, not a generic Fiber scheduler. No PendSV execution, return SVC72,
eight-operation adapter provider, or public runtime-profile promotion is supplied
or qualified. The fixture task entry reports and stops without returning.

Run from the Fiber repository with an existing ARM GCC and the explicitly supplied
isolated WSL QEMU tree:

```powershell
./tools/test_m55_secure_first_start.ps1 `
  -ArmGcc '<existing>/arm-none-eabi-gcc.exe' `
  -CmsisCore '<existing>/CMSIS/Include' `
  -QemuRoot '/home/ruslan/.cache/fiber-qemu-control-owner-20261101' `
  -WslDistro Ubuntu-24.04 `
  -FreeRtosRoot '<existing>/FreeRTOS-Kernel' `
  -BuildRoot $env:TEMP
```

`BuildRoot` and `FreeRtosRoot` are optional. Missing tools are failures, not skips.
The runner performs no installation or board access. `LD_LIBRARY_PATH` and QEMU's
`-L` point into the supplied tree. Only the existing RSP transport class and QEMU
inventory script are reused; architectural oracles are local to this fixture.

## Inventory

The complete run has 568 QEMU launches:

* Ten Fiber modes: O2/Os direct, LTO, archive with GC, archive with GC plus LTO,
  and hostile instrumentation.
* Each mode executes 53 Fiber cases and three compiled actual-source mutation
  controls. Each mutation must compile and link, then be rejected at its precise
  execution oracle. A build failure does not satisfy a negative control.
* Four direct/LTO modes also execute two pinned-reference cases.

Development selectors deliberately set `CompleteSuite` false. The complete run
uses none of `DevelopmentModes`, `DevelopmentCases`, or `DevelopmentReferenceOnly`.
No hostile option is filtered out. Normal and hostile production objects must
have exactly the same undefined dependencies and no hidden instrumentation
counters. A separately compiled annotation-removal control must demonstrate an
instrumentation escape.

## Actual Sources And Explicit Differences

The reference is a clean checkout of FreeRTOS-Kernel
`a50edad08b29052631aa469d4df6e6ec7ff68878`. Its actual M55 non-MPU, non-FP,
TrustZone `port.c`, `portasm.c`, `secure_init.c`, `secure_context.c`, and
`secure_context_port.c` are compiled without rewriting. The reference-only
allocator supplies one bounded 72-byte allocation for the 64-byte request and
eight-byte seal; it is fixture policy, not the reference's general heap policy.
Only the pinned naked assembly parameter functions receive
`-Wno-unused-parameter`; code-generation options remain unchanged.

The real reference startup uses SVC102, transfers handle/PSPLIM/EXC_RETURN, then
`adds r0, #32` to discard the saved r4-r11 words. Its observed r4 holds the global
secure-handle address rather than the saved r4 pattern. The Fiber component
deliberately restores all r4-r11, including the constructor's inherited r9.
The reference begins with handle zero and later allocates/loads through SVC100.
Fiber fulfills a pre-start 64-byte attachment inside its owned SVC70, with one
initialize, one allocation, and one load. A zero-attached Fiber initializes once,
does not allocate, and loads handle zero once. These are policy/transfer deltas,
not identical-assembly or full-scheduler equivalence claims.

Optimized reference code may tail-branch to SecureContext_LoadContext with the
actual BC EXC_RETURN in LR. This is admitted only for the reference load operation
when the generated dispatcher contains that tail branch, and is checked through
the real Thread exception return. No sibling-call option is disabled.

The Fiber images retain actual constructor, attachment, first-start, SVC, Secure
identity/gateway/pool, common configuration guard, and common publication code.
The fixture supplies a staged cohort identity, RAM/code predicates, a real
DMB/DSB/ISB barrier, and a terminal task-return provider. Secure archive extraction
uses an address-valued RO manifest of the actual providers; it does not use fake
NSC bodies or `-u` roots. NS archive extraction follows real fixture calls and
the vector table. The exact twelve genuine C55S imports are checked. Omitted
imports and an actually compiled CM33 Secure provider both fail with the exact
eleven required missing C55S symbols.

Current first preparation also calls the cold PendSV component anchor. The
fixture compiles the actual `fiber_port_pendsv.c` in every normal, hostile,
archive/LTO and compiled-mutant source group; it supplies no replacement anchor.
The runner checks that this actual object defines the anchor, runtime imports
it, fixture objects do not define it, and the final preparation body still calls
it. The real anchor extracts the object from the NS archive and retains its
common-v1/cohort dependencies. Unused PendSV code is section-GC'd; the final
image must still omit `PendSV_Handler`, and vector 14 remains the terminal
fixture fault handler. This dependency repair does not extend execution scope
to PendSV or the complete runtime.

## Oracles

The constructor is checked against all 19 independent numeric frame words,
including zero handle, PSPLIM, BC, GPRs/r9, argument, task-return LR, even entry PC,
and xPSR. Actual SVC entry must have IPSR11 and EXC_RETURN B8. Before final BC,
the handler must expose NS CONTROL2 while still physically using MSP, correct
PSP/PSPLIM, cleared masks, committed current/plan/handle, and the exact GPRs.
The actual Thread entry must use PSP, preserve GPRs/argument, and leave the context
and original frame unchanged except the committed handle. Frame checks occur
before the entry's first push; historical frame bytes are not read after that
memory becomes the live C stack.

All eight query entries/returns and init/allocate/load entries/returns are traced
through actual SG and BXNS. Allocation arguments are independently 64 and the
actual NS context address, not derived from the resulting Secure record. The
entire 480-byte three-record/three-slot Secure pool is checked against an
independent numeric image, including owner, request size, seals, unused bytes,
ready markers, and actual Secure PSP/PSPLIM/CONTROL. Initial NOLOAD bytes are
poisoned, not assumed zero.

QEMU rejects debug reads of Secure RAM when stopped in NS state. Pool snapshots
are therefore captured at actual Secure entry and BXNS exit breakpoints, without
changing SAU attribution or adding a debug gateway. Subsequent NS oracles use the
last real Secure snapshot with no intervening Secure operation. Snapshot hashes
and the actual live banked registers are recorded in each trace.

Negative cases cover vector MSP/reserve and VTOR, saved-frame/canary/hash/bounds,
raw hardware-frame bounds/alignment/xPSR, current slot, owned SVC opcode and site,
all eight bad query values, all eight query PRIMASK disturbances, other banked
state disturbances, primitive failure after real effects, and late vector
changes after Secure load. Rejections require the exact diagnostic, origin,
query prefix, call counts, sticky committed effects, unchanged context/frame,
no Thread entry, and the exact terminal report/exit. Validly prepared foreign
opcode/site cases fail `u`; unprepared foreign protocol fails earlier `D`.
Raw-frame argument mutations preserve the trusted physical MSP stack. Arbitrary
physical MSP corruption is outside the production component's contract.

Three maintained compiled NS mutations omit the full GPR restore, forward the
wrong allocation size, or forward the wrong owner. They must be rejected by the
independent register/argument oracles. Unknown stops, missing reports, generic
faults, timeouts, and malformed code generation fail closed.

## Evidence

Each run creates a unique output root with all compiler/linker/QEMU commands,
saved preprocessed/assembly/object/link artifacts, ELF symbols/disassembly,
per-launch manifests and traces, before/after source/tool hashes, `results.json`,
and `sha256.csv`. Input drift forces failure. QEMU TCG execution is not board,
hardware timing, full Secure Thread/provider lifecycle, or full runtime evidence.
