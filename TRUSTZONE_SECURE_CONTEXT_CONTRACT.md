# TrustZone SecureContext Contract

## Status

`ARM_CM23_NTZ`, `ARM_CM33_NTZ`, `ARM_CM33F_NTZ`, and `ARM_CM7/r0p1` do not
export a SecureContext API. The build-selected `ARM_CM33/non_secure` profile
and paired `ARM_CM33/secure` companion implement the first complete no-MPU,
no-FPU SecureContext runtime. They provide exact initial context construction,
a sealed pre-start attachment API, versioned companion identity, an
eight-function stateful gateway, Secure-private static storage, all eight
mandatory forward runtime operations, and strong SVC/PendSV handlers. First
SVC performs one-shot Secure initialization and first-context allocation/load;
PendSV performs Secure save/unload, scheduler selection, lazy allocation, and
owned Secure load. This is compile/assembly/CMSE/ELF/LTO evidence only, not a
hardware support claim.

`ARM_CM55/non_secure` currently provides only the staged `C55S` M55
Non-secure type/trait foundation: its eleven-word SecureContext-shaped frame,
pre-start request field, and scalar ARMv8.1-M CMSE-level-1 manifest. Its
paired `ARM_CM55/secure` Slice-2/3 artifact exposes eight immutable,
C55S-named v1 NSC identity/capacity veneers plus an explicit Secure-only static
capacity reservation. Matching Secure/Non-secure CMSE linkage, retained pool
geometry, and foreign/v2/missing-import rejection are compile-covered. It
still has no runtime source, public attachment API, pool initialization,
stateful gateway, SVC or PendSV handler, or SecureContext hardware claim. It
must not be treated as an alternative build flag for the complete CM33 profile;
later lifecycle and runtime mechanics need their own exact C55S evidence.

The paths and API names below target the active v2 selected-port architecture.
If implementation follows the post-port-freeze separation in
`CONTEXT_FIBER_ARCHITECTURE.md`, the same saved-state mechanics and companion
gateway move into the selected Context backend. Fiber and ordinary Task policy
remain security-profile-neutral; the lifecycle and isolation outcome below do
not change.

`NTZ` means no TrustZone. Cortex-M7 also has no Armv8-M TrustZone security
extension.

## Purpose

TrustZone separates the MCU into Secure and Non-secure domains. The normal
fiber scheduler and ordinary fibers run in the Non-secure domain. Secure code
owns assets such as device keys, secure storage, firmware-verification state,
and security configuration.

Non-secure code cannot read Secure memory or registers. It may call only
explicit Non-secure Callable (NSC) gateway functions exported by the Secure
image. A SecureContext is not a Secure fiber: it is the private Secure stack
and Secure CPU state associated with one Non-secure fiber that needs to enter
such a gateway.

TrustZone does not isolate Non-secure fibers from each other. That is a
separate MPU/unprivileged-port concern.

## Artifact Model

A full TrustZone profile is two coordinated firmware artifacts:

```text
Non-secure image
  selected ARM_CM23/ARM_CM33/ARM_CM55 Non-secure fiber runtime
  application fibers and scheduler

Secure image
  SecureContext companion
  Secure stacks and state
  application Secure services
  NSC gateway veneers
```

Secure boot and platform attribution configure the Secure, Non-secure, and NSC
memory regions before the Non-secure image starts. The selected profile binds
one matching versioned Secure companion gateway. It must not link a second
fiber runtime into the Secure image.

TF-M is an alternative Secure provider. A TF-M profile uses its matching
NTZ-style CPU port plus TF-M integration; it does not also use a fiber-owned
SecureContext companion for the same profile.

## Implemented Construction, Gateway, And Storage Foundation

The first concrete paired CM33 artifact has two deliberately separate
versioned NSC surfaces:

```text
Non-secure import header
  fiber/port/ARM_CM33/non_secure/fiber_port_secure_gateway_abi.h

Secure provider
  fiber/port/ARM_CM33/secure/fiber_secure_gateway_abi.h
  fiber/port/ARM_CM33/secure/fiber_secure_gateway.c

Stateful SecureContext gateway
  fiber/port/ARM_CM33/non_secure/fiber_port_secure_context_gateway_abi.h
  fiber/port/ARM_CM33/secure/fiber_secure_context_gateway_contract.h
  fiber/port/ARM_CM33/secure/fiber_secure_context_gateway_abi.h
  fiber/port/ARM_CM33/secure/fiber_secure_context_gateway.c
```

The Secure image exports four immutable identity veneers:

```text
fiber_secure_gateway_v1_abi_version
fiber_secure_gateway_v1_context_port_id
fiber_secure_gateway_v1_context_layout_version
fiber_secure_gateway_v1_context_feature_mask
```

The stateful v1 surface adds four immutable capacity queries and four stateful
operations:

```text
fiber_secure_context_gateway_v1_abi_version
fiber_secure_context_gateway_v1_stack_alignment
fiber_secure_context_gateway_v1_max_stack_bytes
fiber_secure_context_gateway_v1_max_contexts
fiber_secure_context_gateway_v1_initialize
fiber_secure_context_gateway_v1_allocate
fiber_secure_context_gateway_v1_load
fiber_secure_context_gateway_v1_save
```

Initialization combines the pinned FreeRTOS
`SecureInit_DePrioritizeNSExceptions()` and `SecureContext_Init()` mechanics:
it sets and reads back Secure `AIRCR.PRIS`, zeros Secure PSP/PSPLIM, clears the
fixed pool, and selects privileged Secure Thread/PSP. It accepts only exact
exception 11. Before the first destructive write it enters an irreversible
initializing state; success advances that state to ready, while any partial
failure permanently rejects a retry for that boot.

Allocation preserves the pinned FreeRTOS IPSR/PSPLIM trust gate but accepts
only exact exception 11 (`SVCall`) for first start or 14 (`PendSV`) for lazy
activation. Initialization must be complete and both Secure PSP and PSPLIM
must be zero. Save accepts only PendSV, records live Secure PSP, proves the
owned stack bounds, then clears and reads back Secure PSPLIM/PSP before
selection. Load accepts only SVC or PendSV, verifies the opaque owner and
sealed pool record, writes PSPLIM before PSP, and reads both back. Handle zero
is the explicit no-context case and succeeds only while no Secure stack is
active. The opaque Non-secure owner token is compared only and is never
dereferenced in Secure state.

The version is part of every symbol name. The compile matrix builds a real
Secure `-mcmse` image, emits a GNU CMSE import library with
`--cmse-implib --out-implib`, and links a matching Non-secure image through it.
It also proves that a missing import library and a v2-only import library fail
on the required v1 symbol at `-O2`, `-Os`, and `-O2 -flto`.

The returned identity and capacity values are validated by the selected-port attach
operation without mutating CPU mask, CONTROL, or PSPLIM state. Every individual
cross-image query and stateful call is followed by CPU-state validation before
its result is consumed. Attach never calls a stateful operation from Thread
mode. The first-start SVC repeats the version/capacity proof under that
guarded envelope, initializes the Secure domain, allocates only when the
selected first fiber requested a Secure stack, and always calls load, including
handle zero to reject stale inheritance.

The paired Secure image now also has the private foundation:

```text
fiber/port/ARM_CM33/secure/fiber_secure_context_pool.h
fiber/port/ARM_CM33/secure/fiber_secure_context_pool.c
```

It is deliberately not an NSC API and is never included by the Non-secure
image. The Secure manifest must explicitly define both
`FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT` and
`FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES`; there is no hidden RAM-cost
default. One successful allocation reserves one fixed-capacity
Secure stack slot plus two ARM stack-seal words (`0xFEF5EDA5`); the current
attach slice records only the sealed request. The requested size must be
nonzero, eight-byte aligned, and no larger than the manifest capacity. The pool
preserves the FreeRTOS record prefix `[saved PSP, PSPLIM, stack top, owner]`,
checks that an owner receives at most one handle, and treats handle zero as
invalid.

This is a static-lifetime Fiber replacement for the FreeRTOS heap-backed
allocator: it intentionally has no `secure_heap`, `pvPortMalloc`, `vPortFree`,
detach, or `SecureContext_FreeContext` equivalent. Its storage is emitted only
into `.fiber_secure_context_pool`; a real Secure linker manifest must place that
section in Secure RAM and never in NSC or Non-secure RAM. The Secure pool
initialization explicitly clears every record and stack slot, so its
correctness does not depend on a generic startup `.bss` loop covering this
custom `NOLOAD` section. The versioned initialize veneer owns this destructive
operation exactly once before any allocation. The matrix proves the section,
alignment, exact twelve-function combined NSC import surface,
and invalid Secure configuration failures under `-O2`, `-Os`, and
`-O2 -flto`.

The selected Non-secure runtime constructs the exact 19-word FreeRTOS-shaped
initial image and keeps its live handle word zero. Its profile-specific attach
API validates lifecycle, context/cohort, gateway identity, capacity, and CPU
state, then reseals only `secure_stack_bytes`. It does not allocate, load, or
write a handle. Strong SVC 70 accepts only exact Non-secure Thread/MSP origin,
initializes the companion, allocates an attached first context, writes its
validated handle to frame word zero, loads owned Secure PSP/PSPLIM, and restores
the exact eleven-word Non-secure software frame. Strong PendSV saves and
unloads current Secure state before selection, lazily allocates an attached
never-run context after selection, restores Non-secure PSPLIM, loads owned
Secure state, and completes the exact r4-r11/PSP restore. This remains
compile/assembly/CMSE/ELF/LTO evidence only, not a hardware support claim.

The strong handlers call four Non-secure attachment helpers from naked inline
assembly. Those edges are not early C relocations visible to the LTO archive
scanner. The always-linked mandatory port object therefore retains two
independent symbols: a handler-bundle anchor and an attachment-bundle anchor.
The matrix links the multi-member selected port with an ordinary one-pass
static-archive link, section GC, and normal/LTO modes; neither
`--whole-archive` nor a linker rescan group is used. Both anchors, all four
helpers, and strong vector slots 11/14 must survive in the final ELF.

Every lazy allocation repeats the companion capacity query inside the guarded
CPU-state envelope. A returned handle must be nonzero and no greater than
`max_contexts` before frame word zero is updated.

Frame handle zero has two meanings distinguished by sealed boot metadata:

```text
secure_stack_bytes == 0 and handle == 0
  unattached fiber; load the explicit no-context state

secure_stack_bytes != 0 and handle == 0
  attached but not allocated yet
```

The first-start SVC allocates the selected first fiber when required. PendSV
allocates any other attached fiber lazily, after saving and unloading current
Secure state and before loading the selected one. Fiber does
not enumerate contexts in common code. Because contexts have static lifetime,
each successful allocation remains reserved; the Secure manifest must budget
`FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT` for every attached fiber that can
become runnable.

## Implemented User-Facing Selected-Port API

The concrete TrustZone profile provides this header:

```text
fiber/port/ARM_CM33/non_secure/fiber_port_secure_context_abi.h
```

The profile-specific operation is:

```c
void fiber_port_secure_context_attach(
    FiberContext *fiber,
    size_t secure_stack_bytes);
```

It is deliberately not declared by `fiber_core.h`, and it does not exist in
ports without the feature. The exact selected port owns the final declaration,
attributes, storage policy, and cross-image gateway version.

The operation is valid only after `fiber_init(fiber, ...)` and before the first
`fiber_start()`. It binds one SecureContext requirement to that fiber. It must
fail closed if the fiber is already published, already attached, belongs to a
different selected-port cohort, or the requested Secure stack size is invalid.
The selected port must also reject Handler-mode use before consulting the
common pre-publication lifecycle guard. The resulting context metadata is
sealed before execution begins.

The static-lifetime v2 runtime has no detach or destroy operation. A fiber that
does not need Secure services simply has no attachment. Dynamic SecureContext
deletion, if ever needed, is a separate optional lifecycle extension.

Example for the completed build-selected M33 TrustZone runtime:

```c
fiber_init(&signer, signer_stack, signer_stack_end, signer_entry, NULL);
fiber_port_secure_context_attach(&signer, 1024u);

fiber_init(&network, network_stack, network_stack_end, network_entry, NULL);

fiber_start();
```

`signer_entry()` may then call an application-defined NSC gateway such as
`secure_sign_gateway()`. `network_entry()` has no SecureContext and cannot
inherit the signer fiber's Secure stack or state.

Portable upper-layer code must not include this selected-port header. It calls
an application-owned security service interface instead. A TrustZone build may
implement that interface through an NSC gateway; an H7 or NTZ build may use a
different approved backend, such as a secure element.

## Runtime Ownership

The user never calls Secure save or restore functions. The selected Non-secure
port owns their placement in PendSV:

```text
current fiber with SecureContext
  -> Secure companion saves its Secure stack/state

normal Non-secure context save/select/restore

next attached fiber with a zero handle
  -> allocate its SecureContext once

next fiber with a nonzero SecureContext handle
  -> Secure companion restores its Secure stack/state
```

A fiber without an attached SecureContext takes the ordinary Non-secure path.
The port must prove the exact save/load ordering against its pinned FreeRTOS
reference port and must validate the Secure companion gateway version before
first start.

## Relation To FreeRTOS

FreeRTOS creates a task without a SecureContext. A task that will call Secure
functions invokes `portALLOCATE_SECURE_CONTEXT(size)` before its first Secure
call; its port uses an SVC service to allocate the context. PendSV then calls
`SecureContext_SaveContext()` and `SecureContext_LoadContext()` when a task has
one.

Fiber preserves the same security outcome and automatic switch-time behavior,
but uses a pre-start attach operation. The fiber runtime has static, sealed
context metadata rather than a mutable FreeRTOS TCB lifecycle. This avoids a
post-start context-layout mutation and makes the required Secure state part of
the selected-port cohort before the first SVC start.

## Required Evidence Before A Runtime Claim

- separate Secure and Non-secure image manifests, linker scripts, and matching
  CPU/FPU/security flags;
- a versioned NSC gateway plus negative companion-version link tests;
- exact SecureContext layout and PendSV save/load parity with the pinned
  FreeRTOS profile at `-O2` and `-Os`;
- proof that a fiber without an attachment cannot inherit another fiber's
  Secure state;
- secure-stack bounds, PSPLIM, FPU, and exception-bank validation where the
  selected core requires them;
- target-hardware validation of Secure service entry, preemption during Secure
  use, context recovery, vectors, priorities, and failure paths.
