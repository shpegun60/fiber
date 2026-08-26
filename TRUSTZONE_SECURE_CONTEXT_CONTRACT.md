# TrustZone SecureContext Contract

## Status

No current fiber runtime implements this contract. `ARM_CM23_NTZ`,
`ARM_CM33_NTZ`, `ARM_CM33F_NTZ`, and `ARM_CM7/r0p1` do not export a
SecureContext API. The reusable optional common pre-publication lifecycle ABI
is implemented and link-versioned, but no selected port currently retains it.
`ARM_CM33/non_secure` and `ARM_CM33/secure` now provide a versioned companion
identity artifact plus a Secure-private static storage foundation; they do not
provide a selected runtime, user-facing attach API, selected-port allocation
bridge, or SecureContext save/load. A working SecureContext profile requires
those later runtime slices in addition to the separately versioned Secure
companion artifact.

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

## Implemented Gateway And Secure Storage Foundation

The public NSC surface of the first concrete paired CM33 artifact is deliberately
limited to identity:

```text
Non-secure import header
  fiber/port/ARM_CM33/non_secure/fiber_port_secure_gateway_abi.h

Secure provider
  fiber/port/ARM_CM33/secure/fiber_secure_gateway_abi.h
  fiber/port/ARM_CM33/secure/fiber_secure_gateway.c
```

The Secure image exports four `cmse_nonsecure_entry` v1 NSC veneers:

```text
fiber_secure_gateway_v1_abi_version
fiber_secure_gateway_v1_context_port_id
fiber_secure_gateway_v1_context_layout_version
fiber_secure_gateway_v1_context_feature_mask
```

The version is part of every symbol name. The compile matrix builds a real
Secure `-mcmse` image, emits a GNU CMSE import library with
`--cmse-implib --out-implib`, and links a matching Non-secure image through it.
It also proves that a missing import library and a v2-only import library fail
on the required v1 symbol at `-O2`, `-Os`, and `-O2 -flto`.

The returned identity values are reserved for the later first-start runtime
cohort check. Gateway v1 still exposes only those four immutable NSC functions.

The paired Secure image now also has the private foundation:

```text
fiber/port/ARM_CM33/secure/fiber_secure_context_pool.h
fiber/port/ARM_CM33/secure/fiber_secure_context_pool.c
```

It is deliberately not an NSC API and is never included by the Non-secure
image. The Secure manifest must explicitly define both
`FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT` and
`FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES`; there is no hidden RAM-cost
default. One attached fiber reserves one fixed-capacity Secure stack slot plus
two ARM stack-seal words (`0xFEF5EDA5`). The requested size must be nonzero,
eight-byte aligned, and no larger than the manifest capacity. The pool preserves
the FreeRTOS record prefix `[saved PSP, PSPLIM, stack top, owner]`, checks that
an owner receives at most one handle, and treats handle zero as invalid.

This is a static-lifetime Fiber replacement for the FreeRTOS heap-backed
allocator: it intentionally has no `secure_heap`, `pvPortMalloc`, `vPortFree`,
detach, or `SecureContext_FreeContext` equivalent. Its storage is emitted only
into `.fiber_secure_context_pool`; a real Secure linker manifest must place that
section in Secure RAM and never in NSC or Non-secure RAM. The Secure pool
boot initialization explicitly clears every record and stack slot, so its
correctness does not depend on a generic startup `.bss` loop covering this
custom `NOLOAD` section. It is destructive by contract and must run exactly
once before any allocation, never as a runtime reinitialization. The matrix
proves the section, alignment, exact four-function NSC import surface, and invalid Secure
configuration failures under `-O2`, `-Os`, and `-O2 -flto`.

The selected runtime still stores no per-fiber handle, offers no public
attachment header, and does not run SecureContext code from SVC or PendSV. This
remains build/link evidence only, not a SecureContext or hardware support claim.

## Future User-Facing Selected-Port API

Only a concrete TrustZone selected port will provide this header:

```text
fiber/port/ARM_CM33/non_secure/fiber_port_secure_context_abi.h
```

The intended profile-specific operation is:

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

Example for a future M33 TrustZone build:

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

next fiber with SecureContext
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
