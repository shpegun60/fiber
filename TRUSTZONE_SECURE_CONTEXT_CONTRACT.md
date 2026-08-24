# TrustZone SecureContext Contract

## Status

This is a future selected-port contract. No current fiber port implements it.
In particular, `ARM_CM23_NTZ`, `ARM_CM33_NTZ`, `ARM_CM33F_NTZ`, and
`ARM_CM7/r0p1` do not export a SecureContext API.

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
The resulting context metadata is sealed before execution begins.

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
