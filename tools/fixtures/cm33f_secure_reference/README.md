# CM33 Scalar-FP SecureContext Reference Sidecar

This is reference evidence and a proposed production delta, not a new Fiber
profile, a runtime activation, or an equivalence/hardware result. The maintained
runner is `tools/test_cm33f_secure_reference.ps1`. It accepts existing `-ArmGcc`,
`-FreeRtosRoot`, `-BuildRoot`, and `-Python` inputs; Python standard library only.
It installs nothing, runs no emulator or board, and edits no reference or
production source. No CMSIS/device facade is substituted into the FreeRTOS code.

## Exact Tuple And Evidence

The local kernel must be clean at
`a50edad08b29052631aa469d4df6e6ec7ff68878`. Reference directories are
`portable/GCC/ARM_CM33/non_secure` and `portable/GCC/ARM_CM33/secure`, not the
NTZ, MPU, CM55, Secure-only, MVE or TF-M cohorts.

All four combinations use real `-mcpu=cortex-m33 -mthumb
-mfpu=fpv5-sp-d16`, O2/Os and hard/softfp. The shared configuration explicitly
sets MPU=0, FPU=1, TrustZone=1, Secure-only=0, MVE/PAC/BTI=0, single core.
Secure compilation additionally uses `-mcmse`; the NS compilation does not.
These are hardware-FP compiler targets, not soft/no-FP targets. The actual
compiler macros and ELF architecture/PCS attributes are recorded per image.
Compiler predefines are target facts, not proof of a literal `-mcpu` spelling
or physical features. Real command arrays identify the supplied target here.

Per mode the runner compiles the actual unchanged NS `port.c`, `portasm.c`, and
Secure `secure_context.c`, `secure_context_port.c`, `secure_init.c`,
`secure_heap.c`: 24 actual reference translation units across four modes.
Twelve fixture objects contain geometry or terminal kernel link providers.
The actual Secure linker generates seven CMSE veneers/imports used by the NS
link; no fixture supplies a SecureContext or port implementation. Links omit
section GC and compare every nonempty generated object function's name/size
against its final ELF. CMSE moves the public name to an eight-byte SG veneer
and leaves a zero-sized `__acle_se_*` body-start alias; for those functions the
runner additionally proves the complete actual input section size/address in
the link map, including compiler alignment beyond the function size. Seven
veneers occupy56 bytes plus bounded section padding (64 bytes with GCC14/ld).
The oracle checks each SG branch to its real body and each NS import pointer.
No generated constructor/handler body is lifted,
rewritten, shortened or replaced. Source snapshots, `.i`, `.s`, `.su`, objects,
relocations, disassembly, maps, full symbols/attributes, imports, macro dumps,
commands, checks, input hashes and artifact hashes remain in a unique output.
The reference secure heap is retained, not silently replaced by a fake pool.

The static oracle compares complete normalized first restore, PendSV, SVC,
start/allocate/free veneers, and Secure load/save helper bodies. Branch targets,
the bit6 skips, bit4 FP transfers, PSP/PSPLIM order, register groups, call spills,
real CMSE import veneer pointers and actual instruction bytes are checked.
The generated C envelopes are checked for their actual dependencies and policy
masks, not asserted instruction-for-instruction equal across optimizations.
Two actual FPU-disabled reference-branch controls per mode must link and fail
the exact NS high-FP or Secure S0-trigger oracle. They are deliberately mixed
control images, not supported production manifests. Compiler/link failures,
tracebacks and unrelated rejections are not successful controls.

## Source And Function Mapping

Line references below address the exact hashes in the final table.

| Source / Function | Reference Fact For This Tuple |
| --- | --- |
| NS `port.c:1652`, `pxPortInitialiseStack` | Initial basic image has 19 words: handle0, PSPLIM, EXC_RETURN=BC, r4-r11, then the 8-word core hardware frame. The default preload branch writes reference debug seeds; the non-preload branch leaves the corresponding gaps. FPU=1 does not pre-create an extended frame. |
| NS `portasm.c:146`, `vRestoreContextOfFirstTask` | Load handle/PSPLIM/EXC_RETURN; publish `xSecureContext`; write PSPLIM; OR CONTROL.SPSEL; skip32 bytes of initial r4-r11; write PSP; clear BASEPRI; BX saved EXC_RETURN. No first Secure allocation/load occurs here. |
| NS `portasm.c:441`, `PendSV_Handler`, save | If handle!=0, spill r0-r2/LR on MSP and call actual Secure save. Test EXC_RETURN bit6 by `LSL #25`/BMI. Secure-origin skips all NS r4-r11/high-FP stores. Otherwise bit4=0 conditionally saves s16-s31, then saves r4-r11. Every path saves the 3-word handle/PSPLIM/EXC_RETURN prefix and TCB cursor. |
| Same function, select/restore | BASEPRI protects `vTaskSwitchContext`. Restore 3-word prefix and NS PSPLIM, publish handle, call actual Secure load with a 16-byte MSP spill when handle!=0. Test bit6 before any NS integer/FP load. Otherwise restore r4-r11 and, only if bit4=0, s16-s31. Write NS PSP and BX the preserved EXC_RETURN. |
| NS `port.c:1109`, `vPortSVCHandler_C` | SVC100 allocates with `(bytes, owner)` and loads; SVC101 frees; SVC102 de-prioritizes NS exceptions, initializes Secure context, enables FPU policy, then first-restores. SVC frame/provenance hardening is not supplied by this generic reference. |
| NS `port.c:1015`, `prvSetupFPU` | First calls Secure FPU grant, then ORs CPACR CP10/11 to full access (`0x00f00000`) in the executing NS bank, then ORs FPCCR ASPEN/LSPEN (`0xc0000000`). Reference policy is lazy, not proof that Fiber eager policy is equivalent. |
| Secure `secure_init.c:64/81` | Handler-only helpers set AIRCR.PRIS; FPU grant ORs Secure NSACR.CP10/11 (`0xc00`), clears Secure FPCCR.LSPENS (`0x20000000`), sets TS (`0x04000000`). This is **not** a Secure write of CPACR_NS at its NS alias. NS CPACR is written separately above. Secure CPACR access/boot attribution remain integration obligations. |
| Secure `secure_context.c:138`, `SecureContext_Init` | One-shot static latch, PSPLIM=0 then PSP=0, zero records, CONTROL=2 for non-MPU. No per-context CONTROL word in this tuple. |
| Secure allocate/load/save/free | Allocate from actual Secure heap, bind opaque owner, 1-based handle, two seal words at requested stack top; no allocation of a dedicated software FP array. C load/save gates record ownership/PSPLIM then delegates real helpers. Reference APIs return void where existing Fiber hardening returns exact success/failure. |
| Secure `secure_context_port.c:42`, load helper | Handler gate; load saved PSP/PSPLIM from record offsets0/4; write PSPLIM then PSP. No non-MPU CONTROL pop and no FP transfer in load. |
| Secure `secure_context_port.c:76`, save helper | Handler gate; read PSP into r1; `VSTMDB r1!,{s0}` followed by `VLDMIA r1!,{s0}` forces deferred stacking and undoes the temporary pointer decrement; store r1, then clear PSPLIM/PSP. This exact FP trigger is absent in scalar C33S today. |

## Frame And Storage Inventory

- **NS basic origin:** prefix3 + r4-r11(8) + core hardware8 = 19 words/76 bytes;
  optional architectural alignment word is additional. Saved cursor is 4 mod8
  when the interrupted raw PSP is eight-byte aligned.
- **NS extended origin:** prefix3 + r4-r11(8) + high FP16 + hardware26
  (core8 plus low FP/FPSCR/reserved18) = 53 words/212 bytes, plus optional
  alignment. Raw PSP points at the core hardware frame; do not transplant the
  historical wrong low-FP-before-core interpretation. The sidecar proves the
  software high-FP branch, not hardware frame allocation or lazy completion.
- **Secure origin, EXC_RETURN bit6=1:** the NS software image contains only
  the three-word prefix at the saved NS PSP. It must not be validated as a
  19/53-word NS frame or decoded as containing NS xPSR/PC. Secure architectural
  stacking owns the corresponding additional state. The reference skips the
  NS integer and FP transfers independent of bit4 on this path.
- **DCRS/SFPA:** initial EXC_RETURN BC has S(bit6)=0, DCRS(bit5)=1 and
  FType(bit4)=1. The handwritten reference has no separate DCRS or SFPA test,
  software SFPA slot, or non-MPU per-context CONTROL slot; it preserves the
  complete saved EXC_RETURN and delegates Secure architectural state to the
  Secure stack/exception and CMSE mechanisms. Compiler-generated CMSE entry/
exit bodies are preserved, including any security FP mechanics. The oracle
records each NSC function's actual FP/return forms rather than banning all
V-instructions. For example GCC14 hard-FP emits S0-S15 `VMOV.F32` and
FPSCR `VMRS`/`VMSR` scrubbing with `BXNS`; these are not the handwritten S0
deferred-stack trigger and not evidence of ordinary Fiber FP computation. Their
  presence/absence is not a software proof that SFPA or DCRS is always zero/one.
  Exact legal Secure-origin EXC_RETURN combinations and additional-state frame
  extents must come from the separately qualified architecture/execution work,
  not speculative literals in this sidecar.
- **Secure companion record:** actual `SecureContext_t` is 16 bytes, alignment4,
  savedPSP/PSPLIM/top/owner at offsets0/4/8/12; handle32, invalid0, valid=index+1.
  The non-MPU Secure stack has no saved CONTROL word. The top seal is two
  `0xFEF5EDA5` words/8 extra bytes; requested usable bytes exclude that seal.
- **Transient scratch:** the S0 trigger touches four bytes immediately below
  saved Secure PSP even though its two instructions have zero net pointer
  movement. A hardened pool needs a proved lower-bound scratch envelope before
  issuing that store; a zero-net effect is not permission to touch below limit.
  Each reference NS PendSV companion call explicitly spills16 MSP bytes.
  Generated CMSE prologues, architectural FP/additional-state stacking, nested
  exceptions and alignment require further stack budget. `.su` and complete
  generated bodies are evidence, not an exhaustive nesting/stack-depth bound.
  GCC's `.su` can explicitly say `ignoring_inline_asm`; the generated CMSE
  return sequence can itself push/pop r4 even where that report says zero.

## Current Scalar C33S Delta And Boundary

The first sidecar baseline was C33S ID `0x43333353`, layout `0x00010001`,
feature `0x8a`, storage `arm_cm33` revision1. It uses a no-FP compiler/data ABI,
11-word software prefix and hardened private static Secure pool. Its record
is 24 bytes (the reference's first4 words plus capacity/allocation fields),
not the reference heap record copied verbatim.

**Historical missing reference branch, not a reproduced cooperative failure:**
the first baseline's `ARM_CM33/non_secure/fiber_port_svc.c:223` required exact
BC at PendSV and always saved/restored r4-r11; its saved-frame/initial checkers
assumed the full19-word image and xPSR. The reference's non-MPU bit6=1 three-word
Secure-origin path already exists with FPU=0 as well as FPU=1. Historical counts
of nineteen implemented runtimes are implementation inventory, not all-branch
software equivalence.

The subsequent A30 production repair implements the scalar dual-origin branch
under private layout generation `0x00020001`, retaining the same profile ID,
feature and public storage revision. This reference sidecar does not qualify
that production repair: its fresh execution and whole-body parity belong to
the separate C33S gates. `scalar-baseline.json` identifies the actual comparison
sources at each run, not a scalar runtime result. The table below preserves
the original authoring-time hashes rather than claiming they are current.

FP-specific production work must additionally introduce real scalar-SP
manifest/attribute admission, NS CPACR and FPCCR startup/readback policy, the
Secure NSACR/LSPENS/TS policy, NS high-FP conditional save/restore, proper raw
basic/extended frame envelopes, Secure S0 lazy trigger with scratch validation,
and preservation/validation of admissible Secure FP state. Do not copy the
scalar cohort's exact CONTROL=2 admission into active-FP load/save or write
CONTROL there merely to clear FPCA/SFPA. The reference writes CONTROL=2 during
initialization only; the non-MPU load/save helpers do not write it.

Existing Fiber strengths remain deliberate: static bounded pool, bytewise
seal access, exact owner/cohort binding, return-status/readback hardening,
SVC/PendSV immediate caller checks, cold zero-handle versus post-allocation
validators, explicit r9 seed/full GPR initialization, and CPU-neutral reverse
services. The process-wide r9 static-base guarantee requires a consistently
reserved-register ABI; ordinary AAPCS permits compiler temporaries and requires
caller preservation, not public-entry-to-new-frame seed equality. Both modes
retain explicit captured-seed-to-builder consistency.
FreeRTOS heap/free/TCB/syscalls/debug seeds are reference context, not features
to import into the public five operations or frozen eight-operation port ABI.

## Proposed New Identity, Not Production Support

Use a separate `ARM_CM33F/{non_secure,secure}` pair, not a mutation of C33S or
the existing NTZ C33FN/C3FP cohorts. Candidate ASCII C3FS ID is `0x43334653`,
initial layout `0x00010001`, storage `arm_cm33f` revision1, regions0. Under the
existing non-MPU bit dictionary, candidate feature `0x8b` adds extended-FP bit0
to PSPLIM/handle/Non-secure bits. Boot FPCA/FPU traits and legal saved-image
semantics must be reflected in the exact private cohort even when the public
outer `sp+boot` size stays unchanged. These values are a proposal, not emitted
definitions or a claimed allocation of a new selectable profile.

The Secure pair needs its own profile-specific NSC/import symbol namespace
and exact private object cohort: an old C33S import archive must not satisfy it.
Version1 is reasonable for a genuinely new namespace/layout, with the matching
identity/capacity/init/allocate/load/save operation set; fold the one-time FPU
grant into its private initializer if that preserves the documented order,
rather than growing common/public APIs. A same-sized24-byte private record may
be retained only after its FP/scratch invariants are asserted; the FP feature
and generation must still differ in its exact private key.

Required gates before activation are actual NS/Secure caller/state rejection,
basic/extended NS and Secure-origin switching with both handle0 and nonzero,
DCRS/SFPA/bit6/bit4 classification and no NS hardware-frame reads on the Secure
path, eager/lazy FP data preservation across NS and Secure operations, forced
deferred stacking with lower-bound/red-zone/readback controls, SVC initialization
and attachment/first-start behavior, scheduler CPU/FP-policy preservation,
instrumentation/codegen/ISA admission, exact cohort/import/archive GC/LTO stale
negatives, and final real common five/eight-operation group links. Secure-only,
MPU, MVE, PAC/BTI and TF-M are different cohorts, not implied by this tuple and
not newly excluded from the roadmap. Missing execution gates cannot become an
equivalence or physical-support claim.

## Exact Source Hashes

SHA256, relative to `portable/GCC/ARM_CM33`:

| File | SHA256 |
| --- | --- |
| `non_secure/port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` |
| `non_secure/portasm.c` | `6F39F5CB7A24766DF3FA025E41E0E502301550136151B5E2EABDFA9AC4E42D60` |
| `non_secure/portasm.h` | `185477BF5A84B9B61927E4A0894427A4F471C448840DBF521F312B6F52D03B6C` |
| `non_secure/portmacro.h` | `60DB3E36671EA9075ED11F369940330355377B7B0B2F044E843E8853BFC9FBAE` |
| `non_secure/portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` |
| `non_secure/mpu_wrappers_v2_asm.c` (inactive for MPU0) | `0DC69DD4372646D176CDF98429C8BC9A056E6B0200CB558C51DF4E1F10378D4F` |
| `secure/secure_context.c` | `E25244584CE048F44AAD7C89E9FEA80B811141760F948FD775E0E9EB2964ED72` |
| `secure/secure_context.h` | `8209F4BAF60741E8ED5516AF9706FC4B5B2EE3CF16452EDB0C034B7DDDE443B4` |
| `secure/secure_context_port.c` | `B3ED96A95CB008F157082C4437D2846D740851865AD2E4DC893AED895823AF8E` |
| `secure/secure_heap.c` | `CE5D5F7FC774E7EC51157F5078361F3CB0A20CE9C94593396F543E5046E53F42` |
| `secure/secure_heap.h` | `E58805B998EE73A9EB84627EBD2955787CDFD0CD968D1BC7D93423441BAB6C87` |
| `secure/secure_init.c` | `1B8444698089651C6415D48A2B6716BA6C6DC32F71C51B679F5A8A9A3968DE55` |
| `secure/secure_init.h` | `7704E518DFAAE39170274B7DD924B1A214FFFB12DC37C050E7D3457B5AA0E149` |
| `secure/secure_port_macros.h` | `5F2DF28DF3D445F08727CAF41F83ED6C67E0494E40AF5572B5E18F6416B2838D` |

The runner also snapshots all current scalar C33S C/header/linker input hashes
in `scalar-baseline.json`; that is comparison identity, not a fresh scalar
runtime qualification. Key inspected baseline hashes at authoring time:

| Fiber Path | SHA256 |
| --- | --- |
| `ARM_CM33/non_secure/fiber_portmacro.h` | `A323EA40777C11EB330591428576D0F0A0915E2BF8CE37821D6C8F2EDFE0294E` |
| `ARM_CM33/non_secure/fiber_port_svc.c` | `1527EF0DF4EB5F284AD3877C47FCB9634DB711660F9E0780B65A646C0CC2D0E4` |
| `ARM_CM33/non_secure/fiber_port_boot.c` | `038C0C765CB2D30EC508B503233CBF893255D75A5F21F169131BA50302E3CCF9` |
| `ARM_CM33/secure/fiber_secure_context_gateway.c` | `2F0DFCA36F84764E0FD03DD53B2CD4BD4C8129087E6F73612017CF1E6F592EE9` |
| `ARM_CM33/secure/fiber_secure_context_pool.h` | `588D17BB445C91374A8921A64B85A24A4EADEE05A34E215A6278CFEA051C8709` |
