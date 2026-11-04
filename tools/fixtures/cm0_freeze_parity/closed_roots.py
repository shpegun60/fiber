"""Eight complete ARMv6-M non-MPU p2 root protocols, not CPU or C proof.

The caller supplies canonical cm55_tfm_parity.elf.Object instances and binds
their identities, receipts, source snapshot, exact cohort and optimization.
This module performs no I/O, process execution or instruction decoding. The
specifications are source transcriptions, not learned token or hash oracles.
Every instruction, branch, literal descriptor and in-symbol NOP is matched.
"""
import hashlib
import json


ROOTS = {
    "Native": ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler"),
    "Reference": ("vStartFirstTask", "SVC_Handler", "vPortSVCHandler_C",
                  "vRestoreContextOfFirstTask", "PendSV_Handler"),
}
DIFFERENCES = frozenset(("FAP-COMMON-START", "FAP-COMMON-PROVENANCE",
    "FAP-COMMON-MASK-RESTORE", "FAP-COMMON-SCHEDULER", "FAP-CM0-STAGED-FRAME"))
MODES = ("O0", "Og", "O2", "Os", "O3")
_NOP = ("nop", "@ (mov r8, r8)")


class Rejected(RuntimeError):
    pass


def _need(ok, detail):
    if not ok:
        raise Rejected("REJECT:CM0-CLOSED-ROOTS:" + detail)


def _body(text):
    """Resolve labels only in our fixed specification, not decoded input."""
    body, labels = [], {}
    for line in text.strip().splitlines():
        line = line.strip()
        if line.endswith(":"):
            label = line[:-1]
            _need(label not in labels, "duplicate specification label")
            labels[label] = len(body)
        elif line:
            op, _, arg = line.partition(" ")
            body.append((op, arg))
    return [(op, "@" + str(labels[arg[1:]]) if arg.startswith("@") and not arg.startswith("@ ") else arg)
            for op, arg in body]


def _island(offset, data, references, relocations=()):
    descriptor = dict(Offset=offset, Bytes=data,
        References=[dict(Instruction=instruction, Offset=literal) for instruction, literal in references],
        Relocations=[dict(Offset=literal, Kind=2, Target=target) for literal, target in relocations])
    return ("@literal-island", json.dumps(descriptor, sort_keys=True, separators=(",", ":")))


# fiber/port/ARM_CM0/fiber_port.c: start, SVC and PendSV; the PRIMASK
# envelope is fiber_portmacro.h:159-170. Frame constants are SW36, HW32,
# xPSR28, alignment4, stack_base12 and stack_top16. BASEPRI is absent.
_NATIVE = {
    "fiber_port_start_first_context": _body("""
cpsid i
dsb #15
isb #15
movs r3,#0
msr control,r3
isb #15
mrs r3,control
movs r2,#3
tst r3,r2
bne @fail_l
cmp r0,#0
beq @setup
lsrs r0,r0,#3
lsls r0,r0,#3
msr msp,r0
isb #15
mrs r3,msp
cmp r3,r0
bne @fail_l
setup:
ldr r3,=3758157060
ldr r2,=134217728
str r2,[r3,#0]
dsb #15
isb #15
cpsie i
dsb #15
isb #15
svc 70
movs r0,#121
bl fiber_panic
stuck:
b @stuck
fail_l:
movs r0,#108
bl fiber_panic
b @fail_l
""") + [_island(96, "04ed00e000000008", ((54, 0), (56, 4)))],
    "SVC_Handler": _body("""
mrs r2,ipsr
cmp r2,#11
bne @fail_l
movs r2,#6
mvns r2,r2
mov r3,lr
cmp r3,r2
bne @fail_l
movs r2,#4
mov r3,lr
tst r3,r2
bne @fail_l
mrs r0,msp
movs r2,#7
mov r3,r0
tst r3,r2
bne @fail_l
ldr r2,[r0,#28]
mov r1,r2
lsls r1,r1,#7
bpl @fail_l
mov r1,r2
lsls r1,r1,#22
bmi @fail_l
lsls r2,r2,#23
bne @fail_l
ldr r3,[r0,#24]
cmp r3,#2
bcc @fail_u
movs r2,#1
tst r3,r2
bne @fail_l
subs r3,#2
ldrb r2,[r3,#1]
cmp r2,#223
bne @fail_u
ldrb r3,[r3,#0]
cmp r3,#70
bne @fail_u
cpsid i
dsb #15
isb #15
ldr r0,=fiber_internal_runtime_current_context_slot+0
ldr r0,[r0,#0]
cmp r0,#0
beq @fail_C
stmdb sp!,{r0,lr}
bl fiber_port_context_validate_restore
ldmia sp!,{r2,r3}
mov lr,r3
ldr r0,[r2,#0]
adds r0,#20
ldmia r0!,{r4,r5,r6,r7}
mov r8,r4
mov r9,r5
mov r10,r6
mov r11,r7
msr psp,r0
subs r0,#36
ldmia r0!,{r3,r4,r5,r6,r7}
mov lr,r3
dsb #15
isb #15
cpsie i
dsb #15
isb #15
bx lr
fail_C:
movs r0,#67
bl fiber_panic
b @fail_C
fail_l:
movs r0,#108
bl fiber_panic
b @fail_l
fail_u:
movs r0,#117
bl fiber_panic
b @fail_u
""") + [_island(178, "000000000000", ((92, 2),),
        ((2, "fiber_internal_runtime_current_context_slot"),))],
    "PendSV_Handler": _body("""
mrs r2,ipsr
cmp r2,#14
bne @fail_j
movs r2,#2
mvns r2,r2
mov r3,lr
cmp r3,r2
bne @fail_j
mrs r0,psp
movs r2,#7
tst r0,r2
bne @fail_d
dsb #15
isb #15
movs r2,#4
mov r3,lr
tst r3,r2
beq @fail_j
ldr r1,=fiber_internal_runtime_current_context_slot+0
ldr r1,[r1,#0]
cmp r1,#0
beq @fail_C
stmdb sp!,{r0,r1,r2,lr}
mov r0,r1
bl fiber_port_context_validate_save_current
ldmia sp!,{r0,r1,r2,r3}
mov lr,r3
ldr r2,[r1,#12]
cmp r0,r2
bcc @fail_d
mov r3,r0
subs r3,#36
bcc @fail_d
cmp r3,r2
bcc @fail_d
ldr r2,[r1,#16]
subs r2,#32
bcc @fail_d
cmp r0,r2
bhi @fail_d
ldr r3,[r0,#28]
lsls r3,r3,#22
bpl @align_done
subs r2,#4
bcc @fail_d
align_done:
cmp r0,r2
bhi @fail_d
subs r0,#36
mov r2,r0
mov r3,lr
stmia r0!,{r3,r4,r5,r6,r7}
mov r4,r8
mov r5,r9
mov r6,r10
mov r7,r11
stmia r0!,{r4,r5,r6,r7}
str r2,[r1,#0]
mrs r3,primask
cpsid i
dsb #15
isb #15
stmdb sp!,{r2,r3}
mov r0,r1
bl fiber_port_scheduler_pick_next_from_pendsv
ldmia sp!,{r2,r3}
msr primask,r3
dsb #15
isb #15
mov r2,r0
ldr r0,[r2,#0]
adds r0,#20
ldmia r0!,{r4,r5,r6,r7}
mov r8,r4
mov r9,r5
mov r10,r6
mov r11,r7
msr psp,r0
subs r0,#36
ldmia r0!,{r3,r4,r5,r6,r7}
mov lr,r3
isb #15
dsb #15
isb #15
bx lr
fail_C:
movs r0,#67
bl fiber_panic
b @fail_C
fail_j:
movs r0,#106
bl fiber_panic
b @fail_j
fail_d:
movs r0,#100
bl fiber_panic
b @fail_d
""") + [_island(224, "00000000", ((44, 0),),
        ((0, "fiber_internal_runtime_current_context_slot"),))],
}

# FreeRTOS pin a50edad08b29052631aa469d4df6e6ec7ff68878,
# portable/GCC/ARM_CM0/portasm.c: non-MPU first restore, start,
# PendSV and SVC dispatcher. Section-end pools outside st_size are resolved
# and relocation-validated by Object, not invented as in-symbol descriptors.
_REFERENCE = {
    "vStartFirstTask": _body("""
cpsie i
dsb #15
isb #15
svc 100
"""),
    "SVC_Handler": _body("""
movs r0,#4
mov r1,lr
tst r0,r1
beq @msp
mrs r0,psp
ldr r3,=vPortSVCHandler_C+0
bx r3
msp:
mrs r0,msp
ldr r3,=vPortSVCHandler_C+0
bx r3
"""),
    "vRestoreContextOfFirstTask": _body("""
ldr r2,=pxCurrentTCB+0
ldr r1,[r2,#0]
ldr r0,[r1,#0]
ldmia r0!,{r2}
movs r1,#2
msr control,r1
adds r0,#32
msr psp,r0
isb #15
bx r2
"""),
    "PendSV_Handler": _body("""
mrs r0,psp
ldr r2,=pxCurrentTCB+0
ldr r1,[r2,#0]
subs r0,#36
str r0,[r1,#0]
mov r3,lr
stmia r0!,{r3,r4,r5,r6,r7}
mov r4,r8
mov r5,r9
mov r6,r10
mov r7,r11
stmia r0!,{r4,r5,r6,r7}
cpsid i
bl vTaskSwitchContext
cpsie i
ldr r2,=pxCurrentTCB+0
ldr r1,[r2,#0]
ldr r0,[r1,#0]
adds r0,#20
ldmia r0!,{r4,r5,r6,r7}
mov r8,r4
mov r9,r5
mov r10,r6
mov r11,r7
msr psp,r0
subs r0,#36
ldmia r0!,{r3,r4,r5,r6,r7}
bx r3
"""),
}

# port.c:842-905, configENABLE_MPU=0, fixture configASSERT infinite loop.
# All C prologue/locals, stacked PC+24, byte PC-2, SVC100, calls, failure
# loops and returning epilogues are explicit. This is not general C semantics.
_C_O0 = _body("""
stmdb sp!,{r7,lr}
sub sp,#16
add r7,sp,#0
str r0,[r7,#4]
ldr r3,[r7,#4]
ldr r3,[r3,#24]
str r3,[r7,#12]
ldr r3,[r7,#12]
subs r3,#2
movs r2,r3
movs r1,#11
adds r3,r7,r1
ldrb r2,[r2,#0]
strb r2,[r3,#0]
adds r3,r7,r1
ldrb r3,[r3,#0]
cmp r3,#100
bne @failed
bl vRestoreContextOfFirstTask
b @returned
failed:
nop @ (mov r8, r8)
b @failed
returned:
nop @ (mov r8, r8)
mov sp,r7
add sp,#16
ldmia sp!,{r7,pc}
""")
_C_SPEED = _body("""
stmdb sp!,{r4,lr}
ldr r3,[r0,#24]
subs r3,#2
ldrb r3,[r3,#0]
cmp r3,#100
beq @restore
failed:
b @failed
restore:
bl vRestoreContextOfFirstTask
ldmia sp!,{r4,pc}
""")
_C_SIZE = _body("""
stmdb sp!,{r4,lr}
ldr r3,[r0,#24]
subs r3,#2
ldrb r3,[r3,#0]
cmp r3,#100
bne @failed
bl vRestoreContextOfFirstTask
ldmia sp!,{r4,pc}
failed:
b @failed
""")
_REFERENCE_PADDING = {"vStartFirstTask": 2, "SVC_Handler": 4,
                      "vRestoreContextOfFirstTask": 3, "PendSV_Handler": 1}


def _protocols(mode):
    """Construct only fixed source-derived protocols and exact mode padding."""
    o0 = int(mode == "O0")
    native = {name: body + [_NOP] * o0 for name, body in _NATIVE.items()}
    reference = {name: body + [_NOP] * (_REFERENCE_PADDING[name] + o0)
                 for name, body in _REFERENCE.items()}
    reference["vPortSVCHandler_C"] = list(_C_O0 if o0 else _C_SIZE if mode == "Os" else _C_SPEED)
    return {"Native": native, "Reference": reference}


_MECHANISMS = (
    ("first-start", "fiber_port_start_first_context", ("vStartFirstTask",),
     ("FAP-COMMON-START", "FAP-COMMON-PROVENANCE")),
    ("first-restore", "SVC_Handler", ("SVC_Handler", "vPortSVCHandler_C", "vRestoreContextOfFirstTask"),
     ("FAP-COMMON-PROVENANCE", "FAP-CM0-STAGED-FRAME")),
    ("PendSV", "PendSV_Handler", ("PendSV_Handler",),
     ("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-CM0-STAGED-FRAME")),
)


def _match(image, side, name, expected):
    _need(callable(getattr(image, "function", None)), side + "/canonical Object required")
    actual = image.function(name, literal_islands=True, thumb1_tail_nop=True)
    _need(type(actual) is list, side + "/" + name + "/decoder result is not a body")
    if actual != expected:
        mismatch = next((i for i, pair in enumerate(zip(actual, expected)) if pair[0] != pair[1]),
                        min(len(actual), len(expected)))
        raise Rejected("REJECT:CM0-CLOSED-ROOTS:%s/%s/token-%d/complete protocol mismatch" % (side, name, mismatch))
    tail = 0
    for token in reversed(expected):
        if token != _NOP:
            break
        tail += 1
    return dict(Side=side, Name=name, Tokens=len(actual),
        LiteralIslands=sum(op == "@literal-island" for op, _ in actual), TailNops=tail,
        BodySha256=hashlib.sha256(json.dumps(actual, separators=(",", ":")).encode("ascii")).hexdigest().upper())


def check_pair(native, reference, mode) -> dict:
    """Match exactly three native and five reference bodies; no partial PASS.

    Supports only the three declared p2/non-MPU soft/no-FP CM0/CM0+ cohorts.
    The caller binds that selection and mode to authoritative object receipts.
    The same instructions may occur at several modes; this API does not infer
    compiler flags from code. No unmatched instruction or NOP is discarded.
    """
    _need(type(mode) is str and mode in MODES, "mode must be exactly O0, Og, O2, Os or O3")
    protocols = _protocols(mode)
    evidence = []
    for side, image in (("Native", native), ("Reference", reference)):
        for name in ROOTS[side]:
            evidence.append(_match(image, side, name, protocols[side][name]))
    mechanisms = [dict(Name=name, NativeRoot=native_name, ReferenceRoots=list(reference_names),
                       DifferenceIds=list(ids)) for name, native_name, reference_names, ids in _MECHANISMS]
    return dict(Verdict="CM0-CLOSED-ROOTS-PASS", Mode=mode,
        Roots={side: list(names) for side, names in ROOTS.items()}, ClosedBodies=8,
        RootEvidence=evidence, Mechanisms=mechanisms,
        DifferenceIds=list(dict.fromkeys(identity for _, _, _, ids in _MECHANISMS for identity in ids)),
        ProofScope="CM0_P2_NO_MPU_EIGHT_CLOSED_ROOT_PROTOCOLS_ONLY",
        DifferenceSource=dict(Spec="tools/freertos_asm_parity.ps1:CM0-non-MPU-mechanisms",
            Ledger="FREERTOS_ASM_PARITY.md", ReferencePin="a50edad08b29052631aa469d4df6e6ec7ff68878"),
        ReferenceSvcObligation=dict(DispatcherRoot="SVC_Handler", CHandlerRoot="vPortSVCHandler_C",
            RestoreRoot="vRestoreContextOfFirstTask", DispatchChainProtocolsMatched=True,
            FirstContextExcReturnProtocolMatched=True, HandlerRoutingProven=False, UnreachabilityProven=False),
        FirstRestoreDifference=dict(DifferenceId="FAP-CM0-STAGED-FRAME",
            Reference="Load EXC_RETURN into r2, write CONTROL=2, skip initial r4-r11 slots",
            Native="Restore the complete nine-word staged software frame",
            InitialRegisterValueEquivalenceProven=False),
        SchedulerThreshold="BASEPRI-NOT-APPLICABLE;PRIMASK-ENVELOPE",
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0, PolicyEquivalence=False,
        CompleteObjectProof=False, CSourceSemanticProof=False, InstructionEquivalence=False,
        CpuExecution=False, BoardExecution=False, FinalElfProof=False, GlobalFreezeQualified=False)
