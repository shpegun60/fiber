"""Complete six-root CM3 p4/b16 protocols, not whole-object or CPU proof.

check_pair accepts already constructed canonical cm55_tfm_parity.elf.Object
instances. The caller owns tool/reader identity and receipt/hash/cohort/mode
binding. There is no path handling, file I/O, subprocess or instruction decoder
here. Every returned instruction, literal descriptor and tail NOP is matched.
"""
import hashlib
import json


class Rejected(RuntimeError):
    pass


def _need(ok, detail):
    if not ok:
        raise Rejected("REJECT:CM3-CLOSED-ROOTS:" + detail)


def _instructions(text):
    return [tuple(line.strip().partition(" ")[::2]) for line in text.strip().splitlines()]


def _island(offset, data, instruction, literal_offset=0, target=None):
    descriptor = dict(Offset=offset, Bytes=data,
        References=[dict(Instruction=instruction, Offset=literal_offset)],
        Relocations=[] if target is None else [dict(Offset=literal_offset, Kind=2, Target=target)])
    return ("@literal-island", json.dumps(descriptor, sort_keys=True, separators=(",", ":")))


_NATIVE = {
    "fiber_port_start_first_context": _instructions("""
cpsid i
dsb #15
isb #15
movs r3,#0
msr control,r3
isb #15
mrs r3,control
tst r3,#3
bne @31
cmp r0,#0
beq @18
lsrs r0,r0,#3
lsls r0,r0,#3
msr msp,r0
isb #15
mrs r3,msp
cmp r3,r0
bne @31
ldr r3,=3758157060
mov r2,#134217728
str r2,[r3,#0]
dsb #15
isb #15
cpsie i
cpsie f
dsb #15
isb #15
svc 70
movs r0,#121
bl fiber_panic
b @30
movs r0,#108
bl fiber_panic
b @31
""") + [_island(100, "04ed00e0", 54)],
    "SVC_Handler": _instructions("""
mrs r3,ipsr
cmp r3,#11
bne @58
mvn r3,#6
cmp lr,r3
bne @58
tst lr,#4
bne @58
mrs r0,msp
tst r0,#7
bne @58
ldr r2,[r0,#28]
tst r2,#16777216
beq @58
tst r2,#512
bne @58
ubfx r2,r2,#0,#9
cmp r2,#0
bne @58
ldr r3,[r0,#24]
cmp r3,#2
bcc @61
tst r3,#1
bne @58
subs r3,#2
ldrb r2,[r3,#1]
cmp r2,#223
bne @61
ldrb r3,[r3,#0]
cmp r3,#70
bne @61
cpsid i
dsb #15
isb #15
movs r0,#0
msr basepri,r0
dsb #15
isb #15
ldr r0,=fiber_internal_runtime_current_context_slot+0
ldr r0,[r0,#0]
cmp r0,#0
beq @55
stmdb sp!,{r0,lr}
bl fiber_port_context_validate_restore
ldmia sp!,{r2,lr}
ldr r0,[r2,#0]
ldmia r0!,{r4,r5,r6,r7,r8,r9,r10,r11,lr}
msr psp,r0
isb #15
dsb #15
isb #15
cpsie i
dsb #15
isb #15
bx lr
movs r0,#67
bl fiber_panic
b @55
movs r0,#108
bl fiber_panic
b @58
movs r0,#117
bl fiber_panic
b @61
""") + [_island(180, "00000000", 104, target="fiber_internal_runtime_current_context_slot")],
    "PendSV_Handler": _instructions("""
mrs r3,ipsr
cmp r3,#14
bne @66
mvn r3,#2
cmp lr,r3
bne @66
mrs r0,psp
tst r0,#7
bne @69
dsb #15
isb #15
tst lr,#4
beq @66
ldr r1,=fiber_internal_runtime_current_context_slot+0
ldr r1,[r1,#0]
cmp r1,#0
beq @63
stmdb sp!,{r0,r1,r2,lr}
mov r0,r1
bl fiber_port_context_validate_save_current
ldmia sp!,{r0,r1,r2,lr}
ldr r2,[r1,#12]
cmp r0,r2
bcc @69
mov r3,r0
subs r3,#36
bcc @69
cmp r3,r2
bcc @69
ldr r2,[r1,#16]
subs r2,#32
bcc @69
cmp r0,r2
bhi @69
ldr r3,[r0,#28]
tst r3,#512
beq @39
subs r2,#4
bcc @69
cmp r0,r2
bhi @69
stmdb r0!,{r4,r5,r6,r7,r8,r9,r10,r11,lr}
str r0,[r1,#0]
mrs r3,basepri
movs r2,#16
stmdb sp!,{r2,r3}
msr basepri,r2
dsb #15
isb #15
mov r0,r1
bl fiber_port_scheduler_pick_next_from_pendsv
ldmia sp!,{r2,r3}
msr basepri,r3
dsb #15
isb #15
mov r2,r0
ldr r0,[r2,#0]
ldmia r0!,{r4,r5,r6,r7,r8,r9,r10,r11,lr}
msr psp,r0
isb #15
dsb #15
isb #15
bx lr
movs r0,#67
bl fiber_panic
b @63
movs r0,#106
bl fiber_panic
b @66
movs r0,#100
bl fiber_panic
b @69
""") + [_island(198, "000000000000", 40, 2, "fiber_internal_runtime_current_context_slot")],
}
_REFERENCE = {
    "prvPortStartFirstTask": _instructions("""
ldr r0,=3758157064
ldr r0,[r0,#0]
ldr r0,[r0,#0]
msr msp,r0
cpsie i
cpsie f
dsb #15
isb #15
svc 0
nop
""") + [_island(26, "000008ed00e0", 0, 2)],
    "vPortSVCHandler": _instructions("""
ldr r3,=pxCurrentTCB+0
ldr r1,[r3,#0]
ldr r0,[r1,#0]
ldmia r0!,{r4,r5,r6,r7,r8,r9,r10,r11}
msr psp,r0
isb #15
mov r0,#0
msr basepri,r0
orr lr,lr,#13
bx lr
""") + [_island(32, "00000000", 0, target="pxCurrentTCB")],
    "xPortPendSVHandler": _instructions("""
mrs r0,psp
isb #15
ldr r3,=pxCurrentTCB+0
ldr r2,[r3,#0]
stmdb r0!,{r4,r5,r6,r7,r8,r9,r10,r11}
str r0,[r2,#0]
stmdb sp!,{r3,lr}
mov r0,#16
msr basepri,r0
bl vTaskSwitchContext
mov r0,#0
msr basepri,r0
ldmia sp!,{r3,lr}
ldr r1,[r3,#0]
ldr r0,[r1,#0]
ldmia r0!,{r4,r5,r6,r7,r8,r9,r10,r11}
msr psp,r0
isb #15
bx lr
""") + [_island(62, "000000000000", 8, 2, "pxCurrentTCB")],
}
_MECHANISMS = (
    ("first-start", "fiber_port_start_first_context", "prvPortStartFirstTask",
     ("FAP-COMMON-START", "FAP-COMMON-PROVENANCE", "FAP-CM3-LOCAL-LITERAL-POOLS")),
    ("first-restore", "SVC_Handler", "vPortSVCHandler",
     ("FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-CM3-EXC-RETURN", "FAP-CM3-LOCAL-LITERAL-POOLS")),
    ("PendSV", "PendSV_Handler", "xPortPendSVHandler",
     ("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-CM3-EXC-RETURN", "FAP-CM3-LOCAL-LITERAL-POOLS")),
)


def _match(image, side, name, expected):
    _need(callable(getattr(image, "function", None)), side + "/canonical Object required")
    actual = image.function(name, literal_islands=True)
    _need(type(actual) is list, side + "/" + name + "/decoder result is not a body")
    tails = [count for count in (0, 1) if actual == expected + [("nop", "")] * count]
    if not tails:
        mismatch = next((i for i, pair in enumerate(zip(actual, expected)) if pair[0] != pair[1]),
                        min(len(actual), len(expected)))
        raise Rejected("REJECT:CM3-CLOSED-ROOTS:%s/%s/token-%d/complete protocol mismatch" % (side, name, mismatch))
    return dict(Side=side, Name=name, Tokens=len(actual), LiteralIslands=1, TailNops=tails[0],
                BodySha256=hashlib.sha256(json.dumps(actual, separators=(",", ":")).encode("ascii")).hexdigest().upper())


def check_pair(native_object, reference_object) -> dict:
    """Match six complete canonical bodies for p4/b16; never return partial PASS.

    The two accepted layouts retain zero or one post-island NOP consistently
    across all six roots. The receipt driver binds the selected optimization.
    SVC is not a decoder terminal. The reference first-context EXC_RETURN
    obligation is represented by the separately matched vPortSVCHandler body;
    this does not establish vector routing or execution of that handler.
    """
    evidence = []
    for side, image, protocols in (("Native", native_object, _NATIVE),
                                   ("Reference", reference_object, _REFERENCE)):
        for name, expected in protocols.items():
            evidence.append(_match(image, side, name, expected))
    _need(len({item["TailNops"] for item in evidence}) == 1, "mixed root tail-NOP layouts")
    mechanisms = [dict(Name=name, NativeRoot=native, ReferenceRoot=reference, DifferenceIds=list(ids))
                  for name, native, reference, ids in _MECHANISMS]
    return dict(Verdict="CM3-CLOSED-ROOTS-PASS", Roots=list(_NATIVE), ClosedBodies=6,
        DifferenceIds=list(dict.fromkeys(identity for _, _, _, ids in _MECHANISMS for identity in ids)),
        Mechanisms=mechanisms, RootEvidence=evidence,
        ProofScope="CM3_P4_B16_SIX_CLOSED_ROOT_PROTOCOLS_ONLY",
        DifferenceSource=dict(Spec="tools/freertos_asm_parity.ps1:Assert-Cm3Mechanisms",
                              Ledger="FREERTOS_ASM_PARITY.md"),
        ReferenceSvcObligation=dict(StartRoot="prvPortStartFirstTask", RestoreRoot="vPortSVCHandler",
            FirstContextExcReturnProtocolMatched=True, HandlerRoutingProven=False, UnreachabilityProven=False),
        RequiredCellSatisfied=False, CompleteObjectProof=False, InstructionEquivalence=False,
        CpuExecution=False, FinalElfProof=False, GlobalFreezeQualified=False)
