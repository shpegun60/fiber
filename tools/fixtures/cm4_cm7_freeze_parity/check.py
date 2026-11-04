"""Six complete classic-FP p4/b16 root protocols, not object or CPU proof.

check_pair takes canonical cm55_tfm_parity.elf.Object instances. The caller
binds their reader identity, receipts, cohort, optimization and source hashes.
There is no I/O, process execution or instruction decoder here. Every returned
instruction, literal-island descriptor and tail NOP must match the protocol.
The protocols are transcribed from the selected Fiber C/macros and pinned
FreeRTOS ARM_CM4F / ARM_CM7/r0p1 C, not generated from observed token streams.
"""
import hashlib
import json


class Rejected(RuntimeError):
    pass


def _need(ok, detail):
    if not ok:
        raise Rejected("REJECT:CLASSIC-FP-CLOSED-ROOTS:" + detail)


_CORE = "{r4,r5,r6,r7,r8,r9,r10,r11,lr}"
_FP = "{s16,s17,s18,s19,s20,s21,s22,s23,s24,s25,s26,s27,s28,s29,s30,s31}"


def _body(text):
    """Resolve labels in our fixed specification, never in decoded input."""
    body, labels = [], {}
    for line in text.replace("CORE", _CORE).replace("FPREGS", _FP).strip().splitlines():
        line = line.strip()
        if line.endswith(":"):
            label = line[:-1]
            _need(label not in labels, "duplicate specification label")
            labels[label] = len(body)
        elif line:
            op, _, arg = line.partition(" ")
            body.append((op, arg))
    return [(op, "@" + str(labels[arg[1:]]) if arg.startswith("@") else arg)
            for op, arg in body]


def _island(offset, data, instruction, literal_offset=0, target=None):
    descriptor = dict(Offset=offset, Bytes=data,
        References=[dict(Instruction=instruction, Offset=literal_offset)],
        Relocations=[] if target is None else [dict(Offset=literal_offset, Kind=2, Target=target)])
    return ("@literal-island", json.dumps(descriptor, sort_keys=True, separators=(",", ":")))


def _write_basepri(profile, register):
    write = "msr basepri," + register + "\ndsb #15\nisb #15"
    if profile == "CM7":
        return "mrs r12,primask\ncpsid i\n" + write + "\nmsr primask,r12\ndsb #15\nisb #15"
    return write


# Fiber start/SVC/PendSV: ARM_CM4/fiber_port.c:219/275/395 and
# ARM_CM7/r0p1/fiber_port.c:244/305/425. Frame: core SW36, HW32,
# high FP64, HW FP extension72, xPSR28, alignment4; p4 raw BASEPRI16.
_START = """
cpsid i
dsb #15
isb #15
movs r3,#0
msr control,r3
isb #15
mrs r3,control
tst r3,#7
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
stuck:
b @stuck
fail_l:
movs r0,#108
bl fiber_panic
b @fail_l
"""
_SVC = """
mrs r3,ipsr
cmp r3,#11
bne @fail_l
mvn r3,#6
cmp lr,r3
bne @fail_l
tst lr,#4
bne @fail_l
mrs r0,msp
tst r0,#7
bne @fail_l
ldr r2,[r0,#28]
tst r2,#16777216
beq @fail_l
tst r2,#512
bne @fail_l
ubfx r2,r2,#0,#9
cmp r2,#0
bne @fail_l
ldr r3,[r0,#24]
cmp r3,#2
bcc @fail_u
tst r3,#1
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
movs r0,#0
WRITE0
ldr r0,=fiber_internal_runtime_current_context_slot+0
ldr r0,[r0,#0]
cmp r0,#0
beq @fail_C
stmdb sp!,{r0,lr}
bl fiber_port_context_validate_restore
ldmia sp!,{r2,lr}
ldr r0,[r2,#0]
ldmia r0!,CORE
tst lr,#16
bne @skip_fp
vldmia r0!,FPREGS
skip_fp:
msr psp,r0
isb #15
mrs r3,control
tst r3,#4
bne @fail_j
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
fail_j:
movs r0,#106
bl fiber_panic
b @fail_j
"""
_PENDSV = """
mrs r3,ipsr
cmp r3,#14
bne @fail_j
mvn r3,#2
cmp lr,r3
beq @valid_exc
bic r3,r3,#16
cmp lr,r3
bne @fail_j
valid_exc:
mrs r0,psp
tst r0,#7
bne @fail_d
dsb #15
isb #15
tst lr,#4
beq @fail_j
ldr r1,=fiber_internal_runtime_current_context_slot+0
ldr r1,[r1,#0]
cmp r1,#0
beq @fail_C
stmdb sp!,{r0,r1,r2,lr}
mov r0,r1
bl fiber_port_context_validate_save_current
ldmia sp!,{r0,r1,r2,lr}
ldr r2,[r1,#12]
cmp r0,r2
bcc @fail_d
mov r3,r0
tst lr,#16
bne @save_extent
subs r3,#64
bcc @fail_d
save_extent:
subs r3,#36
bcc @fail_d
cmp r3,r2
bcc @fail_d
ldr r2,[r1,#16]
subs r2,#32
bcc @fail_d
tst lr,#16
bne @hw_extent
subs r2,#72
bcc @fail_d
hw_extent:
cmp r0,r2
bhi @fail_d
ldr r3,[r0,#28]
tst r3,#512
beq @align_done
subs r2,#4
bcc @fail_d
align_done:
cmp r0,r2
bhi @fail_d
tst lr,#16
bne @saved
vstmdb r0!,FPREGS
saved:
stmdb r0!,CORE
str r0,[r1,#0]
mrs r3,basepri
movs r2,#16
stmdb sp!,{r2,r3}
WRITE2
mov r0,r1
bl fiber_port_scheduler_pick_next_from_pendsv
ldmia sp!,{r2,r3}
WRITE3
mov r2,r0
ldr r0,[r2,#0]
ldmia r0!,CORE
tst lr,#16
bne @restored
vldmia r0!,FPREGS
restored:
msr psp,r0
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
"""


def _native(profile):
    svc = _SVC.replace("WRITE0", _write_basepri(profile, "r0"))
    pend = _PENDSV.replace("WRITE2", _write_basepri(profile, "r2")).replace(
        "WRITE3", _write_basepri(profile, "r3"))
    # Exact .ltorg alignment and PC-relative reference locations are retained,
    # including two zero alignment bytes where a word requires them.
    if profile == "CM4":
        svc_pool = _island(208, "00000000", 104, target="fiber_internal_runtime_current_context_slot")
        pend_pool = _island(246, "000000000000", 48, 2, "fiber_internal_runtime_current_context_slot")
    else:
        svc_pool = _island(226, "000000000000", 122, 2, "fiber_internal_runtime_current_context_slot")
        pend_pool = _island(284, "00000000", 50, target="fiber_internal_runtime_current_context_slot")
    return {
        "fiber_port_start_first_context": _body(_START) + [_island(100, "04ed00e0", 54)],
        "SVC_Handler": _body(svc) + [svc_pool],
        "PendSV_Handler": _body(pend) + [pend_pool],
    }


# Pinned FreeRTOS a50edad08b29052631aa469d4df6e6ec7ff68878:
# portable/GCC/ARM_CM4F/port.c:260/278/504;
# portable/GCC/ARM_CM7/r0p1/port.c:254/272/492.
_REFERENCE_START = """
ldr r0,=3758157064
ldr r0,[r0,#0]
ldr r0,[r0,#0]
msr msp,r0
mov r0,#0
msr control,r0
cpsie i
cpsie f
dsb #15
isb #15
svc 0
nop
"""
_REFERENCE_SVC = """
ldr r3,=pxCurrentTCB+0
ldr r1,[r3,#0]
ldr r0,[r1,#0]
ldmia r0!,CORE
msr psp,r0
isb #15
mov r0,#0
msr basepri,r0
bx lr
"""
_REFERENCE_PENDSV = """
mrs r0,psp
isb #15
ldr r3,=pxCurrentTCB+0
ldr r2,[r3,#0]
tst lr,#16
it eq
vstmdbeq r0!,FPREGS
stmdb r0!,CORE
str r0,[r2,#0]
stmdb sp!,{r0,r3}
mov r0,#16
MASK_ENTER
bl vTaskSwitchContext
mov r0,#0
msr basepri,r0
ldmia sp!,{r0,r3}
ldr r1,[r3,#0]
ldr r0,[r1,#0]
ldmia r0!,CORE
tst lr,#16
it eq
vldmiaeq r0!,FPREGS
msr psp,r0
isb #15
bx lr
"""


def _reference(profile):
    enter = "msr basepri,r0\ndsb #15\nisb #15"
    if profile == "CM7":
        enter = "cpsid i\n" + enter + "\ncpsie i"
    return {
        "prvPortStartFirstTask": _body(_REFERENCE_START) + [_island(34, "000008ed00e0", 0, 2)],
        "vPortSVCHandler": _body(_REFERENCE_SVC) + [_island(28, "00000000", 0, target="pxCurrentTCB")],
        "xPortPendSVHandler": _body(_REFERENCE_PENDSV.replace("MASK_ENTER", enter)) + [
            _island(92 if profile == "CM7" else 88, "00000000", 8, target="pxCurrentTCB")],
    }


_NATIVE = {profile: _native(profile) for profile in ("CM4", "CM7")}
_REFERENCE = {profile: _reference(profile) for profile in ("CM4", "CM7")}
_MECHANISMS = (
    ("first-start", "fiber_port_start_first_context", "prvPortStartFirstTask",
     ("FAP-COMMON-START", "FAP-COMMON-PROVENANCE")),
    ("first-restore", "SVC_Handler", "vPortSVCHandler",
     ("FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-FP-VALIDATION")),
    ("PendSV-FP", "PendSV_Handler", "xPortPendSVHandler",
     ("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-FP-VALIDATION")),
)


def _match(image, side, name, expected):
    _need(callable(getattr(image, "function", None)), side + "/canonical Object required")
    actual = image.function(name, literal_islands=True)
    _need(type(actual) is list, side + "/" + name + "/decoder result is not a body")
    tails = [count for count in (0, 1) if actual == expected + [("nop", "")] * count]
    if not tails:
        mismatch = next((i for i, pair in enumerate(zip(actual, expected)) if pair[0] != pair[1]),
                        min(len(actual), len(expected)))
        raise Rejected("REJECT:CLASSIC-FP-CLOSED-ROOTS:%s/%s/token-%d/complete protocol mismatch" % (side, name, mismatch))
    return dict(Side=side, Name=name, Tokens=len(actual), LiteralIslands=1, TailNops=tails[0],
        BodySha256=hashlib.sha256(json.dumps(actual, separators=(",", ":")).encode("ascii")).hexdigest().upper())


def check_pair(native_object, reference_object, profile) -> dict:
    """Match six full bodies for exactly CM4 or CM7, p4/b16 hard FP, no MPU.

    The caller binds mode: O0 has exactly one post-island NOP per root; the
    other four accepted modes have zero. Mixed root layouts are rejected.
    SVC is not a decoder terminal; separately matching reference SVC does not
    prove handler routing or execution. Callee bodies and FPCCR configuration
    are outside these three roots, so eager/lazy policy is unresolved here.
    """
    _need(type(profile) is str and profile in _NATIVE, "profile must be exactly CM4 or CM7")
    evidence = []
    for side, image, protocols in (("Native", native_object, _NATIVE[profile]),
                                   ("Reference", reference_object, _REFERENCE[profile])):
        for name, expected in protocols.items():
            evidence.append(_match(image, side, name, expected))
    _need(len({item["TailNops"] for item in evidence}) == 1, "mixed root tail-NOP layouts")
    mechanisms = []
    for name, native, reference, ids in _MECHANISMS:
        differences = list(ids)
        if profile == "CM7" and name != "first-start":
            differences.append("FAP-CM7-ERRATA-PRIMASK")
        mechanisms.append(dict(Name=name, NativeRoot=native, ReferenceRoot=reference, DifferenceIds=differences))
    return dict(Verdict="CLASSIC-FP-CLOSED-ROOTS-PASS", Profile=profile, Roots=list(_NATIVE[profile]), ClosedBodies=6,
        DifferenceIds=list(dict.fromkeys(identity for row in mechanisms for identity in row["DifferenceIds"])),
        Mechanisms=mechanisms, RootEvidence=evidence,
        ProofScope="CLASSIC_FP_P4_B16_SIX_CLOSED_ROOT_PROTOCOLS_ONLY",
        DifferenceSource=dict(Spec="tools/freertos_asm_parity.ps1:classic-floatingPort-mechanisms",
            Ledger="FREERTOS_ASM_PARITY.md"),
        ReferenceSvcObligation=dict(StartRoot="prvPortStartFirstTask", RestoreRoot="vPortSVCHandler",
            FirstContextExcReturnProtocolMatched=True, HandlerRoutingProven=False, UnreachabilityProven=False),
        FPCCRPolicy=dict(Status="UNRESOLVED-BY-THREE-ROOTS", NativePolicy="eager",
            ReferencePolicy="ASPEN=1,LSPEN=1", PolicyEquivalenceProven=False),
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0, CompleteObjectProof=False,
        InstructionEquivalence=False, CpuExecution=False, BoardExecution=False, FinalElfProof=False,
        GlobalFreezeQualified=False)
