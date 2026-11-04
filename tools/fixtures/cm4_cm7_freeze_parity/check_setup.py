"""Independent, complete CM4/CM7 eager-vs-lazy setup protocols only.

Native specification: ARM_CM4/fiber_port_boot.c:198 and fiber_portmacro.h:437;
ARM_CM7/r0p1/fiber_port_boot.c:200 and fiber_portmacro.h:573. Reference:
FreeRTOS a50edad08b29052631aa469d4df6e6ec7ff68878 ARM_CM4F/port.c:305/834
and ARM_CM7/r0p1/port.c:299/824, including configASSERT and prvTaskExitError
inlining. The fixed compiler forms retain all surrounding C operations.

No ELF decoder, I/O or learned body hashes. The caller binds canonical reader,
source/receipt identities, compiler recipe and exact hard/eager p4/b16 cohort.
Matching three bodies is not policy equivalence, call-graph or hardware proof.
"""
import hashlib
import json
import re


class Rejected(RuntimeError):
    pass


def _need(ok, detail):
    if not ok:
        raise Rejected("REJECT:FP-SETUP-CLOSED-ROOTS:" + detail)


MODES = ("O0", "Og", "O2", "Os", "O3")
COHORTS = {profile: profile.lower() + "-cortex-m" + profile[-1] +
           "-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default" for profile in ("CM4", "CM7")}
NATIVE_ROOT = "fiber_port_runtime_prepare"
REFERENCE_ROOTS = ("vPortEnableVFP", "xPortStartScheduler")
CPACR, CP_MASK = 0xE000ED88, 0x00F00000
FPCCR, FP_MASK = 0xE000EF34, 0xC0000000
NATIVE_POLICY, REFERENCE_POLICY = 0x80000000, 0xC0000000


def _body(text):
    """Resolve only labels in the fixed specification, not decoded input."""
    rows, labels = [], {}
    for line in text.strip().splitlines():
        line = line.strip()
        if line.endswith(":"):
            _need(line[:-1] not in labels, "duplicate specification label")
            labels[line[:-1]] = len(rows)
        elif line:
            op, _, arg = line.partition(" ")
            rows.append((op, arg))
    return [(op, re.sub(r"@([a-zA-Z_]\w*)", lambda m: "@" + str(labels[m[1]]), arg))
            for op, arg in rows]


def _island(offset, words, refs, relocations=(), padding=0):
    data = b"\0" * padding + b"".join(word.to_bytes(4, "little") for word in words)
    descriptor = dict(Offset=offset, Bytes=data.hex(),
                      References=[dict(Instruction=i, Offset=p) for i, p in refs],
                      Relocations=[dict(Offset=p, Kind=2, Target=t) for p, t in relocations])
    return ("@literal-island", json.dumps(descriptor, sort_keys=True, separators=(",", ":")))


# SHCSR fault enables/readback ('F'), CCR STKALIGN ('A') and DIV_0_TRP ('D')
# precede CPACR ('e'), then ASPEN-set/LSPEN-clear FPCCR ('E'). No body filtering.
_NATIVE_O0 = """
stmdb sp!,{r7,lr}
sub sp,#24
add r7,sp,#0
mov r3,#458752
str r3,[r7,#20]
ldr r3,=3758157056
ldr r2,[r3,#36]
ldr r1,=3758157056
ldr r3,[r7,#20]
orrs r3,r2
str r3,[r1,#36]
dsb #15
isb #15
ldr r3,=3758157056
ldr r2,[r3,#36]
ldr r3,[r7,#20]
ands r3,r2
ldr r2,[r7,#20]
cmp r2,r3
beq @fault_ok
movs r0,#70
bl fiber_panic
fault_ok:
ldr r3,=3758157056
ldr r3,[r3,#20]
ldr r2,=3758157056
orr r3,r3,#512
str r3,[r2,#20]
dsb #15
isb #15
ldr r3,=3758157056
ldr r3,[r3,#20]
and r3,r3,#512
cmp r3,#0
bne @align_ok
movs r0,#65
bl fiber_panic
align_ok:
ldr r3,=3758157056
ldr r3,[r3,#20]
ldr r2,=3758157056
orr r3,r3,#16
str r3,[r2,#20]
dsb #15
isb #15
ldr r3,=3758157056
ldr r3,[r3,#20]
and r3,r3,#16
cmp r3,#0
bne @div_ok
movs r0,#68
bl fiber_panic
div_ok:
mov r3,#15728640
str r3,[r7,#16]
ldr r3,=3758157192
str r3,[r7,#12]
ldr r3,[r7,#12]
ldr r3,[r3,#0]
str r3,[r7,#8]
ldr r2,[r7,#16]
ldr r3,[r7,#8]
ands r3,r2
ldr r2,[r7,#16]
cmp r2,r3
beq @cp_readback
ldr r2,[r7,#8]
ldr r3,[r7,#16]
orrs r3,r2
str r3,[r7,#8]
ldr r3,[r7,#12]
ldr r2,[r7,#8]
str r2,[r3,#0]
dsb #15
isb #15
cp_readback:
ldr r3,[r7,#12]
ldr r2,[r3,#0]
ldr r3,[r7,#16]
ands r3,r2
ldr r2,[r7,#16]
cmp r2,r3
beq @cp_ok
movs r0,#101
bl fiber_panic
cp_ok:
ldr r3,=3758157616
ldr r3,[r3,#4]
str r3,[r7,#0]
movs r3,#0
str r3,[r7,#4]
ldr r3,[r7,#4]
orr r3,r3,#2147483648
str r3,[r7,#4]
ldr r3,[r7,#0]
orr r3,r3,#2147483648
str r3,[r7,#0]
ldr r3,[r7,#4]
orr r3,r3,#1073741824
str r3,[r7,#4]
ldr r3,[r7,#0]
bic r3,r3,#1073741824
str r3,[r7,#0]
ldr r3,=3758157616
ldr r2,[r3,#4]
ldr r3,[r7,#0]
cmp r2,r3
beq @fp_mask
ldr r2,=3758157616
ldr r3,[r7,#0]
str r3,[r2,#4]
dsb #15
isb #15
fp_mask:
ldr r3,[r7,#4]
cmp r3,#0
bne @fp_readback
movs r0,#69
bl fiber_panic
fp_readback:
ldr r3,=3758157616
ldr r2,[r3,#4]
ldr r3,[r7,#0]
eors r2,r3
ldr r3,[r7,#4]
ands r3,r2
cmp r3,#0
beq @fp_ok
movs r0,#69
bl fiber_panic
fp_ok:
nop
bl fiber_port_prepare_start_msp_plan
nop
adds r7,#24
mov sp,r7
ldmia sp!,{r7,pc}
"""
_NATIVE_OG = """
stmdb sp!,{lr}
sub sp,#12
ldr r3,=3758157056
ldr r2,[r3,#36]
orr r2,r2,#458752
str r2,[r3,#36]
dsb #15
isb #15
ldr r3,[r3,#36]
and r3,r3,#458752
cmp r3,#458752
bne @fail_F
ldr r3,=3758157056
ldr r2,[r3,#20]
orr r2,r2,#512
str r2,[r3,#20]
dsb #15
isb #15
ldr r3,[r3,#20]
tst r3,#512
beq @fail_A
ldr r3,=3758157056
ldr r2,[r3,#20]
orr r2,r2,#16
str r2,[r3,#20]
dsb #15
isb #15
ldr r3,[r3,#20]
tst r3,#16
beq @fail_D
mov r3,#3758153728
ldr r3,[r3,#3464]
and r2,r3,#15728640
cmp r2,#15728640
beq @cp_readback
orr r3,r3,#15728640
mov r2,#3758153728
str r3,[r2,#3464]
dsb #15
isb #15
cp_readback:
mov r3,#3758153728
ldr r3,[r3,#3464]
and r3,r3,#15728640
cmp r3,#15728640
bne @fail_e
ldr r2,=3758157568
ldr r3,[r2,#52]
str r3,[sp,#4]
ldr r3,[sp,#4]
orr r3,r3,#2147483648
str r3,[sp,#4]
ldr r3,[sp,#4]
bic r3,r3,#1073741824
str r3,[sp,#4]
ldr r2,[r2,#52]
ldr r3,[sp,#4]
cmp r2,r3
beq @fp_readback
ldr r2,[sp,#4]
ldr r3,=3758157568
str r2,[r3,#52]
dsb #15
isb #15
fp_readback:
ldr r3,=3758157568
ldr r3,[r3,#52]
ldr r2,[sp,#4]
eors r3,r2
cmp r3,#1073741824
bcs @fail_E
bl fiber_port_prepare_start_msp_plan
add sp,#12
ldmia sp!,{pc}
fail_F:
movs r0,#70
bl fiber_panic
fail_A:
movs r0,#65
bl fiber_panic
fail_D:
movs r0,#68
bl fiber_panic
fail_e:
movs r0,#101
bl fiber_panic
fail_E:
movs r0,#69
bl fiber_panic
nop
"""
_NATIVE_O2 = """
PROLOGUE
sub sp,#12
str r2,[r3,#36]
dsb #15
isb #15
ldr r2,[r3,#36]
and r2,r2,#458752
cmp r2,#458752
bne @fail_F
ldr r2,[r3,#20]
orr r2,r2,#512
str r2,[r3,#20]
dsb #15
isb #15
ldr r2,[r3,#20]
lsls r2,r2,#22
bpl @fail_A
ldr r2,[r3,#20]
orr r2,r2,#16
str r2,[r3,#20]
dsb #15
isb #15
ldr r3,[r3,#20]
lsls r3,r3,#27
bpl @fail_D
mov r2,#3758153728
ldr r3,[r2,#3464]
and r1,r3,#15728640
cmp r1,#15728640
beq @cp_readback
orr r3,r3,#15728640
str r3,[r2,#3464]
dsb #15
isb #15
cp_readback:
mov r3,#3758153728
ldr r3,[r3,#3464]
and r3,r3,#15728640
cmp r3,#15728640
bne @fail_e
ldr r2,=3758157568
ldr r3,[r2,#52]
str r3,[sp,#4]
ldr r3,[sp,#4]
orr r3,r3,#2147483648
str r3,[sp,#4]
ldr r3,[sp,#4]
bic r3,r3,#1073741824
str r3,[sp,#4]
ldr r1,[r2,#52]
ldr r3,[sp,#4]
cmp r1,r3
beq @fp_readback
ldr r3,[sp,#4]
str r3,[r2,#52]
dsb #15
isb #15
fp_readback:
ldr r3,=3758157568
ldr r3,[r3,#52]
ldr r2,[sp,#4]
eors r3,r2
cmp r3,#1073741824
bcs @fail_E
add sp,#12
ldr lr,[sp,#0],#4
b fiber_port_prepare_start_msp_plan
fail_F:
movs r0,#70
bl fiber_panic
fail_E:
movs r0,#69
bl fiber_panic
fail_e:
movs r0,#101
bl fiber_panic
fail_D:
movs r0,#68
bl fiber_panic
fail_A:
movs r0,#65
bl fiber_panic
nop
"""
_NATIVE_OS = """
ldr r3,=3758157056
stmdb sp!,{r0,r1,r2,lr}
ldr r2,[r3,#36]
orr r2,r2,#458752
str r2,[r3,#36]
dsb #15
isb #15
ldr r2,[r3,#36]
and r2,r2,#458752
cmp r2,#458752
beq @fault_ok
movs r0,#70
panic:
bl fiber_panic
fault_ok:
ldr r2,[r3,#20]
orr r2,r2,#512
str r2,[r3,#20]
dsb #15
isb #15
ldr r2,[r3,#20]
lsls r2,r2,#22
bmi @align_ok
movs r0,#65
b @panic
align_ok:
ldr r2,[r3,#20]
orr r2,r2,#16
str r2,[r3,#20]
dsb #15
isb #15
ldr r3,[r3,#20]
lsls r3,r3,#27
bmi @div_ok
movs r0,#68
b @panic
div_ok:
mov r2,#3758153728
ldr r3,[r2,#3464]
and r1,r3,#15728640
cmp r1,#15728640
beq @cp_readback
orr r3,r3,#15728640
str r3,[r2,#3464]
dsb #15
isb #15
cp_readback:
mov r3,#3758153728
ldr r3,[r3,#3464]
and r3,r3,#15728640
cmp r3,#15728640
beq @cp_ok
movs r0,#101
b @panic
cp_ok:
ldr r3,=3758157568
ldr r2,[r3,#52]
str r2,[sp,#4]
ldr r2,[sp,#4]
orr r2,r2,#2147483648
str r2,[sp,#4]
ldr r2,[sp,#4]
bic r2,r2,#1073741824
str r2,[sp,#4]
ldr r1,[r3,#52]
ldr r2,[sp,#4]
cmp r1,r2
beq @fp_readback
ldr r2,[sp,#4]
str r2,[r3,#52]
dsb #15
isb #15
fp_readback:
ldr r3,[r3,#52]
ldr r2,[sp,#4]
eors r3,r2
cmp r3,#1073741824
bcc @fp_ok
movs r0,#69
b @panic
fp_ok:
add sp,#12
ldr lr,[sp,#0],#4
b fiber_port_prepare_start_msp_plan
nop
"""


def _native(profile, mode):
    if mode == "O0":
        refs = [(i, 0) for i in (12, 16, 32, 52, 56, 72, 90, 94, 110)]
        refs += [(134, 4)] + [(i, 8) for i in (198, 240, 250, 276)]
        return _body(_NATIVE_O0) + [_island(312, (0xE000ED00, CPACR, 0xE000EF30), refs)]
    if mode == "Og":
        text, offset = _NATIVE_OG, 240
        refs = [(4, 0), (34, 0), (60, 0), (142, 4), (174, 4), (186, 4)]
    elif mode == "Os":
        text, offset, refs = _NATIVE_OS, 216, [(0, 0), (146, 4)]
    else:
        prefix = "ldr r3,=3758157056\nldr r2,[r3,#36]\norr r2,r2,#458752"
        prefix = "stmdb sp!,{lr}\n" + prefix if profile == "CM4" else prefix + "\nstmdb sp!,{lr}"
        text, offset = _NATIVE_O2.replace("PROLOGUE", prefix), 228
        refs = [(2 if profile == "CM4" else 0, 0), (130, 4), (172, 4)]
    return _body(text) + [_island(offset, (0xE000ED00, 0xE000EF00), refs)]


# Reference startup retains handler-installation assertions, NVIC probing and
# restoration, PRIGROUP computation, timer setup and the post-first-task path.
_REF_CPUID_O0 = """
ldr r3,=3758157056
ldr r3,[r3,#0]
ldr r2,=1091551857
cmp r3,r2
bne @cpuid_one_ok
cpuid_one_bad:
nop
b @cpuid_one_bad
cpuid_one_ok:
ldr r3,=3758157056
ldr r3,[r3,#0]
ldr r2,=1091551856
cmp r3,r2
bne @cpuid_zero_ok
cpuid_zero_bad:
nop
b @cpuid_zero_bad
cpuid_zero_ok:
"""
_REFERENCE_O0 = """
stmdb sp!,{r7,lr}
sub sp,#24
add r7,sp,#0
CPUID
ldr r3,=3758157064
ldr r3,[r3,#0]
str r3,[r7,#20]
ldr r3,[r7,#20]
adds r3,#44
ldr r3,[r3,#0]
ldr r2,=vPortSVCHandler+0
cmp r3,r2
beq @svc_ok
svc_bad:
nop
b @svc_bad
svc_ok:
ldr r3,[r7,#20]
adds r3,#56
ldr r3,[r3,#0]
ldr r2,=xPortPendSVHandler+0
cmp r3,r2
beq @pend_ok
pend_bad:
nop
b @pend_bad
pend_ok:
movs r3,#0
str r3,[r7,#8]
ldr r3,=3758154752
str r3,[r7,#16]
ldr r3,[r7,#16]
ldrb r3,[r3,#0]
uxtb r3,r3
strb r3,[r7,#15]
ldr r3,[r7,#16]
movs r2,#255
strb r2,[r3,#0]
ldr r3,[r7,#16]
ldrb r3,[r3,#0]
uxtb r3,r3
strb r3,[r7,#7]
ldrb r3,[r7,#7]
uxtb r3,r3
and r3,r3,#16
uxtb r2,r3
ldr r3,=.bss.ucMaxSysCallPriority+0
strb r2,[r3,#0]
ldr r3,=.bss.ucMaxSysCallPriority+0
ldrb r3,[r3,#0]
cmp r3,#0
bne @threshold_ok
threshold_bad:
nop
b @threshold_bad
threshold_ok:
ldrb r3,[r7,#7]
uxtb r3,r3
mvns r3,r3
and r3,r3,#16
cmp r3,#0
beq @priority_test
unimplemented_bad:
nop
b @unimplemented_bad
priority_loop:
ldr r3,[r7,#8]
adds r3,#1
str r3,[r7,#8]
ldrb r3,[r7,#7]
uxtb r3,r3
lsls r3,r3,#1
uxtb r3,r3
strb r3,[r7,#7]
priority_test:
ldrb r3,[r7,#7]
uxtb r3,r3
and r3,r3,#128
cmp r3,#128
beq @priority_loop
ldr r3,[r7,#8]
cmp r3,#8
bne @less_than_eight
ldr r3,=.bss.ulMaxPRIGROUPValue+0
movs r2,#0
str r2,[r3,#0]
b @group_shift
less_than_eight:
ldr r3,[r7,#8]
rsb r3,r3,#7
ldr r2,=.bss.ulMaxPRIGROUPValue+0
str r3,[r2,#0]
group_shift:
ldr r3,=.bss.ulMaxPRIGROUPValue+0
ldr r3,[r3,#0]
lsls r3,r3,#8
ldr r2,=.bss.ulMaxPRIGROUPValue+0
str r3,[r2,#0]
ldr r3,=.bss.ulMaxPRIGROUPValue+0
ldr r3,[r3,#0]
and r3,r3,#1792
ldr r2,=.bss.ulMaxPRIGROUPValue+0
str r3,[r2,#0]
ldrb r3,[r7,#15]
uxtb r2,r3
ldr r3,[r7,#16]
strb r2,[r3,#0]
ldr r3,=3758157088
ldr r3,[r3,#0]
ldr r2,=3758157088
orr r3,r3,#16711680
str r3,[r2,#0]
ldr r3,=3758157088
ldr r3,[r3,#0]
ldr r2,=3758157088
orr r3,r3,#4278190080
str r3,[r2,#0]
ldr r3,=3758157084
movs r2,#0
str r2,[r3,#0]
bl vPortSetupTimerInterrupt
ldr r3,=.data.uxCriticalNesting+0
movs r2,#0
str r2,[r3,#0]
bl vPortEnableVFP
ldr r3,=3758157620
ldr r3,[r3,#0]
ldr r2,=3758157620
orr r3,r3,#3221225472
str r3,[r2,#0]
bl prvPortStartFirstTask
bl vTaskSwitchContext
bl prvTaskExitError
movs r3,#0
mov r0,r3
adds r7,#24
mov sp,r7
ldmia sp!,{r7,pc}
nop
"""
_REF_CPUID_OG = """
ldr r2,[r3,#3328]
ldr r3,=1091551857
cmp r2,r3
beq @cpuid_one_bad
mov r3,#3758153728
ldr r2,[r3,#3328]
ldr r3,=1091551856
cmp r2,r3
beq @cpuid_zero_bad
mov r3,#3758153728
"""
_REFERENCE_OG = """
mov r3,#3758153728
CPUID
ldr r3,[r3,#3336]
ldr r1,[r3,#44]
ldr r2,=vPortSVCHandler+0
cmp r1,r2
beq @svc_ok
svc_bad:
b @svc_bad
CPUID_FAILURES
svc_ok:
ldr r2,[r3,#56]
ldr r3,=xPortPendSVHandler+0
cmp r2,r3
beq @pend_ok
pend_bad:
b @pend_bad
pend_ok:
stmdb sp!,{r4,r5,lr}
sub sp,#12
movs r3,#0
str r3,[sp,#4]
ldr r3,=3758154752
ldrb r2,[r3,#0]
uxtb r2,r2
strb r2,[sp,#2]
movs r2,#255
strb r2,[r3,#0]
ldrb r3,[r3,#0]
uxtb r3,r3
strb r3,[sp,#3]
ldrb r3,[sp,#3]
and r3,r3,#16
ldr r2,=.bss.ucMaxSysCallPriority+0
strb r3,[r2,#0]
cbnz r3,@threshold_ok
threshold_bad:
b @threshold_bad
threshold_ok:
ldrb r3,[sp,#3]
tst r3,#16
bne @priority_test
unimplemented_bad:
b @unimplemented_bad
priority_test:
ldrb r3,[sp,#3]
tst r3,#128
beq @priority_done
ldr r3,[sp,#4]
adds r3,#1
str r3,[sp,#4]
ldrb r3,[sp,#3]
lsls r3,r3,#1
uxtb r3,r3
strb r3,[sp,#3]
b @priority_test
priority_done:
ldr r3,[sp,#4]
cmp r3,#8
beq @eight_bits
ldr r3,[sp,#4]
rsb r3,r3,#7
ldr r2,=.bss.ulMaxPRIGROUPValue+0
str r3,[r2,#0]
group_shift:
ldr r2,=.bss.ulMaxPRIGROUPValue+0
ldr r3,[r2,#0]
lsls r3,r3,#8
str r3,[r2,#0]
and r3,r3,#1792
str r3,[r2,#0]
ldrb r3,[sp,#2]
uxtb r3,r3
ldr r2,=3758154752
strb r3,[r2,#0]
mov r4,#3758153728
ldr r3,[r4,#3360]
orr r3,r3,#16711680
str r3,[r4,#3360]
ldr r3,[r4,#3360]
orr r3,r3,#4278190080
str r3,[r4,#3360]
movs r5,#0
str r5,[r4,#3356]
bl vPortSetupTimerInterrupt
ldr r3,=.data.uxCriticalNesting+0
str r5,[r3,#0]
bl vPortEnableVFP
ldr r3,[r4,#3892]
orr r3,r3,#3221225472
str r3,[r4,#3892]
bl prvPortStartFirstTask
bl vTaskSwitchContext
bl prvTaskExitError
mov r0,r5
add sp,#12
ldmia sp!,{r4,r5,pc}
eight_bits:
ldr r3,=.bss.ulMaxPRIGROUPValue+0
movs r2,#0
str r2,[r3,#0]
b @group_shift
"""

# O2/O3 retain the compiler's inlined prvTaskExitError, including the CM7
# BASEPRI workaround. It is not dropped as unreachable after first start.
_REF_O2_CM4_PREFIX = """
mov r3,#3758153728
ldr r2,=1091551857
ldr r1,[r3,#3328]
cmp r1,r2
beq @cpuid_one_bad
ldr r1,[r3,#3328]
ldr r2,=1091551856
cmp r1,r2
beq @cpuid_zero_bad
ldr r3,[r3,#3336]
ldr r2,=vPortSVCHandler+0
ldr r1,[r3,#44]
cmp r1,r2
beq @svc_ok
svc_bad:
b @svc_bad
cpuid_one_bad:
b @cpuid_one_bad
cpuid_zero_bad:
b @cpuid_zero_bad
"""
_REF_O2_CM7_PREFIX = """
mov r3,#3758153728
ldr r2,=vPortSVCHandler+0
ldr r3,[r3,#3336]
ldr r1,[r3,#44]
cmp r1,r2
beq @svc_ok
svc_bad:
b @svc_bad
"""
_REF_O2_PRIORITY = """
uxtb r3,r3
strb r3,[sp,#7]
ldrb r3,[sp,#7]
and r3,r3,#16
strb r3,[THRESHOLD,#0]
cmp r3,#0
beq @threshold_bad
ldrb r3,[sp,#7]
lsls r2,r3,#27
bpl @unimplemented_bad
b @priority_test
priority_loop:
ldr r3,[sp,#8]
adds r3,#1
str r3,[sp,#8]
ldrb r3,[sp,#7]
lsls r3,r3,#1
uxtb r3,r3
strb r3,[sp,#7]
priority_test:
ldrb r3,[sp,#7]
lsls r3,r3,#24
bmi @priority_loop
ldr r3,[sp,#8]
cmp r3,#8
beq @eight_bits
ldr r3,[sp,#8]
rsb r3,r3,#7
lsls r3,r3,#8
and r3,r3,#1792
group_restore:
ldrb r2,[sp,#6]
"""
_REF_O2_TAIL = """
bl vPortSetupTimerInterrupt
str r5,[r6,#0]
bl vPortEnableVFP
ldr r3,[r4,#3892]
orr r3,r3,#3221225472
str r3,[r4,#3892]
bl prvPortStartFirstTask
bl vTaskSwitchContext
ldr r3,[r6,#0]
str r5,[sp,#12]
adds r3,#1
beq @exit_disable
exit_bad:
b @exit_bad
threshold_bad:
b @threshold_bad
unimplemented_bad:
b @unimplemented_bad
exit_disable:
mov r3,#16
EXIT_MASK
exit_wait:
ldr r3,[sp,#12]
cmp r3,#0
beq @exit_wait
movs r0,#0
add sp,#16
ldmia sp!,{r4,r5,r6,pc}
eight_bits:
movs r3,#0
b @group_restore
nop
"""


def _reference_o2(profile):
    if profile == "CM4":
        text = _REF_O2_CM4_PREFIX + """
svc_ok:
ldr r2,=xPortPendSVHandler+0
ldr r3,[r3,#56]
cmp r3,r2
beq @pend_ok
pend_bad:
b @pend_bad
pend_ok:
stmdb sp!,{r4,r5,r6,lr}
sub sp,#16
ldr r3,=3758154752
movs r2,#0
str r2,[sp,#8]
ldrb r2,[r3,#0]
movs r1,#255
uxtb r2,r2
strb r2,[sp,#6]
strb r1,[r3,#0]
ldrb r3,[r3,#0]
ldr r2,=.bss.ucMaxSysCallPriority+0
""" + _REF_O2_PRIORITY.replace("THRESHOLD", "r2") + """
ldr r0,=.bss.ulMaxPRIGROUPValue+0
ldr r1,=3758154752
str r3,[r0,#0]
mov r4,#3758153728
uxtb r2,r2
strb r2,[r1,#0]
ldr r3,[r4,#3360]
ldr r6,=.data.uxCriticalNesting+0
orr r3,r3,#16711680
str r3,[r4,#3360]
ldr r3,[r4,#3360]
movs r5,#0
orr r3,r3,#4278190080
str r3,[r4,#3360]
str r5,[r4,#3356]
"""
        mask = "msr basepri,r3\nisb #15\ndsb #15"
    else:
        text = _REF_O2_CM7_PREFIX + """
svc_ok:
ldr r2,=xPortPendSVHandler+0
ldr r3,[r3,#56]
cmp r3,r2
beq @pend_ok
pend_bad:
b @pend_bad
pend_ok:
stmdb sp!,{r4,r5,r6,lr}
ldr r3,=3758154752
sub sp,#16
movs r2,#0
movs r0,#255
ldr r1,=.bss.ucMaxSysCallPriority+0
str r2,[sp,#8]
ldrb r2,[r3,#0]
uxtb r2,r2
strb r2,[sp,#6]
strb r0,[r3,#0]
ldrb r3,[r3,#0]
""" + _REF_O2_PRIORITY.replace("THRESHOLD", "r1") + """
mov r4,#3758153728
ldr r0,=.bss.ulMaxPRIGROUPValue+0
movs r5,#0
ldr r1,=3758154752
uxtb r2,r2
str r3,[r0,#0]
strb r2,[r1,#0]
ldr r3,[r4,#3360]
ldr r6,=.data.uxCriticalNesting+0
orr r3,r3,#16711680
str r3,[r4,#3360]
ldr r3,[r4,#3360]
orr r3,r3,#4278190080
str r3,[r4,#3360]
str r5,[r4,#3356]
"""
        mask = "cpsid i\nmsr basepri,r3\nisb #15\ndsb #15\ncpsie i"
    return text + _REF_O2_TAIL.replace("EXIT_MASK", mask)


_REF_OS_CM4_PREFIX = """
mov r3,#3758153728
stmdb sp!,{r0,r1,r2,r4,r5,lr}
ldr r1,[r3,#3328]
ldr r2,=1091551857
cmp r1,r2
bne @cpuid_one_ok
cpuid_one_bad:
b @cpuid_one_bad
cpuid_one_ok:
ldr r1,[r3,#3328]
ldr r2,=1091551856
cmp r1,r2
bne @cpuid_zero_ok
cpuid_zero_bad:
b @cpuid_zero_bad
cpuid_zero_ok:
ldr r3,[r3,#3336]
ldr r2,=vPortSVCHandler+0
ldr r1,[r3,#44]
cmp r1,r2
beq @svc_ok
svc_bad:
b @svc_bad
"""
_REF_OS_CM7_PREFIX = """
mov r3,#3758153728
ldr r3,[r3,#3336]
stmdb sp!,{r0,r1,r2,r4,r5,lr}
ldr r1,[r3,#44]
ldr r2,=vPortSVCHandler+0
cmp r1,r2
beq @svc_ok
svc_bad:
b @svc_bad
"""
_REF_OS_PRIORITY = """
svc_ok:
ldr r2,[r3,#56]
ldr r3,=xPortPendSVHandler+0
cmp r2,r3
beq @pend_ok
pend_bad:
b @pend_bad
pend_ok:
movs r3,#0
str r3,[sp,#4]
ldr r3,=3758154752
ldrb r2,[r3,#0]
uxtb r2,r2
strb r2,[sp,#2]
movs r2,#255
strb r2,[r3,#0]
ldrb r3,[r3,#0]
ldr r2,=.bss.ucMaxSysCallPriority+0
uxtb r3,r3
strb r3,[sp,#3]
ldrb r3,[sp,#3]
and r3,r3,#16
strb r3,[r2,#0]
cbnz r3,@threshold_ok
threshold_bad:
b @threshold_bad
threshold_ok:
ldrb r3,[sp,#3]
lsls r3,r3,#27
bmi @priority_test
unimplemented_bad:
b @unimplemented_bad
priority_loop:
adds r3,#1
str r3,[sp,#4]
ldrb r3,[sp,#3]
lsls r3,r3,#1
uxtb r3,r3
strb r3,[sp,#3]
priority_test:
ldrb r3,[sp,#3]
tst r3,#128
ldr r3,[sp,#4]
bne @priority_loop
cmp r3,#8
"""


def _reference_os(profile):
    if profile == "CM4":
        return _REF_OS_CM4_PREFIX + _REF_OS_PRIORITY + """
it ne
ldrne r3,[sp,#4]
ldr r2,=.bss.ulMaxPRIGROUPValue+0
ite ne
rsbne r3,r3,#7
moveq r3,#0
lsls r3,r3,#8
and r3,r3,#1792
str r3,[r2,#0]
ldrb r3,[sp,#2]
ldr r2,=3758154752
mov r4,#3758153728
uxtb r3,r3
strb r3,[r2,#0]
ldr r3,[r4,#3360]
orr r3,r3,#16711680
str r3,[r4,#3360]
ldr r3,[r4,#3360]
movs r5,#0
orr r3,r3,#4278190080
str r3,[r4,#3360]
str r5,[r4,#3356]
bl vPortSetupTimerInterrupt
ldr r3,=.data.uxCriticalNesting+0
str r5,[r3,#0]
bl vPortEnableVFP
ldr r3,[r4,#3892]
orr r3,r3,#3221225472
str r3,[r4,#3892]
bl prvPortStartFirstTask
bl vTaskSwitchContext
bl prvTaskExitError
mov r0,r5
add sp,#12
ldmia sp!,{r4,r5,pc}
"""
    return _REF_OS_CM7_PREFIX + _REF_OS_PRIORITY + """
beq @eight_bits
ldr r3,[sp,#4]
rsb r3,r3,#7
group_shift:
lsls r3,r3,#8
ldr r2,=.bss.ulMaxPRIGROUPValue+0
mov r4,#3758153728
movs r5,#0
and r3,r3,#1792
str r3,[r2,#0]
ldrb r3,[sp,#2]
ldr r2,=3758154752
uxtb r3,r3
strb r3,[r2,#0]
ldr r3,[r4,#3360]
orr r3,r3,#16711680
str r3,[r4,#3360]
ldr r3,[r4,#3360]
orr r3,r3,#4278190080
str r3,[r4,#3360]
str r5,[r4,#3356]
bl vPortSetupTimerInterrupt
ldr r3,=.data.uxCriticalNesting+0
str r5,[r3,#0]
bl vPortEnableVFP
ldr r3,[r4,#3892]
orr r3,r3,#3221225472
str r3,[r4,#3892]
bl prvPortStartFirstTask
bl vTaskSwitchContext
mov r0,r5
bl prvTaskExitError
add sp,#12
ldmia sp!,{r4,r5,pc}
eight_bits:
movs r3,#0
b @group_shift
"""


def _scheduler_island(profile, mode):
    targets = ("vPortSVCHandler", "xPortPendSVHandler", ".bss.ucMaxSysCallPriority",
               ".bss.ulMaxPRIGROUPValue", ".data.uxCriticalNesting")
    if mode == "O0":
        if profile == "CM4":
            words = (0xE000ED00, 0x410FC271, 0x410FC270, 0xE000ED08, 0, 0,
                     0xE000E400, 0, 0, 0xE000ED20, 0xE000ED1C, 0, FPCCR)
            refs = [(6, 0), (10, 4), (20, 0), (24, 8), (34, 12), (46, 16), (62, 20),
                    (76, 24), (112, 28), (116, 28), (180, 32), (194, 32), (198, 32),
                    (204, 32), (208, 32), (216, 32), (228, 36), (232, 36), (240, 36),
                    (244, 36), (252, 40), (262, 44), (272, 48), (276, 48)]
            offset, slots = 308, (16, 20, 28, 32, 44)
        else:
            words = (0xE000ED08, 0, 0, 0xE000E400, 0, 0, 0xE000ED20, 0xE000ED1C, 0, FPCCR)
            refs = [(6, 0), (18, 4), (34, 8), (48, 12), (84, 16), (88, 16), (152, 20),
                    (166, 20), (170, 20), (176, 20), (180, 20), (188, 20), (200, 24),
                    (204, 24), (212, 24), (216, 24), (224, 28), (234, 32), (244, 36), (248, 36)]
            offset, slots = 280, (4, 8, 16, 20, 32)
    else:
        words = (0, 0, 0xE000E400, 0, 0, 0)
        if profile == "CM4":
            words = (0x410FC271, 0x410FC270) + words
            slots = (8, 12, 20, 24, 28)
            if mode == "Og":
                offset = 272
                refs = [(8, 0), (22, 4), (38, 8), (52, 12), (68, 16), (98, 20),
                        (160, 24), (164, 24), (184, 16), (226, 28), (264, 24)]
            elif mode == "Os":
                offset = 244
                refs = [(10, 0), (22, 4), (34, 8), (46, 12), (58, 16), (74, 20),
                        (140, 24), (162, 16), (206, 28)]
            else:
                offset = 280
                refs = [(4, 0), (18, 4), (28, 8), (42, 12), (56, 16), (76, 20),
                        (156, 24), (158, 16), (174, 28)]
        else:
            slots = (0, 4, 12, 16, 20)
            if mode == "Og":
                offset = 240
                refs = [(10, 0), (20, 4), (36, 8), (66, 12), (128, 16), (132, 16),
                        (152, 8), (194, 20), (232, 16)]
            elif mode == "Os":
                offset = 220
                refs = [(12, 0), (22, 4), (34, 8), (50, 12), (122, 16), (140, 8), (178, 20)]
            else:
                offset = 260
                refs = [(4, 0), (18, 4), (30, 8), (38, 12), (136, 16), (140, 8), (152, 20)]
    return _island(offset, words, refs, tuple(zip(slots, targets)))


def _reference(profile, mode):
    enable = _body("""
ldr r0,=3758157192
ldr r1,[r0,#0]
orr r1,r1,#15728640
str r1,[r0,#0]
bx lr
""") + [_island(14, (CPACR,), ((0, 2),), padding=2)]
    if mode == "O0":
        enable.append(("nop", ""))
        text = _REFERENCE_O0.replace("CPUID", _REF_CPUID_O0 if profile == "CM4" else "")
    elif mode == "Og":
        failures = "cpuid_one_bad:\nb @cpuid_one_bad\ncpuid_zero_bad:\nb @cpuid_zero_bad"
        text = _REFERENCE_OG.replace("CPUID_FAILURES", failures if profile == "CM4" else "")
        text = text.replace("CPUID", _REF_CPUID_OG if profile == "CM4" else "")
    elif mode == "Os":
        text = _reference_os(profile)
    else:
        text = _reference_o2(profile)
    return {"vPortEnableVFP": enable,
            "xPortStartScheduler": _body(text) + [_scheduler_island(profile, mode)]}


def protocols(profile, mode):
    _need(type(profile) is str and profile in COHORTS, "profile must be exactly CM4 or CM7")
    _need(type(mode) is str and mode in MODES, "mode must be exactly O0/Og/O2/Os/O3")
    return {NATIVE_ROOT: _native(profile, mode)}, _reference(profile, mode)


def _match(image, side, name, expected):
    _need(callable(getattr(image, "function", None)), side + "/canonical Object required")
    actual = image.function(name, literal_islands=True)
    _need(type(actual) is list, side + "/" + name + "/decoder result is not a body")
    if actual != expected:
        index = next((i for i, pair in enumerate(zip(actual, expected)) if pair[0] != pair[1]),
                     min(len(actual), len(expected)))
        raise Rejected("REJECT:FP-SETUP-CLOSED-ROOTS:%s/%s/token-%d/complete protocol mismatch" % (side, name, index))
    return dict(Side=side, Name=name, Tokens=len(actual), LiteralIslands=1,
                BodySha256=hashlib.sha256(json.dumps(actual, separators=(",", ":")).encode("ascii")).hexdigest().upper())


def check_pair(native_object, reference_object, profile, mode) -> dict:
    """Match all three complete emitted bodies for the caller-bound exact cohort.

    Expected protocols are independent of input. Body hashes are output evidence
    only, not admission rules. No alternate tails, ignored helpers or subsequences.
    This neither executes MMIO nor proves a callee, startup routing, or LSPACT.
    """
    native, reference = protocols(profile, mode)
    evidence = [_match(image, side, name, expected)
                for side, image, bodies in (("Native", native_object, native),
                                            ("Reference", reference_object, reference))
                for name, expected in bodies.items()]
    return dict(Verdict="FP-SETUP-CLOSED-ROOTS-PASS", Profile=profile, Mode=mode,
                Cohort=COHORTS[profile], ClosedBodies=3, RootEvidence=evidence,
                ProofScope="CM4_CM7_HARD_EAGER_P4_B16_THREE_COMPLETE_SETUP_PROTOCOLS_ONLY",
                DifferenceIds=["fpccr-eager-vs-lazy", "native-conditional-stores-barriers-readbacks"],
                DistinctContractsChecked=True, CPACR=dict(Address=CPACR, AccessMask=CP_MASK),
                FPCCR=dict(Address=FPCCR, PolicyMask=FP_MASK, NativeBits=NATIVE_POLICY,
                           ReferenceBits=REFERENCE_POLICY, NativePolicy="eager", ReferencePolicy="lazy",
                           PolicyEquivalenceProven=False, HardwareReadbackProven=False,
                           LspactHandlingProven=False),
                ReferencePin="a50edad08b29052631aa469d4df6e6ec7ff68878",
                RequiredCellSatisfied=False, RequiredCellsSatisfied=0, CompleteObjectProof=False,
                InstructionEquivalence=False, CpuExecution=False, BoardExecution=False,
                FinalElfProof=False, GlobalFreezeQualified=False, StartupRoutingProven=False,
                CalleeBodiesProven=False, UnreachabilityProven=False)
