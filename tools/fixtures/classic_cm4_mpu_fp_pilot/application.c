#include "fixture.h"
#if PILOT_FIBER
#include "fiber/lifecycle/fiber_v1.h"
#else
#include "context/context.h"
#endif
#include <stddef.h>

#if !defined(PILOT_FIBER) || (PILOT_FIBER != 0 && PILOT_FIBER != 1)
#error "PILOT_FIBER must select Context or FiberV1"
#endif
#if !defined(PILOT_LAZY) || (PILOT_LAZY != 0 && PILOT_LAZY != 1)
#error "PILOT_LAZY must select eager or lazy FP preservation"
#endif
#if !defined(FIBER_FPU_LAZY) || FIBER_FPU_LAZY != PILOT_LAZY
#error "fixture and production FP policies must agree"
#endif

/* Semihost stderr only; stdout must remain empty. Hex fields are eight uppercase
 * digits. Success is exactly these three lines, followed by exit(0):
 * CHECK:CM4-MPU-FP:API=CONTEXT|FIBERV1:LAZY=0|1:CALLS=00000017:SELF=00000001:CROSS=00000015:EXT0=00000008:EXT1=00000007:BASIC2=00000007:CHALLENGE=0000000F:POSTCONTROL=<mask>:LSPACT=00000000
 * RETURN:CM4-MPU-FP:CODE=00000052:IPSR=0000000B:PC=<pc>:PSP=<psp>:XPSR=<xpsr>
 * PASS:CM4-MPU-FP:CONTEXT|FIBERV1:LAZY=0|1
 * A fixture failure is exactly two lines, followed by exit(66):
 * REASON:CM4-MPU-FP:CODE=<code>:WORKER=<index>:PHASE=<phase>
 * FAIL:CM4-MPU-FP
 * POSTCONTROL is the OR of (1 << raw Handler CONTROL) observed after save;
 * only raw values 1/5 are admitted. No pre-save LSPACT observation is claimed.
 */

typedef struct Mailbox {
    uint32_t entered, initial_control, identity, current_reads;
    uint32_t control, ipsr, sp, error, rounds, returning;
} Mailbox;

typedef struct TaskArgument {
    uint32_t index;
    void *identity;
    volatile Mailbox *mailbox;
    volatile ProbeBox *probe;
} TaskArgument;

typedef struct PilotReport {
    uint32_t selections, self, cross, previous;
    uint32_t saved[3], public_saves[3], direct_saves[3];
    uint32_t challenges, post_control_mask, post_lspact;
} PilotReport;

_Static_assert(sizeof(ProbeBox) == PILOT_BOX_BYTES, "FP probe box size");
_Static_assert(offsetof(ProbeBox, phase) == PILOT_BOX_PHASE, "FP probe phase");
_Static_assert(offsetof(ProbeBox, completed) == PILOT_BOX_COMPLETED, "FP probe count");
_Static_assert(offsetof(ProbeBox, before_sp) == PILOT_BOX_BEFORE_SP, "FP probe before SP");
_Static_assert(offsetof(ProbeBox, after_sp) == PILOT_BOX_AFTER_SP, "FP probe after SP");
_Static_assert(offsetof(ProbeBox, control) == PILOT_BOX_CONTROL, "FP probe CONTROL");
_Static_assert(offsetof(ProbeBox, reason) == PILOT_BOX_REASON, "FP probe reason");
_Static_assert(offsetof(ProbeBox, cookie0) == PILOT_BOX_COOKIE0, "FP probe cookie0");
_Static_assert(offsetof(ProbeBox, cookie1) == PILOT_BOX_COOKIE1, "FP probe cookie1");
_Static_assert(offsetof(ProbeBox, registers) == PILOT_BOX_GPRS, "FP probe GPRs");
_Static_assert(offsetof(ProbeBox, fp_checks) == PILOT_BOX_FP_CHECKS, "FP probe FP checks");
_Static_assert(offsetof(ProbeBox, fpscr_checks) == PILOT_BOX_FPSCR_CHECKS, "FP probe FPSCR checks");

static volatile PilotReport report;
static volatile uint32_t initialized_data = 0xc04f4a71u;
#if PILOT_FIBER
static FiberV1 workers[3];
static FiberRuntimeV1 runtime = FIBER_RUNTIME_V1_INITIALIZER;
#else
static CtxrtContextV1 workers[3];
#endif
static const TaskArgument arguments[3] __attribute__((section(".fixture_user_rodata"))) = {
    { 0u, &workers[0], (volatile Mailbox *)0x20002080u, (volatile ProbeBox *)0x20002100u },
    { 1u, &workers[1], (volatile Mailbox *)0x20004080u, (volatile ProbeBox *)0x20004100u },
    { 2u, &workers[2], (volatile Mailbox *)0x20006080u, (volatile ProbeBox *)0x20006100u }
};
extern const unsigned char fiber_port_svc_return_return_site[];

static PILOT_GRO uint32_t read_ipsr(void)
{
    uint32_t value;
    __asm volatile("mrs %0,ipsr" : "=r"(value));
    return value;
}
static PILOT_GRO uint32_t read_control(void)
{
    uint32_t value;
    __asm volatile("mrs %0,control" : "=r"(value));
    return value;
}
static PILOT_GRO uint32_t read_psp(void)
{
    uint32_t value;
    __asm volatile("mrs %0,psp" : "=r"(value));
    return value;
}
static PILOT_GRO uint32_t read_sp(void)
{
    uint32_t value;
    __asm volatile("mov %0,sp" : "=r"(value));
    return value;
}
static PILOT_NORETURN PILOT_GRO void fail(uint32_t code, uint32_t worker, uint32_t phase)
{
    fixture_write("REASON:CM4-MPU-FP:CODE="); fixture_hex(code);
    fixture_write(":WORKER="); fixture_hex(worker);
    fixture_write(":PHASE="); fixture_hex(phase);
    fixture_write("\nFAIL:CM4-MPU-FP\n");
    fixture_exit(66u);
}
static PILOT_GRO void require(int valid, uint32_t code)
{
    if (!valid) {
        fail(code, report.previous, 0u);
    }
}
static PILOT_GRO CtxrtContextV1 *context_of(uint32_t index)
{
#if PILOT_FIBER
    return &workers[index].private_context;
#else
    return &workers[index];
#endif
}
static PILOT_GRO volatile Mailbox *mailbox_of(uint32_t index)
{
    return (volatile Mailbox *)(uintptr_t)(0x20002080u + index * 0x2000u);
}
static PILOT_GRO volatile ProbeBox *probe_of(uint32_t index)
{
    return (volatile ProbeBox *)(uintptr_t)(0x20002100u + index * 0x2000u);
}

PILOT_USER void *fixture_task_current(void)
{
#if PILOT_FIBER
    return fiber_v1_current();
#else
    return ctxrt_v1_current();
#endif
}
PILOT_USER void fixture_task_yield(void)
{
#if PILOT_FIBER
    fiber_v1_yield();
#else
    ctxrt_v1_yield();
#endif
}
static PILOT_NORETURN PILOT_USER void task_fail(const TaskArgument *arg, uint32_t reason)
{
    arg->mailbox->error = reason;
    /* The next real PendSV reports the error in privileged code. No task
     * accesses semihosting, privileged MMIO, or another task's memory. */
    for (;;) {
        fixture_task_yield();
    }
}
static PILOT_USER void task_check(const TaskArgument *arg, uint32_t expected_control)
{
    uint32_t control, ipsr, sp;
    __asm volatile("mrs %0,control\nmrs %1,ipsr\nmov %2,sp"
            : "=r"(control), "=r"(ipsr), "=r"(sp));
    volatile Mailbox *const box = arg->mailbox;
    box->identity = (uint32_t)(uintptr_t)fixture_task_current();
    ++box->current_reads;
    box->control = control;
    box->ipsr = ipsr;
    box->sp = sp;
    const uint32_t base = 0x20002000u + arg->index * 0x2000u;
    if (control != expected_control) {
        task_fail(arg, expected_control == 3u ? PILOT_REASON_INITIAL_CONTROL : PILOT_REASON_FPCA);
    }
    if (ipsr != 0u) {
        task_fail(arg, PILOT_REASON_IPSR);
    }
    if (box->identity != (uint32_t)(uintptr_t)arg->identity ||
            sp < base + 0x200u || sp > base + 4096u || (sp & 7u) != 0u) {
        task_fail(arg, 0x101u);
    }
}
PILOT_USER void fixture_task_entry(void *argument)
{
    const TaskArgument *const arg = (const TaskArgument *)argument;
    task_check(arg, 3u);
    arg->mailbox->entered = 1u;
    arg->mailbox->initial_control = arg->mailbox->control;
    for (uint32_t round = 0u; round != 4u; ++round) {
        const uint32_t reason = fixture_fp_probe(arg->index, arg->probe);
        if (reason != 0u) {
            task_fail(arg, reason);
        }
        ++arg->mailbox->rounds;
        task_check(arg, arg->index == 2u ? 3u : 7u);
    }
    if (arg->index != 0u) {
        task_fail(arg, 0x104u);
    }
    arg->mailbox->returning = 1u;
    /* Constructor-seeded LR enters the production SVC72 return veneer. */
}

static PILOT_GRO void observe_saved(uint32_t index)
{
    CtxrtContextV1 *const ctx = context_of(index);
    volatile Mailbox *const mailbox = mailbox_of(index);
    volatile ProbeBox *const probe = probe_of(index);
    if (mailbox->error != 0u) {
        fail(mailbox->error, index, probe->phase);
    }
    require(mailbox->entered == 1u && mailbox->initial_control == 3u &&
            mailbox->identity == (uint32_t)(uintptr_t)&workers[index], 0x204u);
    require(probe->phase == 1u || probe->phase == 2u, 0x205u);

    const FiberPortProtectedCoreContext *core;
    const FiberPortProtectedHardwareFrame *hardware;
    const uint32_t bytes = index == 2u ? 32u : 104u;
    if (index == 2u) {
        require(ctx->protected_context_cursor == &ctx->protected_context.basic.cursor_limit, 0x206u);
        core = &ctx->protected_context.basic.core;
        hardware = &ctx->protected_context.basic.hardware;
        require(core->exc_return == 0xfffffffdu, 0x207u);
    } else {
        require(ctx->protected_context_cursor == &ctx->protected_context.extended.cursor_limit, 0x208u);
        core = &ctx->protected_context.extended.core;
        hardware = &ctx->protected_context.extended.hardware;
        require(core->exc_return == 0xffffffedu &&
                ctx->protected_context.extended.cursor_limit == 0u, 0x209u);
    }
    require(core->control == 1u, 0x20au);
    const uint32_t base = 0x20002000u + index * 0x2000u;
    const uint32_t padding = (hardware->xpsr & 0x200u) != 0u ? 4u : 0u;
    require((hardware->psp & 7u) == 0u && hardware->psp >= base + 0x200u &&
            hardware->psp <= base + 4096u - bytes - padding, 0x20bu);
    require((hardware->xpsr & 0x010001ffu) == 0x01000000u && (hardware->pc & 1u) == 0u &&
            hardware->pc >= 0x10000u && hardware->pc < 0x20000u, 0x20cu);

    const uint32_t control = read_control();
    const uint32_t fpccr = *(volatile uint32_t *)0xe000ef34u;
    require(control == 1u || control == 5u, 0x20du);
    require((fpccr & 0xc0000001u) == (0x80000000u | ((uint32_t)PILOT_LAZY << 30)), 0x20eu);
    require((*(volatile uint32_t *)0xe000ed88u & 0x00f00000u) == 0x00f00000u, 0x20fu);
    report.post_control_mask |= 1u << control;
    report.post_lspact |= fpccr & 1u;
    ++report.saved[index];
    if (probe->phase == 1u) {
        ++report.public_saves[index];
    } else {
        ++report.direct_saves[index];
    }

    if (index != 2u) {
        /* Production has already copied this frame into privileged storage.
         * Poison only low16/FPSCR in the outgoing user frame, not its core8 or
         * reserved word. Even a self-selection must reconstruct these words.
         * Payload assertions remain in the resumed assembly oracle, so save/
         * restore mutants fail for FP data, not a scheduler payload check. */
        volatile uint32_t *const low = (volatile uint32_t *)(uintptr_t)(hardware->psp + 32u);
        for (uint32_t word = 0u; word != 16u; ++word) {
            low[word] = 0x3e800000u + word;
        }
        low[16] = 0x00800000u;
        __asm volatile("dsb" ::: "memory");
        ++report.challenges;
    }
}
static PILOT_GRO uint32_t select_index(uint32_t current)
{
    if (current == 3u) {
        require(report.selections == 0u && read_ipsr() == 0u, 0x201u);
        report.previous = 0u;
        ++report.selections;
        return 0u;
    }
    uint32_t basepri, primask, faultmask;
    __asm volatile("mrs %0,basepri\nmrs %1,primask\nmrs %2,faultmask"
            : "=r"(basepri), "=r"(primask), "=r"(faultmask));
    require(current == report.previous && read_ipsr() == 14u &&
            report.selections < 23u, 0x202u);
    require(basepri == 0x80u && primask == 0u && faultmask == 0u &&
            *(volatile uint32_t *)0xe000ed94u == 5u &&
            *(void *volatile *)__slot_start__ == (void *)context_of(current), 0x203u);
    observe_saved(current);
    const uint32_t next = report.selections == 1u ? current : (current + 1u) % 3u;
    if (next == current) {
        ++report.self;
    } else {
        ++report.cross;
    }
    report.previous = next;
    ++report.selections;
    return next;
}
#if PILOT_FIBER
static CTXRT_DISPATCH_ATTR FiberV1 *dispatch(FiberV1 *current, void *user)
{
    require(user == (void *)&report, 0x210u);
    const uint32_t index = current == NULL ? 3u :
            (current == &workers[0] ? 0u : (current == &workers[1] ? 1u : 2u));
    require(current == NULL || current == &workers[index], 0x211u);
    return &workers[select_index(index)];
}
#else
static CTXRT_DISPATCH_ATTR CtxrtContextV1 *dispatch(CtxrtContextV1 *current, void *user)
{
    require(user == (void *)&report, 0x210u);
    const uint32_t index = current == NULL ? 3u :
            (current == &workers[0] ? 0u : (current == &workers[1] ? 1u : 2u));
    require(current == NULL || current == &workers[index], 0x211u);
    return &workers[select_index(index)];
}
#endif
PILOT_GRO int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{
    return end > begin && ((begin >= 0x20002000u && end <= 0x20008000u) ||
            (begin >= 0x20008000u && end <= 0x2000e000u));
}
PILOT_GRO int fiber_addr_plausible_code(uintptr_t address)
{
    return (address & ~(uintptr_t)1u) < 0x20000u;
}
static PILOT_GRO void write_api(void)
{
#if PILOT_FIBER
    fixture_write("FIBERV1");
#else
    fixture_write("CONTEXT");
#endif
}
static PILOT_GRO void write_lazy(void)
{
#if PILOT_LAZY
    fixture_write("1");
#else
    fixture_write("0");
#endif
}
PILOT_NORETURN PILOT_GRO void fiber_panic(char code)
{
    if (code != 'R') {
        fail(0x300u | (uint32_t)(unsigned char)code, report.previous, 0u);
    }
    require(read_ipsr() == 11u && report.previous == 0u && report.selections == 23u &&
            report.self == 1u && report.cross == 21u, 0x301u);
    require(report.saved[0] == 8u && report.saved[1] == 7u && report.saved[2] == 7u &&
            report.challenges == 15u && report.post_lspact == 0u &&
            report.post_control_mask != 0u && (report.post_control_mask & ~0x22u) == 0u, 0x302u);
    for (uint32_t index = 0u; index != 3u; ++index) {
        volatile Mailbox *const mailbox = mailbox_of(index);
        volatile ProbeBox *const probe = probe_of(index);
        const uint32_t completed = index == 0u ? 8u : 6u;
        require(report.public_saves[index] == 4u &&
                report.direct_saves[index] == (index == 0u ? 4u : 3u), 0x303u);
        require(mailbox->error == 0u && mailbox->entered == 1u && mailbox->initial_control == 3u &&
                mailbox->identity == (uint32_t)(uintptr_t)&workers[index] && mailbox->ipsr == 0u &&
                mailbox->rounds == (index == 0u ? 4u : 3u) &&
                mailbox->current_reads == (index == 0u ? 5u : 4u) &&
                mailbox->control == (index == 2u ? 3u : 7u) &&
                mailbox->returning == (index == 0u ? 1u : 0u), 0x304u);
        require(probe->reason == 0u && probe->completed == completed &&
                probe->phase == (index == 0u ? 2u : 1u) &&
                probe->before_sp == probe->after_sp && (probe->before_sp & 7u) == 0u &&
                probe->cookie0 == 0xc04fcafeu && probe->cookie1 == 0x13579bdfu &&
                probe->control == (index == 2u ? 3u : 7u) &&
                probe->fp_checks == (index == 2u ? 0u : completed) &&
                probe->fpscr_checks == (index == 2u ? 0u : completed / 2u), 0x305u);
        for (uint32_t reg = 0u; reg != 8u; ++reg) {
            require(probe->registers[reg] ==
                    0xa4000000u + index * 0x01000000u + (reg + 4u) * 0x1111u, 0x306u);
        }
    }
    const uint32_t frame_base = read_psp();
    require((frame_base & 7u) == 0u && frame_base >= 0x20002200u &&
            frame_base <= 0x20003000u - 104u, 0x307u);
    const uint32_t *const frame = (const uint32_t *)(uintptr_t)frame_base;
    const uint32_t padding = (frame[7] & 0x200u) != 0u ? 4u : 0u;
    require(frame_base <= 0x20003000u - 104u - padding, 0x307u);
    require((frame[7] & 0x010001ffu) == 0x01000000u &&
            frame[6] == (uint32_t)(uintptr_t)fiber_port_svc_return_return_site, 0x308u);
    require(read_control() == 1u && *(volatile uint32_t *)0xe000ed94u == 5u &&
            *(void *volatile *)__slot_start__ == (void *)context_of(0u) &&
            read_sp() >= (uintptr_t)__StackLimit && read_sp() < (uintptr_t)__StackTop, 0x309u);

    fixture_write("CHECK:CM4-MPU-FP:API="); write_api();
    fixture_write(":LAZY="); write_lazy();
    fixture_write(":CALLS=00000017:SELF=00000001:CROSS=00000015:EXT0=00000008:EXT1=00000007:BASIC2=00000007:CHALLENGE=0000000F:POSTCONTROL=");
    fixture_hex(report.post_control_mask);
    fixture_write(":LSPACT=00000000\nRETURN:CM4-MPU-FP:CODE=00000052:IPSR=0000000B:PC=");
    fixture_hex(frame[6]);
    fixture_write(":PSP="); fixture_hex(frame_base);
    fixture_write(":XPSR="); fixture_hex(frame[7]);
    fixture_write("\nPASS:CM4-MPU-FP:"); write_api();
    fixture_write(":LAZY="); write_lazy(); fixture_write("\n");
    fixture_exit(0u);
}
PILOT_NORETURN PILOT_GRO void fixture_fault_record(uint32_t *frame,
        uint32_t exc_return, uint32_t exception)
{
    (void)frame;
    (void)exc_return;
    fail(0x400u | exception, 0xffffffffu, 0u);
}
PILOT_NORETURN PILOT_GRO void fixture_main(void)
{
    require(initialized_data == 0xc04f4a71u && report.selections == 0u && read_ipsr() == 0u, 0x501u);
    for (uint32_t index = 0u; index != 3u; ++index) {
        unsigned char *const begin = index == 0u ? __stack0_start :
                (index == 1u ? __stack1_start : __stack2_start);
        unsigned char *const end = begin + 4096u;
        for (volatile unsigned char *byte = begin; byte != end; ++byte) {
            *byte = 0u;
        }
#if PILOT_FIBER
        fiber_v1_init(&workers[index], begin, end, fixture_task_entry, (void *)&arguments[index]);
#else
        ctxrt_v1_init(&workers[index], begin, end, fixture_task_entry, (void *)&arguments[index]);
#endif
    }
#if PILOT_FIBER
    fiber_v1_set_scheduler(&runtime, dispatch, (void *)&report);
    fiber_v1_start();
#else
    ctxrt_v1_set_dispatcher(dispatch, (void *)&report);
    ctxrt_v1_start();
#endif
}
