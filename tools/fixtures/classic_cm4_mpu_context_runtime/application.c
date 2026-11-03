#include "fixture.h"
#if PILOT_FIBER
#include "fiber/lifecycle/fiber_v1.h"
#else
#include "context/context.h"
#endif
#include <stddef.h>

typedef struct Mailbox {
    uint32_t identity, control, ipsr, sp, current_reads, yields, returning, error;
} Mailbox;
typedef struct TaskArgument {
    uint32_t index;
    void *identity;
    volatile Mailbox *mailbox;
} TaskArgument;
typedef struct PilotReport {
    uint32_t selections, self, cross, previous, entered[2], last_control;
    uint32_t fault_frame, fault_exc_return, fault_status, fault_address;
} PilotReport;
static volatile PilotReport report;
static uint32_t initialized_data = 0xc04da7a1u;
#if PILOT_FIBER
static FiberV1 workers[2];
static FiberRuntimeV1 runtime = FIBER_RUNTIME_V1_INITIALIZER;
#else
static CtxrtContextV1 workers[2];
#endif
static const TaskArgument arguments[2] __attribute__((section(".fixture_user_rodata"))) = {
    { 0u, &workers[0], (volatile Mailbox *)(uintptr_t)0x20002080u },
    { 1u, &workers[1], (volatile Mailbox *)(uintptr_t)0x20004080u }
};
extern const unsigned char fiber_port_svc_return_return_site[];
extern void fixture_slot_write(void), fixture_peer_read(void);
extern const unsigned char fixture_slot_write_access[], fixture_peer_read_access[];

static PILOT_GRO uint32_t ipsr(void) { uint32_t v; __asm volatile("mrs %0,ipsr" : "=r"(v)); return v; }
static PILOT_GRO uint32_t psp(void) { uint32_t v; __asm volatile("mrs %0,psp" : "=r"(v)); return v; }
static PILOT_GRO uint32_t current_sp(void) { uint32_t v; __asm volatile("mov %0,sp" : "=r"(v)); return v; }
static PILOT_NORETURN PILOT_GRO void fail(uint32_t code)
{
    fixture_write("FAIL:CM4-MPU:REASON="); fixture_hex(code); fixture_write("\n");
    fixture_exit(66u);
}
static PILOT_GRO void require(int valid, uint32_t code) { if (!valid) { fail(code); } }
static PILOT_GRO void require_basic_frame(const uint32_t *frame, uint32_t code)
{
    const uintptr_t base = (uintptr_t)frame;
    /* Admit the eight readable core words before consulting their xPSR. */
    require((base & 7u) == 0u && base >= 0x20002000u && base <= 0x20003000u - 32u, code);
    const uint32_t xpsr = frame[7];
    const uint32_t bytes = 32u + ((xpsr & 0x200u) != 0u ? 4u : 0u);
    require((xpsr & 0x010001ffu) == 0x01000000u && base <= 0x20003000u - bytes, code);
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
    return (volatile Mailbox *)(uintptr_t)(index == 0u ? 0x20002080u : 0x20004080u);
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
static PILOT_USER void task_check(const TaskArgument *arg)
{
    uint32_t control, exception, sp;
    __asm volatile("mrs %0,control\nmrs %1,ipsr\nmov %2,sp" : "=r"(control), "=r"(exception), "=r"(sp));
    volatile Mailbox *const box = arg->mailbox;
    box->identity = (uint32_t)(uintptr_t)fixture_task_current();
    box->control = control; box->ipsr = exception; box->sp = sp;
    ++box->current_reads;
    const uintptr_t base = arg->index == 0u ? 0x20002000u : 0x20004000u;
    if (box->identity != (uint32_t)(uintptr_t)arg->identity || control != 3u || exception != 0u ||
            sp < base + 256u || sp > base + 4096u) {
        box->error = 0x101u;
        for (;;) { fixture_task_yield(); }
    }
}
PILOT_USER void fixture_task_entry(void *argument)
{
    const TaskArgument *const arg = (const TaskArgument *)argument;
    task_check(arg);
#if PILOT_CASE == 1
    fixture_slot_write();
    arg->mailbox->error = 0x102u;
#elif PILOT_CASE == 2
    fixture_peer_read();
    arg->mailbox->error = 0x103u;
#endif
    for (uint32_t round = 0u; round < (arg->index == 0u ? 4u : 8u); ++round) {
        ++arg->mailbox->yields;
        fixture_task_yield();
        task_check(arg);
    }
    if (arg->index != 0u) { arg->mailbox->error = 0x104u; }
    arg->mailbox->returning = 1u;
    /* The real constructor-seeded LR enters the real SVC72 return veneer. */
}
static PILOT_GRO uint32_t select_index(uint32_t current)
{
    if (current == 2u) {
        require(report.selections == 0u && ipsr() == 0u, 0x201u);
        report.previous = 0u;
        ++report.selections;
        return 0u;
    }
    require(ipsr() == 14u && current == report.previous, 0x202u);
    uint32_t basepri; __asm volatile("mrs %0,basepri" : "=r"(basepri));
    require(basepri == 0x80u && *(volatile uint32_t *)0xe000ed94u == 5u, 0x203u);
    volatile Mailbox *const box = mailbox_of(current);
    require(box->error == 0u && box->control == 3u && box->ipsr == 0u &&
            box->identity == (uint32_t)(uintptr_t)&workers[current], 0x204u);
    report.entered[current] = 1u;
    const uint32_t next = report.selections == 1u ? current : (current ^ 1u);
    if (next == current) { ++report.self; } else { ++report.cross; }
    report.previous = next;
    ++report.selections;
    return next;
}
#if PILOT_FIBER
static CTXRT_DISPATCH_ATTR FiberV1 *dispatch(FiberV1 *current, void *user)
{
    require(user == (void *)&report, 0x205u);
    uint32_t index = current == NULL ? 2u : (current == &workers[0] ? 0u : 1u);
    require(current == NULL || current == &workers[index], 0x206u);
    return &workers[select_index(index)];
}
#else
static CTXRT_DISPATCH_ATTR CtxrtContextV1 *dispatch(CtxrtContextV1 *current, void *user)
{
    require(user == (void *)&report, 0x205u);
    uint32_t index = current == NULL ? 2u : (current == &workers[0] ? 0u : 1u);
    require(current == NULL || current == &workers[index], 0x206u);
    return &workers[select_index(index)];
}
#endif
PILOT_GRO int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{
    return end > begin && ((begin >= 0x20002000u && end <= 0x20006000u) ||
            (begin >= 0x20008000u && end <= 0x2000e000u));
}
PILOT_GRO int fiber_addr_plausible_code(uintptr_t address)
{
    return (address & ~(uintptr_t)1u) < 0x20000u;
}
static PILOT_GRO void pass_line(void)
{
#if PILOT_FIBER
    fixture_write("PASS:CM4-MPU:FIBERV1\n");
#else
    fixture_write("PASS:CM4-MPU:CONTEXT\n");
#endif
    fixture_exit(0u);
}
PILOT_NORETURN PILOT_GRO void fiber_panic(char code)
{
    require(PILOT_CASE == 0 && code == 'R', 0x300u | (uint32_t)(unsigned char)code);
    require(ipsr() == 11u && report.selections == 8u && report.self == 1u && report.cross == 6u &&
            report.entered[0] == 1u && report.entered[1] == 1u, 0x301u);
    require(mailbox_of(0u)->returning == 1u && mailbox_of(0u)->current_reads == 5u &&
            mailbox_of(1u)->current_reads == 3u, 0x302u);
    const uint32_t *const frame = (const uint32_t *)(uintptr_t)psp();
    require_basic_frame(frame, 0x303u);
    require(frame[6] == (uint32_t)(uintptr_t)fiber_port_svc_return_return_site, 0x304u);
    require(*(volatile uint32_t *)0xe000ed94u == 5u &&
            *(void *volatile *)__slot_start__ == (void *)context_of(0u), 0x305u);
    require(current_sp() >= (uintptr_t)__StackLimit && current_sp() < (uintptr_t)__StackTop, 0x306u);
    fixture_write("RETURN:CM4-MPU:CODE=00000052:IPSR=0000000B:PC="); fixture_hex(frame[6]);
    fixture_write(":PSP="); fixture_hex((uint32_t)(uintptr_t)frame);
    fixture_write(":XPSR="); fixture_hex(frame[7]);
    fixture_write(":CALLS=00000008:SELF=00000001:CROSS=00000006\n");
    pass_line();
    __builtin_unreachable();
}
PILOT_NORETURN PILOT_GRO void fixture_fault_record(uint32_t *frame, uint32_t exc_return, uint32_t exception)
{
    const uint32_t status = *(volatile uint32_t *)0xe000ed28u;
    const uint32_t hfsr = *(volatile uint32_t *)0xe000ed2cu;
    const uint32_t address = *(volatile uint32_t *)0xe000ed34u;
    require(PILOT_CASE != 0 && exception == 4u && ipsr() == 4u && exc_return == 0xfffffffdu, 0x401u);
    require_basic_frame(frame, 0x402u);
    const uint32_t expected_pc = (uint32_t)(uintptr_t)(PILOT_CASE == 1 ? fixture_slot_write_access : fixture_peer_read_access);
    require(status == 0x82u && hfsr == 0u && address == (PILOT_CASE == 1 ? 0x20000000u : 0x20004080u), 0x403u);
    require(frame[6] == expected_pc, 0x404u);
    require(current_sp() >= (uintptr_t)__StackLimit && current_sp() < (uintptr_t)__StackTop &&
            mailbox_of(0u)->control == 3u && mailbox_of(0u)->ipsr == 0u, 0x405u);
    require(*(volatile uint32_t *)0xe000ed94u == 5u &&
            *(void *volatile *)__slot_start__ == (void *)context_of(0u), 0x406u);
    report.fault_frame = (uint32_t)(uintptr_t)frame; report.fault_exc_return = exc_return;
    report.fault_status = status; report.fault_address = address;
    fixture_write("FAULT:CM4-MPU:IPSR=00000004:EXC=FFFFFFFD:CFSR="); fixture_hex(status);
    fixture_write(":HFSR="); fixture_hex(hfsr); fixture_write(":MMFAR="); fixture_hex(address);
    fixture_write(":PC="); fixture_hex(frame[6]); fixture_write(":PSP="); fixture_hex((uint32_t)(uintptr_t)frame);
    fixture_write(":XPSR="); fixture_hex(frame[7]); fixture_write("\n");
    pass_line();
    __builtin_unreachable();
}
PILOT_NORETURN PILOT_GRO void fixture_main(void)
{
    require(initialized_data == 0xc04da7a1u && report.selections == 0u && ipsr() == 0u, 0x501u);
    for (uint32_t i = 0u; i < 2u; ++i) {
        unsigned char *const begin = i == 0u ? __stack0_start : __stack1_start;
        unsigned char *const end = i == 0u ? __stack0_end : __stack1_end;
        for (unsigned char *p = begin; p != end; ++p) { *p = 0u; }
#if PILOT_FIBER
        fiber_v1_init(&workers[i], begin, end, fixture_task_entry, (void *)&arguments[i]);
#else
        ctxrt_v1_init(&workers[i], begin, end, fixture_task_entry, (void *)&arguments[i]);
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
