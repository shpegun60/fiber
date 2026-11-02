#include "fiber_port_private.h"
#include "fiber/fiber_runtime_state.h"
#include "fiber/fiber_runtime_port_abi.h"
#pragma GCC push_options
#pragma GCC target("general-regs-only")
#include "../cm33f_mpu_first_start_execution/report.h"

#define REG(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define CHECK(c) report_check((c), __LINE__)
_Static_assert(FIBER_PORT_RUNTIME_SELECTABLE == EXEC_EXPECT_RUNTIME_SELECTABLE,
        "explicit pre-promotion or activated runtime manifest required");
static FiberContext contexts[2];
__attribute__((section(".fixture_stack_a"), aligned(32))) unsigned char stack_a[4096];
__attribute__((section(".fixture_stack_b"), aligned(32))) unsigned char stack_b[4096];
static uint32_t selections;
static FiberContext *pending;
static uint32_t yields[2];
static const unsigned sequence_current[6] = {0,1,0,0,1,1};
static const unsigned sequence_next[6] = {1,0,0,1,1,0};
void fixture_task_a(void *);
void fixture_task_b(void *);
extern const unsigned char fixture_task_a_resume1[], fixture_task_a_resume2[], fixture_task_a_resume3[];
extern const unsigned char fixture_task_b_resume1[], fixture_task_b_resume2[], fixture_task_b_resume3[];

static uint32_t addr(const void *p) {return (uint32_t)(uintptr_t)p;}
static uint32_t stack_top(unsigned id) {return id == 0 ? 0x20007000u : 0x20008000u;}
static unsigned active_fp(unsigned id) {return EXEC_FP==1 || (EXEC_FP==2 && id==0);}
static uint32_t seed(unsigned id, unsigned reg) {return (id == 0 ? 0x11000000u : 0x22000000u) + reg;}
__attribute__((unused)) static uint32_t fp_seed(unsigned id, unsigned reg) {return (id == 0 ? 0x3f100000u : 0x40100000u) + reg * 0x1000u;}
static uint32_t resume(unsigned id, unsigned round)
{
    const unsigned char *const labels[2][3] = {
        {fixture_task_a_resume1, fixture_task_a_resume2, fixture_task_a_resume3},
        {fixture_task_b_resume1, fixture_task_b_resume2, fixture_task_b_resume3}};
    CHECK(id < 2 && round < 3);
    return addr(labels[id][round]) | 1u;
}

static void mpu(unsigned id, uint32_t ctrl)
{
    const uint32_t bases[8] = {0x10004u,0x20006u,0x28006u,0x20004021u,
        (id == 0 ? 0x20006000u : 0x20007000u) | 3u,0x20004007u,0,0};
    const uint32_t limits[8] = {0x1ffe1u,0x27fe1u,0x28fe1u,0x20005fe1u,
        ((stack_top(id)-1u)&~31u)|1u,0x20004001u,0,0};
    CHECK(REG(0xe000ed94u) == ctrl);
    CHECK(REG(0xe000edc0u) == 0x04ffu);
    uint32_t rnr = REG(0xe000ed98u);
    for (unsigned i=0;i<8;++i) {
        REG(0xe000ed98u)=i; __DSB(); __ISB();
        CHECK(REG(0xe000ed9cu)==bases[i]);
        CHECK(REG(0xe000eda0u)==limits[i]);
    }
    REG(0xe000ed98u)=rnr; __DSB(); __ISB();
}

static void records(unsigned id, unsigned count)
{
    for (unsigned round=0;round<count;++round) {
        const uint32_t *r=(const uint32_t *)(uintptr_t)(stack_top(id)-1024u+round*256u);
        for (unsigned i=0;i<13;++i) CHECK(r[i]==seed(id,i));
        CHECK(r[13]==resume(id,round));
        CHECK(r[14]==(active_fp(id) ? 7u:3u));
        CHECK(r[15]==stack_top(id)-1024u);
        CHECK(r[16]==addr(&contexts[id]));
        if (active_fp(id)) {
            for (unsigned i=0;i<32;++i) CHECK(r[20+i]==fp_seed(id,i));
            CHECK(r[52]==(id==0?0x00400000u:0x00800000u));
        }
    }
}

static void saved(unsigned id)
{
    const FiberContext *c=&contexts[id];
    const uint32_t *w=c->protected_context.words;
    unsigned fp=active_fp(id), core=fp?41u:8u, callee=fp?33u:0u, special=fp?49u:16u;
    CHECK(c->protected_context_cursor==&c->protected_context.words[fp?53:20]);
    CHECK(w[53]==0u && c->runtime_flags==0u);
    for (unsigned i=0;i<8;++i) CHECK(w[callee+i]==seed(id,i+4));
    for (unsigned i=0;i<4;++i) CHECK(w[core+i]==seed(id,i));
    CHECK(w[core+4]==seed(id,12));
    CHECK(w[core+5]==resume(id,yields[id]-1u));
    CHECK(w[core+6]==(addr(fiber_port_svc_yield_return_site)&~1u));
    CHECK((w[core+7]&0x010003ffu)==0x01000000u);
    CHECK(w[special]==stack_top(id)-1024u-(fp?104u:32u));
    CHECK(w[special+1]==contexts[id].boot.stack_base);
    CHECK((w[special+2]&3u)==1u);
    CHECK(w[special+3]==(fp?0xffffffacu:0xffffffbcu));
    CHECK(__get_PSP()==w[special]);
    CHECK(__get_PSPLIM()==w[special+1]);
    if (fp) {
        for (unsigned i=0;i<16;++i) {
            CHECK(w[i]==fp_seed(id,i+16));
            CHECK(w[16+i]==fp_seed(id,i));
        }
        CHECK(w[32]==(id==0?0x00400000u:0x00800000u));
    }
}

static FiberContext *pick(FiberContext *current, void *user)
{
    CHECK(user==&contexts[0]);
    if (current==NULL) {
        CHECK(selections==0 && __get_IPSR()==0 && __get_CONTROL()==0);
        return &contexts[0];
    }
    CHECK(selections<6);
    unsigned id=sequence_current[selections], next=sequence_next[selections];
    CHECK(current==&contexts[id] && fiber_internal_runtime_current_context_slot==current);
    CHECK(__get_IPSR()==14 && __get_PRIMASK()==0 && __get_FAULTMASK()==0);
    CHECK(__get_BASEPRI()==FIBER_PORT_SCHEDULER_BASEPRI && (__get_CONTROL()&3u)==1u);
    ++yields[id]; saved(id); records(id,yields[id]-1u); mpu(id,5u);
    pending=&contexts[next]; ++selections;
    report_value("PENDSV_SELECTION", selections);
#if EXEC_CASE == 3
    pending->boot.hash ^= 1u;
#elif EXEC_CASE == 4
    pending->protected_context_cursor = &pending->protected_context.words[1];
#elif EXEC_CASE == 5
    pending->protected_context.words[53] = 1u;
#elif EXEC_CASE == 6
    __set_BASEPRI(0);
#elif EXEC_CASE == 7
    REG(0xe000ed98u)=4; REG(0xe000ed9cu)^=32u; __DSB(); __ISB();
#endif
    return pending;
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION void fiber_panic(char code)
{
    report_value("PANIC_CODE",(unsigned char)code);
    report_value("PANIC_IPSR",__get_IPSR());
#if EXEC_CASE == 0
    CHECK(code=='R' && __get_IPSR()==11);
    CHECK(selections==6);
    CHECK(yields[0]==3 && yields[1]==3);
    CHECK(fiber_internal_runtime_current_context_slot==&contexts[0]);
    CHECK(contexts[0].protected_context_cursor==contexts[0].protected_context.words);
    CHECK(contexts[1].protected_context_cursor==&contexts[1].protected_context.words[active_fp(1)?53:20]);
    records(0,3); records(1,2); mpu(0,5);
    CHECK(__get_PRIMASK()==0 && __get_BASEPRI()==0 && __get_FAULTMASK()==0);
    CHECK(__get_PSPLIM()==contexts[0].boot.stack_base && (__get_CONTROL()&3u)==1u);
    CHECK(__get_PSP()==stack_top(0)-1024u-(active_fp(0)?104u:32u));
    const uint32_t *terminal_frame=(const uint32_t *)(uintptr_t)__get_PSP();
    CHECK(terminal_frame[6]==(addr(fiber_port_svc_return_return_site)&~1u));
    CHECK(REG(0xe000ed88u)==0x00f00000u);
    CHECK((REG(0xe000ef34u)&0xc0000000u)==(FIBER_FPU_LAZY?0xc0000000u:0x80000000u));
    report_value("VERIFIED_SWITCHES",selections);
    report_value("VERIFIED_FP_REGISTERS",EXEC_FP?32u:0u);
    report_value("VERIFIED_FP_TASKS",active_fp(0)+active_fp(1));
    report_exit(0,"PASS:C3FP-RUNNING-EXECUTION\n");
#elif EXEC_CASE == 1 || EXEC_CASE == 2
    CHECK(code=='u' && __get_IPSR()==11 && selections==0);
    CHECK(fiber_internal_runtime_current_context_slot==&contexts[0]); mpu(0,5);
    report_exit(0,"PASS:C3FP-UNOWNED-SVC-REJECTED\n");
#else
    const char expected = EXEC_CASE==3?'h':EXEC_CASE==6?'B':EXEC_CASE==7?'M':'P';
    CHECK(code==expected && __get_IPSR()==14 && selections==1);
    CHECK(fiber_internal_runtime_current_context_slot==&contexts[0]);
    CHECK(REG(0xe000ed94u)==5u);
    if (EXEC_CASE!=7) mpu(0,5);
    report_exit(0,"PASS:C3FP-CANDIDATE-OR-CALLBACK-REJECTED\n");
#endif
}

__attribute__((noreturn)) void fixture_fault_report(const uint32_t *frame,uint32_t exc_return)
{
    report_value("FAULT_IPSR",__get_IPSR());report_value("FAULT_EXC_RETURN",exc_return);
    report_value("FAULT_CFSR",SCB->CFSR);report_value("FAULT_MMFAR",SCB->MMFAR);
    report_value("FAULT_PC",frame[6]);
#if EXEC_CASE == 8
    extern const unsigned char fixture_task_a_forbidden_store[];
    CHECK(__get_IPSR()==4 && exc_return==0xffffffbc && SCB->CFSR==0x82);
    CHECK(SCB->MMFAR==addr((const void *)&fiber_internal_runtime_current_context_slot));
    CHECK(frame[6]==(addr(fixture_task_a_forbidden_store)&~1u));
    CHECK(selections==0); mpu(0,5);
    report_exit(0,"PASS:C3FP-CURRENT-WRITE-DENIED\n");
#else
    report_exit(1,"FAIL:C3FP-UNEXPECTED-FAULT\n");
#endif
}

void fixture_ns_main(void)
{
    CHECK(__get_IPSR()==0 && __get_CONTROL()==0 && REG(0xe000ed94u)==0);
    fiber_port_context_init(&contexts[0],stack_a,stack_a+sizeof(stack_a),fixture_task_a,NULL);
    fiber_port_context_init(&contexts[1],stack_b,stack_b+sizeof(stack_b),fixture_task_b,NULL);
    fiber_internal_scheduler_store_pick_next(pick,&contexts[0]);
    FiberContext *first=fiber_internal_runtime_select_scheduler_candidate(NULL);
    fiber_internal_runtime_publish_current_context(first);
    report_text("PASS:C3FP-REAL-COMMON-POLICY\n");
    fiber_port_start_first_context(first);
}
#pragma GCC pop_options
