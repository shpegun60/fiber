#include "fiber_portmacro.h"
#include "fiber_port_boot.h"
#include "fiber_port_secure_context_abi.h"
#include "fiber/fiber_runtime_state.h"
#include "fixture.h"
#include "report.h"

/* Staged-profile harness provider only; this is not a runtime implementation. */
#ifndef OMIT_COHORT
FIBER_PORT_CONTEXT_COHORT_DEFINE();
#endif
__attribute__((section(".fixture_case"),used)) volatile const uint32_t fixture_case = 0;

extern void fixture_construct(FiberContext *, void *, void *, entry_t, void *);
extern void fixture_disturb(uint32_t field);
extern uint32_t *pxPortInitialiseStack(uint32_t *, uint32_t *, entry_t, void *);
static struct { uint32_t low[4]; FiberContext context; uint32_t high[4]; } object;
static __attribute__((aligned(8))) unsigned char stack[1024];
static __attribute__((aligned(8))) uint32_t reference_stack[256];
static unsigned char saved_object[sizeof(object)], saved_stack[sizeof(stack)];
static volatile uint32_t expected_panic, query_count, expected_queries, expect_snapshot;
static volatile uint32_t map_ram_deny, map_code_deny;

POINT void *memcpy(void *destination, const void *source, size_t count)
{
    unsigned char *d = destination; const unsigned char *s = source;
    while (count--) { *d++ = *s++; } return destination;
}
POINT void *memset(void *destination, int value, size_t count)
{
    unsigned char *d = destination;
    while (count--) { *d++ = (unsigned char)value; } return destination;
}
POINT void __aeabi_memcpy(void *d, const void *s, size_t n) { (void)memcpy(d,s,n); }
POINT void __aeabi_memcpy4(void *d, const void *s, size_t n) { (void)memcpy(d,s,n); }
POINT void __aeabi_memclr4(void *d, size_t n) { (void)memset(d,0,n); }

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{
    return !map_ram_deny && begin >= 0x20010000u && end <= 0x20020000u && end > begin;
}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t address)
{
    return !map_code_deny && address >= 0x10000u && address < 0x20000u;
}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_memory_barrier(void) { __DMB(); __DSB(); __ISB(); }
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_NORETURN
void fiber_internal_task_return(void) { finish(92, "FAIL:C55S-ATTACH:task-executed\n"); }
static void entry(void *argument) { (void)argument; finish(92, "FAIL:C55S-ATTACH:entry-executed\n"); }

void require_query(uint32_t index)
{
    require(__get_IPSR() == 0u, 1);
    require(query_count == index, 2);
    query_count = index+1u;
}
static void snapshot(void)
{
    memcpy(saved_object, &object, sizeof(object));
    memcpy(saved_stack, stack, sizeof(stack));
    expect_snapshot = 1u;
}
static void unchanged(void)
{
    const unsigned char *p = (const unsigned char *)&object;
    for (uint32_t i=0; i<sizeof(object); ++i) { require(p[i] == saved_object[i], 10+i); }
    for (uint32_t i=0; i<sizeof(stack); ++i) { require(stack[i] == saved_stack[i], 2000+i); }
}
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
    emit("PANIC:C55S-ATTACH case="); hex(fixture_case); emit(" code="); hex((uint32_t)code);
    emit(" IPSR="); hex(__get_IPSR()); emit(" CONTROL="); hex(__get_CONTROL()); emit("\n");
    require(expected_panic != 0u && (uint32_t)code == expected_panic, 3000);
    require(query_count == expected_queries, 3001);
    if (expect_snapshot) { unchanged(); }
    if (fixture_case >= 200u && fixture_case < 248u) {
        const uint32_t field = (fixture_case-200u)%6u;
        if (field == 0u) { require(__get_IPSR() == 11u, 3002); }
        if (field == 1u) { require(__get_PRIMASK() == 1u, 3003); }
        if (field == 2u) { require(__get_BASEPRI() == 128u, 3004); }
        if (field == 3u) { require(__get_FAULTMASK() == 1u, 3005); }
        if (field == 4u) { require(__get_CONTROL() == 2u && __get_IPSR() == 0u, 3006); }
        if (field == 5u) { require(__get_PSPLIM() == 0x20010000u, 3007); }
    }
    emit("PASS:C55S-ATTACH:rejected case="); hex(fixture_case); emit("\n");
    finish(0, "PASS-EXIT:C55S-ATTACH\n");
}
__attribute__((noreturn)) void attachment_fault_report(uint32_t exc_return, uint32_t ipsr)
{
    emit("FAULT:C55S-ATTACH:NS EXC_RETURN="); hex(exc_return);
    emit(" IPSR="); hex(ipsr); emit("\n"); finish(91, "FAULT-EXIT\n");
}

static uint32_t hash_value(uint32_t hash, uint32_t value)
{
    for (uint32_t i=0; i<4; ++i) { hash = (hash ^ (value & 255u)) * 16777619u; value >>= 8; }
    return hash;
}
static uint32_t independent_hash(const FiberPortBoot *b)
{
    /* Independent field oracle, no production hashing helper or layout macro. */
    const uint32_t values[] = {(uintptr_t)b->begin,(uintptr_t)b->end,b->stack_base,b->stack_top,
        b->avail,(uintptr_t)b->entry,(uintptr_t)b->arg,b->secure_stack_bytes,b->abi_port_id,
        b->abi_layout_version,b->abi_context_size,b->abi_context_alignment,b->abi_feature_mask,
        b->abi_initial_exc_return,b->magic,b->version,b->guard_lo,b->guard_hi};
    uint32_t hash = 2166136261u;
    for (uint32_t i=0; i<sizeof(values)/sizeof(values[0]); ++i) { hash = hash_value(hash,values[i]); }
    return hash;
}
static void image_oracle(void)
{
    FiberContext *const c = &object.context;
    const uintptr_t base = (((uintptr_t)(stack+3)+3u)&~3u)+32u;
    const uintptr_t bottom = (base+7u)&~7u;
    const uintptr_t top = ((uintptr_t)(stack+1021))&~7u;
    require((uintptr_t)c->sp == top-76u && (((uintptr_t)c->sp)&7u) == 4u, 3100);
    const uint32_t golden[19] = {0,(uint32_t)bottom,0xffffffbcu,0,0,0,0,0,0x91a2b3c4u,0,0,
        0x12345678u,0,0,0,0,((uintptr_t)&fiber_internal_task_return)|1u,
        ((uintptr_t)&entry)&~1u,0x01000000u};
    for (uint32_t i=0; i<19; ++i) { require(c->sp[i] == golden[i], 3200+i); }
    const FiberPortBoot *const b = &c->boot;
    require(b->begin == stack+3 && b->end == stack+1021 && b->stack_base == bottom &&
        b->stack_top == top && b->avail == top-bottom && b->entry == entry &&
        b->arg == (void *)0x12345678u && b->secure_stack_bytes == 0u, 3300);
    require(b->abi_port_id == 0x43353553u && b->abi_layout_version == 0x10001u &&
        b->abi_context_size == 80u && b->abi_context_alignment == 4u &&
        b->abi_feature_mask == 0x8au && b->abi_initial_exc_return == 0xffffffbcu, 3301);
    require(b->magic == 0x46424f54u && b->version == 3u && b->sealed == 1u &&
        b->guard_lo == 0xa5a5a5a5u && b->guard_hi == 0x5a5a5a5au &&
        b->hash == independent_hash(b), 3302);
    const uintptr_t canary = ((uintptr_t)(stack+3)+3u)&~3u;
    require(*(const uint32_t *)canary == 0xdeadbeefu, 3303);
    for (uint32_t i=0; i<sizeof(stack); ++i) {
        const uintptr_t address = (uintptr_t)(stack+i);
        if ((address >= canary && address < canary+4u) || (address >= top-76u && address < top)) { continue; }
        require(stack[i] == 0xa5u, 3400+i);
    }
    for (uint32_t i=0; i<4; ++i) { require(object.low[i] == 0xa5a5a5a5u && object.high[i] == 0xa5a5a5a5u, 4500+i); }

    memset(reference_stack,0xa5,sizeof(reference_stack));
    uint32_t *const reference_top = reference_stack+256;
    uint32_t *const r = pxPortInitialiseStack(reference_top,(uint32_t *)bottom,entry,(void *)0x12345678u);
    require(r == reference_top-19, 4510);
    for (uint32_t i=0; i<19; ++i) {
        /* The unmodified pin has portPRELOAD_REGISTERS=1, not a fixture override. */
        uint32_t expected = 0;
        if (i>=3u && i<=8u) { expected=(i+1u)*0x01010101u; }
        if (i==9u) { expected=0x10101010u; }
        if (i==10u) { expected=0x11111111u; }
        if (i>=12u && i<=14u) { expected=(i-11u)*0x01010101u; }
        if (i==15u) { expected=0x12121212u; }
        if (i==0 || i==1 || i==2 || i==11 || i==16 || i==18) { expected=golden[i]; }
        if (i==17) { expected=(uintptr_t)entry; }
        require(r[i] == expected, 4600+i);
    }
    for (uint32_t i=0; i<256-19; ++i) { require(reference_stack[i] == 0xa5a5a5a5u, 4700+i); }
    emit("PASS:C55S-ATTACH:constructor19+pinned19+r9+guards\n");
}

static void metadata_mutation(uint32_t field)
{
    FiberPortBoot *b = &object.context.boot;
    static const char errors[] = {'m','v','g','G','s','h','q','q','q','q','q','q','Z','z','a','D','e'};
    expected_panic = (uint32_t)errors[field];
    switch (field) {
    case 0: b->magic ^= 1; break; case 1: b->version ^= 1; break;
    case 2: b->guard_lo ^= 1; break; case 3: b->guard_hi ^= 1; break;
    case 4: b->sealed = 0; break; case 5: b->hash ^= 1; break;
    case 6: b->abi_port_id ^= 1; break; case 7: b->abi_layout_version ^= 1; break;
    case 8: b->abi_context_size ^= 4; break; case 9: b->abi_context_alignment ^= 4; break;
    case 10: b->abi_feature_mask ^= 1; break; case 11: b->abi_initial_exc_return ^= 4; break;
    case 12: b->stack_base += 8; b->avail -= 8; break;
    case 13: b->stack_top -= 8; b->avail -= 8; break;
    case 14: b->avail ^= 8; break; case 15: b->secure_stack_bytes = 7; break;
    case 16: b->entry = (entry_t)(((uintptr_t)b->entry)&~1u); break;
    default: require(0,5000);
    }
    if (field != 5u) { b->hash = independent_hash(b); }
}
__attribute__((noreturn)) void attachment_ns_main(void)
{
    const uint32_t n = fixture_case;
    require(__get_IPSR() == 0u && __get_CONTROL() == 0u && __get_PRIMASK() == 0u &&
        __get_BASEPRI() == 0u && __get_FAULTMASK() == 0u && __get_PSPLIM() == 0u, 5100);
    emit("START:C55S-ATTACH:NS-Thread case="); hex(n); emit("\n");
    if (n==900u) { __asm volatile("udf #0"); }
    if (n==901u) { finish(0,"SELFTEST:C55S-ATTACH:missing-report\n"); }
    if (n==902u) { for (;;) { __asm volatile("wfe"); } }
    memset(&object,0xa5,sizeof(object)); memset(stack,0xa5,sizeof(stack));
    FiberContext *c = &object.context;
    if (n >= 1000u && n < 1012u) {
        void *begin=stack+3, *end=stack+1021; entry_t code=entry;
        const char errors[]={'C','B','T','E','A','O','N','C','e','c','C','H'};
        expected_panic=(uint32_t)errors[n-1000u];
        switch (n-1000u) {
        case 0: c=0; break; case 1: begin=0; break; case 2: end=0; break;
        case 3: code=0; break; case 4: c=(FiberContext *)((uintptr_t)c+1u); break;
        case 5: c=(FiberContext *)0xfffffffcu; break; case 6: end=begin; break;
        case 7: begin=(void *)&object; end=(void *)((uintptr_t)&object+sizeof(object)); break;
        case 8: code=(entry_t)(((uintptr_t)entry)&~1u); break;
        case 9: map_code_deny=1; break; case 10: map_ram_deny=1; break;
        case 11: end=stack+64; break;
        }
        snapshot(); fixture_construct(c,begin,end,code,(void *)0x12345678u);
        finish(93,"FAIL:C55S-ATTACH:constructor-accepted\n");
    }
    fixture_construct(c,stack+3,stack+1021,entry,(void *)0x12345678u);
    image_oracle();
    uint32_t request = 64u;
    if (n >= 100u && n < 108u) { expected_panic='Q'; expected_queries=n-100u+1u; }
    if (n==108u || n==109u) { expected_panic='Q'; expected_queries=8; }
    if (n >= 200u && n < 248u) {
        const char errors[]={'i','p','b','f','l','L'};
        expected_panic=errors[(n-200u)%6u]; expected_queries=(n-200u)/6u+1u;
    }
    if (n >= 300u && n < 317u) { metadata_mutation(n-300u); }
    if (n >= 400u && n < 419u) {
        const char errors[19]={'D','L','x','4','5','6','7','8',0,'1','1','0','1','2','3','2','R','x','X'};
        require(errors[n-400u] != 0, 5200);
        expected_panic=(uint32_t)errors[n-400u]; c->sp[n-400u] ^= 1u;
    }
    if (n==500u) { expected_panic='c'; *(uint32_t *)(stack+4) ^= 1; }
    if (n==501u) { expected_panic='S'; c->sp=(uint32_t *)(c->boot.stack_base-4u); }
    if (n==502u) { expected_panic='D'; request=0; expected_queries=8; }
    if (n==503u) { expected_panic='D'; request=7; expected_queries=8; }
    if (n==504u) { expected_panic='D'; request=136; expected_queries=8; }
    if (n==505u) { expected_panic='k'; fiber_internal_runtime_close_context_configuration(); }
    if (n==506u) { expected_panic='n'; c=0; }
    if (n==507u) { expected_panic='A'; c=(FiberContext *)((uintptr_t)c+1u); }
    if (n==508u) { expected_panic='O'; c=(FiberContext *)0xfffffffcu; }
    if (n==509u) { expected_panic='C'; map_ram_deny=1; }
    if (n==510u) { expected_panic='i'; }
    if (n==511u) {
        fiber_port_boot_attach_secure_stack(&c->boot,64);
        expected_panic='D';
    }
    snapshot();
    if (n==510u) { fixture_disturb(0); }
    fiber_port_secure_context_attach(c,request);
    require(expected_panic == 0u, 5300);
    require(query_count == (n==1u ? 8u : 0u), 5301);
    /* Only request/hash may change. The saved image and every guard stay exact. */
    for (uint32_t i=0; i<sizeof(stack); ++i) { require(stack[i] == saved_stack[i], 5400+i); }
    FiberContext old;
    memcpy(&old,saved_object+offsetof(__typeof__(object),context),sizeof(old));
    old.boot.secure_stack_bytes=64;
    old.boot.hash=independent_hash(&old.boot);
    const unsigned char *actual=(const unsigned char *)c, *expected=(const unsigned char *)&old;
    for (uint32_t i=0; i<sizeof(old); ++i) { require(actual[i] == expected[i],6500+i); }
    for (uint32_t i=0; i<4; ++i) { require(object.low[i] == 0xa5a5a5a5u && object.high[i] == 0xa5a5a5a5u,6590+i); }
    require(__get_IPSR()==0u && __get_CONTROL()==0u && __get_PRIMASK()==0u &&
        __get_BASEPRI()==0u && __get_FAULTMASK()==0u && __get_PSPLIM()==0u,6600);
    emit(n==0 ? "PASS:C55S-ATTACH:real-SG-eight-query\n" : "PASS:C55S-ATTACH:labelled-NS-query-doubles\n");
    finish(0,"PASS-EXIT:C55S-ATTACH\n");
}
