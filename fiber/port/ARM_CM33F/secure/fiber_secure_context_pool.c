/* C3FS Secure-private pool backing. Initialization only: no fake allocator. */
#include "fiber_secure_gateway_abi.h"
#include "fiber_secure_context_pool.h"
#include "fiber_secure_context_cohort.h"

#define FIBER_C3FS_POOL_INITIALIZING 0x53465042u
#define FIBER_C3FS_POOL_READY 0x53465052u

typedef union FiberSecureContextStackStorage {
    unsigned char bytes[FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES +
            FIBER_ARM_CM33F_SECURE_CONTEXT_STACK_SEAL_BYTES];
    uint64_t force_eight_byte_alignment;
} FiberSecureContextStackStorage;

typedef struct FiberSecureContextPoolImage {
    FiberSecureContextRecord records[FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT];
    FiberSecureContextStackStorage stacks[FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT];
} FiberSecureContextPoolImage;

/* The board maps this section to Secure NOLOAD RAM. The C extraction edge
 * below retains the actual image even with archive GC/LTO, without KEEP. */
static FiberSecureContextPoolImage fiber_secure_context_pool_image
        __attribute__((section(".fiber_secure_context_pool"), used, aligned(8)));
static volatile uint32_t fiber_secure_context_pool_state;

_Static_assert(_Alignof(FiberSecureContextStackStorage) == 8u,
        "[fiber]: C3FS stack storage alignment changed");
_Static_assert(sizeof(FiberSecureContextStackStorage) ==
        FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES + 8u,
        "[fiber]: C3FS stack storage stride changed");
_Static_assert(offsetof(FiberSecureContextPoolImage, stacks) ==
        FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT * 24u,
        "[fiber]: C3FS record/stack boundary changed");
_Static_assert(sizeof(FiberSecureContextPoolImage) ==
        FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT *
        (24u + FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES + 8u),
        "[fiber]: C3FS pool image geometry changed");
_Static_assert(sizeof(fiber_secure_context_pool_state) == 4u,
        "[fiber]: C3FS pool marker must occupy four normal BSS bytes");

/* Real C symbol for the archive/LTO index. Address-only operands retain pool
 * storage and its marker; neither memory nor CPU state is read or written. */
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((externally_visible))
#endif
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_secure_context_pool_c3fs_g2_cohort_provider(void)
{
    __asm volatile("" :: "r" (&fiber_secure_context_pool_image),
            "r" (&fiber_secure_context_pool_state) : "memory");
    FIBER_C3FS_PRIVATE_COHORT_DEFINE();
}

static FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_secure_context_pool_fail_closed(void)
{
    __builtin_trap();
    for (;;) {}
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_pool_boot_is_pristine(void)
{
    return fiber_secure_context_pool_state == 0u;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_pool_boot_initialize(void)
{
    const uint32_t state = fiber_secure_context_pool_state;
    if ((state == FIBER_C3FS_POOL_INITIALIZING) || (state == FIBER_C3FS_POOL_READY)) {
        return 0u;
    }
    if (state != 0u) {
        fiber_secure_context_pool_fail_closed();
    }
    fiber_secure_context_pool_state = FIBER_C3FS_POOL_INITIALIZING;
    __asm volatile("" ::: "memory");
    if (fiber_secure_context_pool_state != FIBER_C3FS_POOL_INITIALIZING) {
        fiber_secure_context_pool_fail_closed();
    }
    volatile unsigned char * const image =
            (volatile unsigned char *)(void *)&fiber_secure_context_pool_image;
    for (size_t byte = 0u; byte < sizeof(fiber_secure_context_pool_image); ++byte) {
        image[byte] = 0u;
    }
    for (size_t byte = 0u; byte < sizeof(fiber_secure_context_pool_image); ++byte) {
        if (image[byte] != 0u) {
            fiber_secure_context_pool_fail_closed();
        }
    }
    if (fiber_secure_context_pool_state != FIBER_C3FS_POOL_INITIALIZING) {
        fiber_secure_context_pool_fail_closed();
    }
    __asm volatile("" ::: "memory");
    fiber_secure_context_pool_state = FIBER_C3FS_POOL_READY;
    __asm volatile("" ::: "memory");
    if (fiber_secure_context_pool_state != FIBER_C3FS_POOL_READY) {
        fiber_secure_context_pool_fail_closed();
    }
    return 1u;
}
