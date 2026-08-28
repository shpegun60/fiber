/* ARM_CM33 TrustZone strong SVC/PendSV handler bundle. */

#include "fiber_port_private.h"

#define fiber_portSTRINGIFY2(value) #value
#define fiber_portSTRINGIFY(value) fiber_portSTRINGIFY2(value)

const unsigned char fiber_port_arm_cm33_secure_context_handler_bundle_v1_anchor
		__attribute__((used)) = 1u;

enum {
	fiber_portSVC_OFF_STACK_BASE =
		offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_base),
	fiber_portSVC_OFF_STACK_TOP =
		offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_top),
	fiber_portSVC_OFFSET_STACKED_XPSR = 7u * 4u
};

FIBER_STATIC_ASSERT(fiber_portSVC_OFF_STACK_BASE < 4096u,
		"[fiber]: ARM_CM33 PendSV stack-base offset must fit Thumb-2 LDR");
FIBER_STATIC_ASSERT(fiber_portSVC_OFF_STACK_TOP < 4096u,
		"[fiber]: ARM_CM33 PendSV stack-top offset must fit Thumb-2 LDR");

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
void fiber_port_start_first_context(
		uintptr_t msp_top FIBER_ATTR_UNUSED_PARAM)
{
	fiber_portASM volatile(
			".syntax unified                         \n"
			"cpsid i                                \n"
			"dsb                                    \n"
			"isb                                    \n"

			/* First start must originate in privileged Thread/MSP mode. */
			"movs  r3, #0                           \n"
			"msr   control, r3                      \n"
			"isb                                    \n"
			"mrs   r3, control                      \n"
			"tst   r3, #3                           \n"
			"bne   9f                               \n"

			"cmp   r0, #0                           \n"
			"beq   1f                               \n"
			"tst   r0, #7                           \n"
			"bne   9f                               \n"
			"msr   msp, r0                          \n"
			"isb                                    \n"
			"mrs   r3, msp                          \n"
			"cmp   r3, r0                           \n"
			"bne   9f                               \n"

			"1:                                     \n"
			/* Clear stale PendSV before issuing the only accepted start SVC. */
			"ldr   r3, =0xE000ED04                  \n"
			"ldr   r2, =0x08000000                  \n"
			"str   r2, [r3]                         \n"
			"movs  r0, #0                           \n"
			fiber_portASM_WRITE_BASEPRI_R0_SYNC
			"mrs   r3, " fiber_portBASEPRI_SYM "    \n"
			"cmp   r3, #0                           \n"
			"bne   9f                               \n"
			"mrs   r3, faultmask                    \n"
			"cmp   r3, #0                           \n"
			"bne   9f                               \n"
			"cpsie f                                \n"
			"cpsie i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"svc   #" fiber_portSTRINGIFY(FIBER_SVC_START_NUMBER) " \n"

			"movs  r0, #121                         \n" /* 'y' */
			"bl    fiber_panic                      \n"
			"b     .                                \n"

			"9:                                     \n"
			"movs  r0, #108                         \n" /* 'l' */
			"bl    fiber_panic                      \n"
			"b     9b                               \n"
			".ltorg                                 \n"
			:
			:
			: "memory", "cc");
}

FIBER_ATTR_NAKED_ASM
void SVC_Handler(void)
{
	fiber_portASM volatile(
			".syntax unified                         \n"
			/* Exact Non-secure Handler/MSP SVC provenance. */
			"mrs   r3, ipsr                         \n"
			"cmp   r3, #11                          \n"
			"bne   93f                              \n"
			"mvn   r3, #71                          \n" /* 0xFFFFFFB8 */
			"cmp   lr, r3                           \n"
			"bne   93f                              \n"
			"tst   lr, #4                           \n"
			"bne   93f                              \n"

			"mrs   r0, msp                          \n"
			"tst   r0, #7                           \n"
			"bne   93f                              \n"
			"ldr   r2, [r0, #28]                    \n"
			"tst   r2, #0x01000000                  \n"
			"beq   93f                              \n"
			"tst   r2, #0x200                       \n"
			"bne   93f                              \n"
			"ubfx  r2, r2, #0, #9                   \n"
			"cmp   r2, #0                           \n"
			"bne   93f                              \n"

			/* Decode the actual SVC instruction, not only the stacked PC. */
			"ldr   r3, [r0, #24]                    \n"
			"cmp   r3, #2                           \n"
			"blo   94f                              \n"
			"tst   r3, #1                           \n"
			"bne   93f                              \n"
			"subs  r3, #2                           \n"
			"ldrb  r2, [r3, #1]                     \n"
			"cmp   r2, #0xDF                        \n"
			"bne   94f                              \n"
			"ldrb  r3, [r3]                         \n"
			"cmp   r3, #" fiber_portSTRINGIFY(FIBER_SVC_START_NUMBER) " \n"
			"bne   94f                              \n"

			"cpsid i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"movs  r0, #0                           \n"
			fiber_portASM_WRITE_BASEPRI_R0_SYNC
			"mrs   r1, " fiber_portBASEPRI_SYM "    \n"
			"cmp   r1, #0                           \n"
			"bne   96f                              \n"

			/* Common owns publication; the port may only load this slot. */
			"ldr   r0, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r0, [r0]                         \n"
			"cmp   r0, #0                           \n"
			"beq   90f                              \n"
			"push  {r0, lr}                         \n"
			"bl    fiber_port_secure_context_prepare_first_start \n"
			"pop   {r2, r3}                         \n"

			/* Exact 11-word FreeRTOS-shaped software frame:
			 * handle, PSPLIM, EXC_RETURN, r4-r11. */
			"ldr   r0, [r2]                         \n"
			"ldmia r0!, {r1-r11}                    \n"
			"mvn   r12, #67                         \n" /* 0xFFFFFFBC */
			"cmp   r3, r12                          \n"
			"bne   92f                              \n"
			"msr   psplim, r2                       \n"
			"dsb                                    \n"
			"isb                                    \n"
			"mrs   r12, psplim                      \n"
			"cmp   r12, r2                          \n"
			"bne   95f                              \n"

			/* EXC_RETURN selects Non-secure Thread/PSP. CONTROL is seeded and
			 * read back as an independent privileged-PSP policy check. */
			"movs  r2, #2                           \n"
			"msr   control, r2                      \n"
			"isb                                    \n"
			"mrs   r2, control                      \n"
			"and   r2, r2, #3                       \n"
			"cmp   r2, #2                           \n"
			"bne   93f                              \n"
			"msr   psp, r0                          \n"
			"isb                                    \n"
			"mrs   r2, psp                          \n"
			"cmp   r2, r0                           \n"
			"bne   92f                              \n"
			"mrs   r2, faultmask                    \n"
			"cmp   r2, #0                           \n"
			"bne   93f                              \n"

			"dsb                                    \n"
			"isb                                    \n"
			"cpsie i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"bx    r3                               \n"

			"90:                                    \n"
			"movs  r0, #67                          \n" /* 'C' */
			"bl    fiber_panic                      \n"
			"b     90b                              \n"
			"92:                                    \n"
			"movs  r0, #120                         \n" /* 'x' */
			"bl    fiber_panic                      \n"
			"b     92b                              \n"
			"93:                                    \n"
			"movs  r0, #108                         \n" /* 'l' */
			"bl    fiber_panic                      \n"
			"b     93b                              \n"
			"94:                                    \n"
			"movs  r0, #117                         \n" /* 'u' */
			"bl    fiber_panic                      \n"
			"b     94b                              \n"
			"95:                                    \n"
			"movs  r0, #76                          \n" /* 'L' */
			"bl    fiber_panic                      \n"
			"b     95b                              \n"
			"96:                                    \n"
			"movs  r0, #98                          \n" /* 'b' */
			"bl    fiber_panic                      \n"
			"b     96b                              \n"
			".ltorg                                 \n"
			:
			:
			: "memory", "cc");
}

FIBER_ATTR_NAKED_ASM
void PendSV_Handler(void)
{
	fiber_portASM volatile(
			".syntax unified                         \n"

			/* Exact Non-secure Thread/PSP PendSV provenance. */
			"mrs   r3, ipsr                         \n"
			"cmp   r3, #14                          \n"
			"bne   91f                              \n"
			"mvn   r3, #67                          \n" /* 0xFFFFFFBC */
			"cmp   lr, r3                           \n"
			"bne   91f                              \n"
			"tst   lr, #4                           \n"
			"beq   91f                              \n"

			"mrs   r0, psp                          \n"
			"tst   r0, #7                           \n"
			"bne   92f                              \n"
			"dsb                                    \n"
			"isb                                    \n"

			/* Validate current before any context-owned metadata read. */
			"ldr   r1, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r1, [r1]                         \n"
			"cmp   r1, #0                           \n"
			"beq   90f                              \n"
			"push  {r0, r1, r2, lr}                 \n"
			"mov   r0, r1                           \n"
			"bl    fiber_port_context_validate_save_current \n"
			"pop   {r0, r1, r2, lr}                 \n"

			/* Prove source hardware/software frame bounds before either
			 * Secure or Non-secure context state is changed. */
			"ldr   r2, [r1, %c[offsb]]              \n"
			"cmp   r0, r2                           \n"
			"blo   92f                              \n"
			"mov   r3, r0                           \n"
			"subs  r3, #%c[swbytes]                 \n"
			"bcc   92f                              \n"
			"cmp   r3, r2                           \n"
			"blo   92f                              \n"
			"ldr   r2, [r1, %c[offtop]]             \n"
			"subs  r2, #%c[hwbase]                  \n"
			"bcc   92f                              \n"
			"cmp   r0, r2                           \n"
			"bhi   92f                              \n"
			"ldr   r3, [r0, %c[xpsr]]               \n"
			"tst   r3, #0x200                       \n"
			"beq   83f                              \n"
			"subs  r2, #%c[alignpad]                \n"
			"bcc   92f                              \n"
			"83:                                    \n"
			"cmp   r0, r2                           \n"
			"bhi   92f                              \n"

			/* Save and unload the active Secure stack before selection. */
			"push  {r0, r1, r2, lr}                 \n"
			"mov   r0, r1                           \n"
			"bl    fiber_port_secure_context_save_current_from_pendsv \n"
			"mov   r3, r0                           \n"
			"pop   {r0, r1, r2, lr}                 \n"

			/* FreeRTOS ARM_CM33 SecureContext frame, low to high:
			 * handle, PSPLIM, EXC_RETURN, r4-r11. */
			"ldr   r2, [r1, %c[offsb]]              \n"
			"mrs   r12, psplim                      \n"
			"cmp   r12, r2                          \n"
			"bne   93f                              \n"
			"stmdb r0!, {r4-r11}                    \n"
			"mov   r2, r3                           \n"
			"mrs   r3, psplim                       \n"
			"stmdb r0!, {r2, r3, lr}                \n"
			"str   r0, [r1]                         \n"

			fiber_portASM_ENTER_SCHEDULER_CRITICAL
			"mov   r0, r1                           \n"
			"bl    fiber_port_scheduler_pick_next_from_pendsv \n"
			fiber_portASM_EXIT_SCHEDULER_CRITICAL
			"mrs   r1, " fiber_portBASEPRI_SYM "    \n"
			"cmp   r1, #0                           \n"
			"bne   95f                              \n"

			/* Allocate a never-run attached context after current Secure
			 * state is unloaded, but before any next Secure state is loaded. */
			"push  {r0, lr}                         \n"
			"bl    fiber_port_secure_context_prepare_next_from_pendsv \n"
			"mov   r3, r0                           \n"
			"pop   {r1, lr}                         \n"

			/* Restore special words first, matching FreeRTOS ordering. */
			"ldr   r2, [r1]                         \n"
			"ldr   r0, [r2]                         \n"
			"cmp   r0, r3                           \n"
			"bne   97f                              \n"
			"ldmia r2!, {r0, r3, lr}                \n"
			"mvn   r12, #67                         \n" /* 0xFFFFFFBC */
			"cmp   lr, r12                          \n"
			"bne   94f                              \n"
			"msr   psplim, r3                       \n"
			"dsb                                    \n"
			"isb                                    \n"
			"mrs   r12, psplim                      \n"
			"cmp   r12, r3                          \n"
			"bne   93f                              \n"

			/* Load owned Secure state only after next NS PSPLIM is active. */
			"push  {r1-r3, lr}                      \n"
			"mov   r12, r0                          \n"
			"mov   r0, r1                           \n"
			"mov   r1, r12                          \n"
			"bl    fiber_port_secure_context_load_next_from_pendsv \n"
			"pop   {r1-r3, lr}                      \n"

			"ldmia r2!, {r4-r11}                    \n"
			"msr   psp, r2                          \n"
			"isb                                    \n"
			"mrs   r1, psp                          \n"
			"cmp   r1, r2                           \n"
			"bne   92f                              \n"

			/* No scheduler or CMSE call may leak privileged NS state. */
			"mrs   r1, " fiber_portBASEPRI_SYM "    \n"
			"cmp   r1, #0                           \n"
			"bne   95f                              \n"
			"mrs   r1, control                      \n"
			"and   r1, r1, #3                       \n"
			"cmp   r1, #2                           \n"
			"bne   96f                              \n"
			"mrs   r1, primask                      \n"
			"cmp   r1, #0                           \n"
			"bne   96f                              \n"
			"mrs   r1, faultmask                    \n"
			"cmp   r1, #0                           \n"
			"bne   96f                              \n"

			"dsb                                    \n"
			"isb                                    \n"
			"bx    lr                               \n"

			"90:                                    \n"
			"movs  r0, #67                          \n" /* 'C' */
			"bl    fiber_panic                      \n"
			"b     90b                              \n"
			"91:                                    \n"
			"movs  r0, #106                         \n" /* 'j' */
			"bl    fiber_panic                      \n"
			"b     91b                              \n"
			"92:                                    \n"
			"movs  r0, #100                         \n" /* 'd' */
			"bl    fiber_panic                      \n"
			"b     92b                              \n"
			"93:                                    \n"
			"movs  r0, #76                          \n" /* 'L' */
			"bl    fiber_panic                      \n"
			"b     93b                              \n"
			"94:                                    \n"
			"movs  r0, #120                         \n" /* 'x' */
			"bl    fiber_panic                      \n"
			"b     94b                              \n"
			"95:                                    \n"
			"movs  r0, #98                          \n" /* 'b' */
			"bl    fiber_panic                      \n"
			"b     95b                              \n"
			"96:                                    \n"
			"movs  r0, #108                         \n" /* 'l' */
			"bl    fiber_panic                      \n"
			"b     96b                              \n"
			"97:                                    \n"
			"movs  r0, #68                          \n" /* 'D' */
			"bl    fiber_panic                      \n"
			"b     97b                              \n"
			".ltorg                                 \n"
			:
			: [sched_basepri] "i" (FIBER_PORT_SCHEDULER_BASEPRI),
			  [swbytes] "I" (FIBER_PORT_SOFTWARE_FRAME_BYTES),
			  [hwbase] "I" (FIBER_PORT_EXC_BASE_BYTES),
			  [alignpad] "I" (FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES),
			  [xpsr] "I" (fiber_portSVC_OFFSET_STACKED_XPSR),
			  [offsb] "I" (fiber_portSVC_OFF_STACK_BASE),
			  [offtop] "I" (fiber_portSVC_OFF_STACK_TOP)
			: "memory", "cc");
}
