/* fiber_port_core.c — CPU-specific helpers + public API
 *
 * One-translation-unit implementation for cooperative context switching
 * across STM32 Cortex-M series (M0/M0+/M3/M4/M7/M33), with optional FPU
 * and optional PSPLIM (ARMv8-M Mainline / Non-Secure).
 *
 * Public API (opaque):
 *   - FiberContext* fiber_create(void);
 *   - void          fiber_destroy(FiberContext*);
 *   - void          fiber_init(FiberContext*, void* stack_mem, size_t stack_bytes,
 *                              void (*entry)(void*), void* arg);
 *   - void          fiber_switch(FiberContext* from, const FiberContext* to);  // Thread mode only
 *
 * AAPCS compliance: keep SP 8-byte aligned at function entry/exit. We place a
 * single PAD word in the synthetic frame and the trampoline drops it before
 * popping (arg, entry) to guarantee 8-byte alignment at entry().
 *
 * FPU policy (manual context):
 *   - Callee-saved FP regs are s16..s31. FPSCR is considered part of the FP state.
 *   - Each saved context places, directly under the marker word:
 *        [ FPSCR ][ s16..s31 (16 words) ]
 *     If the FP context is not active (CONTROL.FPCA == 0), we still reserve the
 *     same space (68 bytes total) but do not read/write hardware FP registers.
 *     This yields a fixed stack layout and cheap skip via ADD when marker==0.
 *
 * ---------------- Stack layouts (addresses increase downward) ----------------
 *
 * Cortex-M0/M0+ (ARMv6-M):
 *   SP -> +00 [ r8spill ]      ; pop {r4-r7} then mov -> r8..r11
 *         +04 [ r9spill ]
 *         +08 [ r10spill ]
 *         +12 [ r11spill ]
 *         +16 [ r4 ]
 *         +20 [ r5 ]
 *         +24 [ r6 ]
 *         +28 [ r7 ]
 *         +32 [ pc = fiber_trampoline | 1 ]
 *         +36 [ PAD ]          ; keeps entry() SP 8-byte aligned
 *         +40 [ arg ]
 *         +44 [ entry ]
 *
 * Cortex-M3 (ARMv7-M, no FPU):
 *   SP -> +00 [ r4 ]
 *         +04 [ r5 ]
 *         +08 [ r6 ]
 *         +12 [ r7 ]
 *         +16 [ r8 ]
 *         +20 [ r9 ]
 *         +24 [ r10 ]
 *         +28 [ r11 ]
 *         +32 [ pc = fiber_trampoline | 1 ]
 *         +36 [ PAD ]
 *         +40 [ arg ]
 *         +44 [ entry ]
 *
 * Cortex-M4F/M7F/M33 (ARMv7E-M / ARMv8-M, FPU present):
 *   SP -> +00 [ marker ]       ; 0 => no FP state, 1 => FPSCR + s16..s31 valid
 *         +04 [ FPSCR ]
 *         +08 [ s16..s31 ]     ; 16 words (64 bytes)
 *         +72 [ r4 ]
 *         +76 [ r5 ]
 *         +80 [ r6 ]
 *         +84 [ r7 ]
 *         +88 [ r8 ]
 *         +92 [ r9 ]
 *         +96 [ r10 ]
 *         +100[ r11 ]
 *         +104[ pc = fiber_trampoline | 1 ]
 *         +108[ PAD ]
 *         +112[ arg ]
 *         +116[ entry ]
 *
 * Cortex-M33 Non-Secure + PSPLIM:
 *   Same stack as above. FiberContext carries stack_base (lowest stack address),
 *   which is programmed into PSPLIM before switching into that fiber.
 */


#include "fiber.h"
#include "target/fiber_compiler.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>   /* malloc/free */

#if defined(__cplusplus)
#  include <new>
#endif


/* Diagnostics helper (panic-on-fail) */
#ifndef FIBER_REQUIRE
#  define FIBER_REQUIRE(cond, code) do { if (!(cond)) fiber_panic((code)); } while (0)
#endif

#if defined(FIBER_STACK_CANARY) && !FIBER_HAS_PSPLIM
#  define FIBER_NEEDS_BASE_FIELD 1
#else
#  define FIBER_NEEDS_BASE_FIELD 0
#endif

/* --------- Opaque layout (private) --------- */
struct FiberContext {
	uint32_t* sp;             /* must be at offset 0 */
#if FIBER_HAS_PSPLIM || FIBER_NEEDS_BASE_FIELD
	uint32_t* stack_base;     /* low bound for PSPLIM and/or canary */
#endif
};
typedef struct FiberContext FiberContext;

static_assert(offsetof(struct FiberContext, sp) == 0, "fiber: sp offset");
#if FIBER_HAS_PSPLIM || FIBER_NEEDS_BASE_FIELD
static_assert(offsetof(struct FiberContext, stack_base) == 4, "fiber: stack_base offset");
#endif
static_assert(alignof(struct FiberContext) >= 4, "fiber: align >= 4");

/* Minimal frame size in 32-bit words (matches the synthetic frame in fiber_init) */
#if defined(__ARM_ARCH_6M__)
enum { FIBER_MIN_FRAME_WORDS = 12 };                 /* H4(4)+L4(4)+PC+PAD+ARG+ENTRY */
#else
# if FIBER_HAS_FPU
enum { FIBER_MIN_FRAME_WORDS = 8 + 1 + 1 + 2 + 16 + 1 + 1 };
/* r4..r11(8) + PC(1) + PAD(1) + ARG+ENTRY(2) + s16..s31(16) + FPSCR(1) + marker(1) = 30 */
# else
enum { FIBER_MIN_FRAME_WORDS = 8 + 1 + 1 + 2 };      /* 12 */
# endif
#endif
enum { FIBER_MIN_FRAME_BYTES = FIBER_MIN_FRAME_WORDS * 4u };


/* ---------- Diagnostics / Panic ---------- */
FIBER_WEAK FIBER_NORETURN FIBER_NOINSTR
void fiber_panic(const char code) {
	(void)code;
#if defined(__arm__) || defined(__thumb__)
	__asm volatile ("bkpt #0" ::: "memory");
#endif
	for(;;) { /* spin */ }
}

/* ---------- Tiny CPU helpers ---------- */
static inline uint32_t FIBER_NOINSTR fiber_rd_ipsr(void) {
	uint32_t x;
	__asm volatile ("mrs %0, ipsr" : "=r"(x) :: "memory");
	return x;
}

static inline void FIBER_NOINSTR fiber_isb(void) {
	__asm volatile ("isb" ::: "memory");
}

static inline uint32_t FIBER_NOINSTR fiber_rd_control(void) {
	uint32_t x;
	__asm volatile("mrs %0, control" : "=r"(x) :: "memory");
	__get_CONTROL();
	return x;
}


#if FIBER_HAS_PSPLIM
static inline void FIBER_NOINSTR fiber_wr_psplim(uint32_t* base) {
	__asm volatile ("msr psplim, %0" :: "r"(base) : "memory");
	fiber_isb(); /* make limit effective immediately */
}
#endif

static inline uintptr_t fiber_align_down(uintptr_t x, size_t a) {
	return x & ~((uintptr_t)a - 1u);
}

/* ---------- Heap lifecycle ---------- */
FiberContext* fiber_create(void) {
#if defined(__cplusplus)
	return new (std::nothrow) FiberContext{};
#else
	FiberContext* p = (FiberContext*)malloc(sizeof *p);
	if (p) {
		/* zero-init without pulling in memset */
		unsigned char* b = (unsigned char*)p;
		for (size_t i = 0; i < sizeof *p; ++i) b[i] = 0;
	}
	return p;
#endif
}

void fiber_destroy(FiberContext* ctx) {
#if defined(__cplusplus)
	delete ctx;
#else
	free(ctx);
#endif
}



/* ---------- Default trampoline (Thumb), weak so you can override ---------- */
FIBER_NAKED FIBER_WEAK FIBER_NOINSTR FIBER_USED
void fiber_trampoline(void) {
	__asm volatile(
			"add  sp, sp, #4\n"  /* drop PAD to keep 8-byte alignment at entry() */
			"pop  {r0, r1}\n"    /* r0 = arg, r1 = entry */
			"blx  r1\n"          /* entry(arg), must not return */
			"b    .\n"           /* if it returns: spin */
	);
}

/* ---------- Public API ---------- */
void fiber_init(FiberContext* ctx,
		void*         stack_mem,
		size_t        stack_bytes,
		void        (*entry)(void*),
		void*         arg)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	FIBER_REQUIRE(stack_mem != NULL, 'M');
	FIBER_REQUIRE(entry != NULL, 'E');

	const uintptr_t base   = (uintptr_t)stack_mem;
	const uintptr_t rawTop = base + (uintptr_t)stack_bytes;
	const uintptr_t top    = fiber_align_down(rawTop, FIBER_STACK_ALIGN);
	FIBER_REQUIRE(top >= base, 'S');
	FIBER_REQUIRE((((uintptr_t)entry) & 1u) == 1u, 'e'); /* Thumb */

	const size_t avail = (size_t)(top - base);
	FIBER_REQUIRE(avail >= FIBER_MIN_FRAME_BYTES, 'Z');

#ifdef FIBER_STACK_CANARY
	/* Canary lives at the lowest stack word. Require 4-byte alignment to avoid UNALIGNED faults. */
	FIBER_REQUIRE( (base & 3u) == 0u, 'b' );
	((volatile uint32_t*)base)[0] = FIBER_CANARY_VALUE;
#endif

	volatile uint32_t* sp = (volatile uint32_t*)top;

#if defined(__ARM_ARCH_6M__)
	/* Cortex-M0/M0+ (ARMv6-M) synthetic frame layout (from highest address downward):
       [ENTRY][ARG][PAD][PC][L0..L3 = r4..r7][H0..H3 = placeholders for r8..r11] */

	*(--sp) = (uint32_t)(uintptr_t)entry;                    /* ENTRY */
	*(--sp) = (uint32_t)(uintptr_t)arg;                      /* ARG   */
	*(--sp) = 0u;                                            /* PAD   */
	*(--sp) = ((uint32_t)(uintptr_t)&fiber_trampoline) | 1u; /* PC (Thumb) */

	/* Low regs block r4..r7 (popped second into real r4..r7) */
	*(--sp) = 0; /* r7 */
	*(--sp) = 0; /* r6 */
	*(--sp) = 0; /* r5 */
	*(--sp) = 0; /* r4 */

	/* High-block placeholders for r8..r11 (popped first via r4..r7 then moved) */
	*(--sp) = 0; /* -> r11 */
	*(--sp) = 0; /* -> r10 */
	*(--sp) = 0; /* -> r9  */
	*(--sp) = 0; /* -> r8  */

#else
	/* ARMv7-M / ARMv8-M (M3/M4/M7/M33) synthetic frame:
       [ENTRY][ARG][PAD][PC][r11..r4][(s16..s31)][FPSCR][marker]
       On restore (FPU ON): pop marker, pop FPSCR, if marker==1 -> vmsr+vpop; else skip 64 bytes. */

	*(--sp) = (uint32_t)(uintptr_t)entry;                    /* ENTRY */
	*(--sp) = (uint32_t)(uintptr_t)arg;                      /* ARG   */
	*(--sp) = 0u;                                            /* PAD   */
	*(--sp) = ((uint32_t)(uintptr_t)&fiber_trampoline) | 1u; /* PC    */

	/* Core callee-saved */
	*(--sp) = 0; /* r11 */
	*(--sp) = 0; /* r10 */
	*(--sp) = 0; /* r9  */
	*(--sp) = 0; /* r8  */
	*(--sp) = 0; /* r7  */
	*(--sp) = 0; /* r6  */
	*(--sp) = 0; /* r5  */
	*(--sp) = 0; /* r4  */

#if FIBER_HAS_FPU
	/* Reserve space for s16..s31 and FPSCR (contents do not matter initially) */
	for (int i = 0; i < 16; ++i) { *(--sp) = 0; }            /* s16..s31 */
	*(--sp) = 0;                                             /* FPSCR */
	*(--sp) = 0;                                             /* marker (0 => no FP state yet) */
#endif
#endif

	ctx->sp = (uint32_t*)sp;
#if FIBER_HAS_PSPLIM || FIBER_NEEDS_BASE_FIELD
	ctx->stack_base = (uint32_t*)base;
#endif

	/* Extra sanity */
	FIBER_REQUIRE((uintptr_t)ctx->sp >= base, 'U');
	FIBER_REQUIRE( (((uintptr_t)&fiber_trampoline) & 1u) == 1u, 'T' );

	/* Prevent aggressive reordering/elimination under O3/LTO */
	__asm volatile ("" ::: "memory");
}

/* --------- ASM core (naked) + safe C wrapper --------- */
static FIBER_NOINSTR FIBER_NAKED void
fiber_switch_asm(FiberContext* from, const FiberContext* to)
{
#if defined(__ARM_ARCH_6M__)   /* ---------------- Cortex-M0/M0+ ---------------- */
	__asm volatile (
			/* r0 = from, r1 = to */
			"push {r4-r7, lr}\n"
			"mov  r4, r8\n"
			"mov  r5, r9\n"
			"mov  r6, r10\n"
			"mov  r7, r11\n"
			"push {r4-r7}\n"          /* save high regs via r4..r7 */

			"str  sp, [r0]\n"         /* from->sp = sp */
			"ldr  r2, [r1]\n"         /* to->sp */
			"mov  sp, r2\n"           /* sp = to->sp  */

			"pop  {r4-r7}\n"          /* load high-block placeholders */
			"mov  r8,  r4\n"
			"mov  r9,  r5\n"
			"mov  r10, r6\n"
			"mov  r11, r7\n"
			"pop  {r4-r7, pc}\n"      /* load low-block and jump */
	);
#else                           /* --------------- Cortex-M3/M4/M7/M33 ---------- */
#if FIBER_HAS_FPU
	__asm volatile (
			/* r0 = from, r1 = to */
			"push {r4-r11, lr}\n"

			/* Decide FP path, prepare [FPSCR][s16..s31] under the marker */
			"mrs  r2, control\n"      /* CONTROL.FPCA bit2 */
			"tst  r2, #4\n"
			"beq  0f\n"
			"vpush {s16-s31}\n"
			"vmrs r3, fpscr\n"
			"movs r2, #1\n"
			"b    1f\n"
			"0:\n"
			"sub  sp, sp, #64\n"      /* reserve s16..s31 area */
			"movs r3, #0\n"           /* dummy FPSCR */
			"movs r2, #0\n"           /* marker=0 */
			"1:\n"
			"push {r3}\n"             /* FPSCR */
			"push {r2}\n"             /* marker */

			"str  sp, [r0]\n"         /* from->sp = sp */
			"ldr  r3, [r1]\n"         /* to->sp */
			"mov  sp, r3\n"           /* sp = to->sp   */

			/* Restore next: marker, FPSCR, then FP regs or skip. */
			"pop  {r2}\n"             /* marker */
			"pop  {r3}\n"             /* FPSCR word */
			"cbz  r2, 2f\n"
			"vmsr fpscr, r3\n"
			"vpop {s16-s31}\n"
			"b    3f\n"
			"2:\n"
			"add  sp, sp, #64\n"      /* skip s16..s31 block when marker==0 */
			"3:\n"
			"pop  {r4-r11, pc}\n"
	);
#else
	__asm volatile(
			/* r0 = from, r1 = to */
			"push {r4-r11, lr}\n"
			"str  sp, [r0]\n"         /* from->sp = sp */
			"ldr  r2, [r1]\n"         /* to->sp */
			"mov  sp, r2\n"           /* sp = to->sp   */
			"pop  {r4-r11, pc}\n"
	);
#endif
#endif
}

void fiber_switch(FiberContext* from, const FiberContext* to)
{
	/* Must be called from Thread mode, never from ISRs */
	FIBER_REQUIRE(fiber_rd_ipsr() == 0u, 'I');
	FIBER_REQUIRE((fiber_rd_control() & 2u) != 0u, 'p'); /* PSP selected */
	FIBER_REQUIRE(from != NULL, 'F');
	FIBER_REQUIRE(to   != NULL, 'T');
	FIBER_REQUIRE(from != to,   'X');
	FIBER_REQUIRE( (((uintptr_t)to->sp) & (FIBER_STACK_ALIGN - 1u)) == 0u, 'A');

#if FIBER_HAS_PSPLIM
	FIBER_REQUIRE(to->stack_base != NULL, 'P');
	fiber_wr_psplim(to->stack_base);
#endif

	/* Do the real switch; control returns here only when some other fiber switches back. */
	fiber_switch_asm(from, to);

#ifdef FIBER_STACK_CANARY
#if FIBER_HAS_PSPLIM || FIBER_NEEDS_BASE_FIELD
	if (to->stack_base) {
		FIBER_REQUIRE(*(volatile uint32_t*)to->stack_base == FIBER_CANARY_VALUE, 'K');
	}
#endif
#endif
}
