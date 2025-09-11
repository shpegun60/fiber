/*
 * fiber_boot.c
 *
 * Minimal, universal PSP boot helpers for STM32 Cortex-M (bare-metal).
 * - Naked trampoline to switch Thread mode to PSP and tail-call an entry.
 * - Safe wrapper: validates stack bounds/size using (base, top), programs PSPLIM (M33),
 *   enforces privileged Thread+MSP precondition, never returns.
 *
 * No RTOS coexistence. If you call this under an RTOS, you own the crash.
 */

/* Arch support notes:
 * - ARMv6-M (Cortex-M0/M0+): PSP present; CONTROL.SPSEL works; no PSPLIM; no Mem/Bus/Usage faults; no FPU.
 * - ARMv7-M / ARMv7E-M: PSP present; optional FPU; no PSPLIM.
 * - ARMv8-M Mainline: PSP + PSPLIM; optional TrustZone (NSACR/SCB_NS) guarded by ifdefs.
 */


#include "fiber_boot.h"
#include "fiber_panic.h"

/* --------------------------------------------------------------------------
 * Trampoline: atomically switch Thread mode to PSP and branch to next(arg).
 * Never returns. M0-safe (Thumb-1 only where required).
 *
 * Register contract on entry:
 *   r0: psp_top  — target PSP top (caller ensured 8-byte alignment or higher)
 *   r1: next     — entry function (Thumb, must not return)
 *   r2: arg      — argument passed to next(arg)
 *   r3: msp_top  — optional MSP top (0 means leave MSP unchanged)
 * -------------------------------------------------------------------------- */
static FIBER_NORETURN FIBER_ATTR_NAKED_ASM
void fiber_boot_trampoline(void *psp_top, void (*next)(void*), void *arg, void *msp_top)
{
	__ASM volatile(
			/* ---------------------------------------------------------------------- 	*/
			/* Save & mask IRQs                                                       	*/
			/* ---------------------------------------------------------------------- 	*/
			"mrs   r12, PRIMASK        \n"  /* save current IRQ mask into r12         	*/
			"cpsid i                   \n"  /* mask IRQs (NMI/HardFault stay enabled) 	*/
			"isb                       \n"  /* ensure mask IRQs are recognized immediately (serialize PRIMASK change) */

			/* ---------------------------------------------------------------------- 	*/
			/* Program PSP                                                            	*/
			/* ---------------------------------------------------------------------- 	*/
			"lsrs  r0, r0, #3          \n"  /* align psp_top down to 8 bytes: r0 >>= 3 	*/
			"lsls  r0, r0, #3          \n"  /* restore magnitude with low 3 bits = 0   	*/
			"msr   psp, r0             \n"  /* PSP = r0 (new process stack pointer)    	*/
			"isb                       \n"  /* ensure PSP write takes effect before read-back (required before dependent reads) */
			/* read-back PSP into r4 and verify */
			"mrs   r4, psp             \n"
			"cmp   r4, r0              \n"
			"bne   9f                  \n"  /* if PSP didn't take the value, go to fatal path */

			/* ---------------------------------------------------------------------- 	*/
			/* Optionally set MSP if msp_top != 0                                     	*/
			/* ---------------------------------------------------------------------- 	*/
			"cmp   r3, #0              \n"  /* msp_top provided? compare r3 with 0     	*/
			"beq   1f                  \n"  /* if r3 == 0, skip MSP update             	*/
			"lsrs  r3, r3, #3          \n"  /* align msp_top down to 8 bytes: r3 >>= 3 	*/
			"lsls  r3, r3, #3          \n"  /* restore magnitude with low 3 bits = 0   	*/
			"msr   msp, r3             \n"  /* MSP = r3 (new main stack for handlers)  	*/
			"isb                       \n"  /* ensure MSP write takes effect before read-back */
			/* read-back MSP into r4 and verify */
			"mrs   r4, msp             \n"
			"cmp   r4, r3              \n"
			"bne   9f                  \n"  /* mismatch means we refuse to proceed safely */
			"1:                        \n"  /* label: fall through (no MSP change)     	*/

			/* ---------------------------------------------------------------------- 	*/
			/* Select PSP for Thread mode                                             	*/
			/* ---------------------------------------------------------------------- 	*/
			"mrs   r3, control         \n"  /* r3 = CONTROL                             */
			"movs  r5, #2              \n"  /* mask for SPSEL                           */
			"orr   r3, r3, r5          \n"  /* set CONTROL.SPSEL (bit1) -> use PSP      */
			"msr   control, r3         \n"  /* write CONTROL with SPSEL=1               */
			"isb                       \n"  /* make SPSEL change visible before verification (architecturally required) */
			/* verify SPSEL==1 */
			"mrs   r4, control         \n"
			"tst   r4, r5              \n"
			"beq   9f                  \n"  /* if SPSEL didn't latch, fail hard         */

			/* ---------------------------------------------------------------------- 	*/
			/* Serialize state change before re-enabling IRQs                         	*/
			/* ---------------------------------------------------------------------- 	*/
			"dsb                       \n"  /* complete prior explicit memory accesses 	*/
			"isb                       \n"  /* synchronize pipeline; ultra-conservative here */

			/* ---------------------------------------------------------------------- 	*/
			/* Safety: if next() ever returns, fault deterministically                	*/
			/* ---------------------------------------------------------------------- 	*/
			"movs  r3, #0              \n"  /* M0/M0+: no MOV imm to LR; zero r3 first  */
			"mov   lr, r3              \n"  /* LR = 0 (Thumb bit cleared) => INVSTATE   */
			/* returning via BX LR will cause INVSTATE/HardFault */

			/* ---------------------------------------------------------------------- 	*/
			/* (Optional) Fence before restoring IRQs if caller might add shared writes */
			/* ---------------------------------------------------------------------- 	*/
			"dmb                       \n"  /* ensure prior core writes are observable by other agents */

			/* ---------------------------------------------------------------------- 	*/
			/* Restore IRQ mask                                                       	*/
			/* ---------------------------------------------------------------------- 	*/
			"msr   PRIMASK, r12        \n"  /* restore saved PRIMASK (may unmask IRQs) 	*/
			"isb                       \n"  /* ensure new PRIMASK state takes effect before next instruction */

			/* ---------------------------------------------------------------------- 	*/
			/* Tail-call next(arg) — never returns                                    	*/
			/* ---------------------------------------------------------------------- 	*/
			"mov   r0, r2              \n"  /* r0 = arg (ABI: first argument in r0)    	*/
			"bx    r1                  \n"  /* branch to next (Thumb), never returns   	*/

			/* Fatal path: make a UsageFault and park */
			"9:                        \n"
			"udf   #0                  \n"  /* architecturally-defined undefined instruction -> UsageFault/HardFault */
			"b     9b                  \n"  /* spin forever in the fault path (won't return) */

			:
			:
			: "r0","r1","r2","r3","r4", "r5","r12","lr","cc","memory"
	);
}


/* --------------------------------------------------------------------------
 * Clear "sticky" fault status where architecturally present (v7-M/v7E-M/v8-M Mainline).
 * Use read-then-write (W1C) to avoid leftovers from a previous boot/loader session.
 * -------------------------------------------------------------------------- */
static inline void fiber_clear_sticky_faults(void)
{
#if defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_8M_MAIN__)
	/* CFSR: Configurable Fault Status Register (W1C). */
	const volatile uint32_t cfsr = SCB->CFSR;   /* read current sticky bits */
	SCB->CFSR = cfsr;                  /* write-back ‘1’s to clear them */

	/* HFSR: Hard Fault Status Register (W1C). */
	const volatile uint32_t hfsr = SCB->HFSR;
	SCB->HFSR = hfsr;

	/* DFSR: Debug Fault Status Register (W1C). Some CMSIS expose bit masks, some don’t. */
# if defined(SCB_DFSR_EXTERNAL_Msk) || defined(SCB_DFSR_BKPT_Msk) || 	\
		defined(SCB_DFSR_DWTTRAP_Msk)  || defined(SCB_DFSR_VCATCH_Msk) || 	\
		defined(SCB_DFSR_HALTED_Msk)
	const volatile uint32_t dfsr = SCB->DFSR;
	SCB->DFSR = dfsr;
# else
	SCB->DFSR = 0x1Fu;                 /* clear all standard DFSR bits if masks are missing */
# endif

	{ __DSB(); __ISB(); }                  	/* serialize side effects of status clears */
#else
	(void)0;                            	/* v6-M may lack these regs: nothing to do */
#endif
}

/* --------------------------------------------------------------------------
 * Platform hygiene: enable fault handlers, enforce 8-byte stack alignment,
 * optional traps for UB, and FPU policy (CPACR and lazy stacking) if present.
 * Idempotent and safe to call once or multiple times at boot.
 * -------------------------------------------------------------------------- */
static inline void fiber_platform_bootstrap(void)
{
	fiber_clear_sticky_faults();

	/* Let Mem/Bus/Usage faults fire (where available) to catch programming errors early. */
#if defined(SCB_SHCSR_MEMFAULTENA_Msk) || defined(SCB_SHCSR_BUSFAULTENA_Msk) || defined(SCB_SHCSR_USGFAULTENA_Msk)
	SCB->SHCSR |=
# ifdef SCB_SHCSR_MEMFAULTENA_Msk
			SCB_SHCSR_MEMFAULTENA_Msk |
# endif
# ifdef SCB_SHCSR_BUSFAULTENA_Msk
			SCB_SHCSR_BUSFAULTENA_Msk |
# endif
# ifdef SCB_SHCSR_USGFAULTENA_Msk
			SCB_SHCSR_USGFAULTENA_Msk
# else
			0u
# endif
			;
#endif

	/* Keep exception frames 8-byte aligned as per ARM ABI. */
#ifdef SCB_CCR_STKALIGN_Msk
	SCB->CCR |= SCB_CCR_STKALIGN_Msk;
#endif

	/* Optionally trap unaligned accesses and division-by-zero to surface UB early. */
#if defined(SCB_CCR_UNALIGN_TRP_Msk) && FIBER_ENABLE_UNALIGNED_TRAP
	SCB->CCR |= SCB_CCR_UNALIGN_TRP_Msk;
#endif
#if defined(SCB_CCR_DIV_0_TRP_Msk) && FIBER_ENABLE_DIV0_TRAP
	SCB->CCR |= SCB_CCR_DIV_0_TRP_Msk;
#endif

	/* Optionally enable FPU access (CP10/CP11) if an FPU exists and the build may emit FP instructions.
       Use architectural bit positions instead of vendor-specific masks; do a read-back and only write if needed. */
#if FIBER_HAS_FPU && FIBER_ENABLE_CPACR
	const uint32_t CPACR_CP10_CP11_FULL = 0x00F00000u;  /* CP11[23:22]=11, CP10[21:20]=11 => full access */

	/* Secure CPACR (current world): enable only if not already enabled */
	volatile uint32_t cpacr = SCB->CPACR;
	if ((cpacr & CPACR_CP10_CP11_FULL) != CPACR_CP10_CP11_FULL) {
		cpacr = (cpacr & ~CPACR_CP10_CP11_FULL) | CPACR_CP10_CP11_FULL;
		SCB->CPACR = cpacr;               	/* enable CP10/CP11 full access in Secure */
		{ __DSB(); __ISB(); }                 /* ensure the change is visible before any FP usage */
	}

	/* TrustZone allowances only make sense on v8-M Mainline, secure build with CMSE. */
# if defined(__ARM_ARCH_8M_MAIN__) && defined(__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3U)
#   ifdef SCB_NSACR
	/* 1) Allow FP in Non-secure world via NSACR (R/W, NOT W1C). Do RMW to avoid touching other bits. */
	const uint32_t NSACR_CP10_CP11_FULL = (3u << 10);   /* NSACR.CP10=11b, CP11=11b */
	volatile uint32_t nsacr = SCB->NSACR;
	if ((nsacr & NSACR_CP10_CP11_FULL) != NSACR_CP10_CP11_FULL) {
		nsacr |= NSACR_CP10_CP11_FULL;  /* set only the FP permission bits */
		SCB->NSACR = nsacr;
		{ __DSB(); __ISB(); }               /* serialize before touching NS CPACR */
	}
#   endif
#   ifdef SCB_NS
	/* 2) Non-secure CPACR via Secure alias. Again, RMW only if needed. */
	volatile uint32_t nscpacr = SCB_NS->CPACR;
	if ((nscpacr & CPACR_CP10_CP11_FULL) != CPACR_CP10_CP11_FULL) {
		nscpacr = (nscpacr & ~CPACR_CP10_CP11_FULL) | CPACR_CP10_CP11_FULL;
		SCB_NS->CPACR = nscpacr;        	/* enable CP10/CP11 full access in Non-secure */
		{ __DSB(); __ISB(); }               /* make effective before NS code runs FP */
	}
#   endif
# endif /* TZ secure build */
#endif /* FPU gate */
	/* FPU lazy stacking policy (does nothing if FPU is absent or headers lack FPU symbols). */
#if FIBER_HAS_FPU
# ifdef FPU
#  ifdef FPU_FPCCR_ASPEN_Msk
	FPU->FPCCR |= FPU_FPCCR_ASPEN_Msk;                   /* enable automatic FP context save trigger */
#  endif
#  ifdef FPU_FPCCR_LSPEN_Msk
#   if FIBER_FPU_LAZY
	FPU->FPCCR |= FPU_FPCCR_LSPEN_Msk;                   /* enable lazy FP context stacking */
#   else
	FPU->FPCCR &= ~FPU_FPCCR_LSPEN_Msk;                  /* disable lazy stacking (eager) */
#   endif
#  endif
# endif
#endif
}


/* --------------------------------------------------------------------------
 * Universal PSP start wrapper (bare-metal only).
 *
 * Parameters:
 *   psp_top  - top of PSP stack (byte address). Rounded down to 8-byte alignment.
 *   next     - entry function to run on PSP (must not return). Must be Thumb (bit0=1).
 *   arg      - argument passed to next as r0.
 *   psp_base - base (lowest address) of the PSP stack region. REQUIRED.
 *              Used to validate size and, on Armv8-M Mainline, to program PSPLIM.
 *
 * Behavior:
 *   - Validates arguments: non-null pointers, Thumb entry, base alignment.
 *   - Enforces preconditions: Thread mode (not Handler), privileged, SPSEL==0.
 *   - Computes red-zone start:
 *         redzone_base = psp_base + FIBER_STACK_REDZONE_BYTES
 *         redzone_8    = align_up(redzone_base, 8)
 *   - Verifies available size:
 *         top_aligned = align_down(psp_top, 8)
 *         avail = top_aligned - redzone_8
 *         require: avail >= (FIBER_EXC_PER_LEVEL * FIBER_EXC_LEVELS_ON_PSP) + FIBER_BOOT_EXTRA_BYTES
 *     Note: only the first preemption from Thread→Handler can stack on PSP; nested IRQs use MSP.
 *   - If PSPLIM is supported (Armv8-M Mainline), programs PSPLIM = redzone_8 and read-backs.
 *   - Optionally rewinds MSP to the initial top-of-stack from the active vector table
 *     (VTOR if present, else 0x00000000) when FIBER_REWIND_MSP=1.
 *   - Switches Thread mode to PSP and tail-calls next(arg) via the naked trampoline.
 *   - Never returns; if next returns anyway, spins forever after forcing a fault.
 * -------------------------------------------------------------------------- */


/* --------------------------------------------------------------------------
 * Universal PSP start wrapper (bare-metal only).
 * (all previous commentary preserved; only new plausibility checks added)
 * -------------------------------------------------------------------------- */
FIBER_NORETURN
FIBER_ATTR_SENSITIVE
void fiber_boot(void *psp_top, void (*next)(void*), void *arg, void *psp_base)
{
	/* Basic contract checks. */
	FIBER_REQUIRE(next     != NULL, 'E');
	FIBER_REQUIRE(psp_top  != NULL, 'T');
	FIBER_REQUIRE(psp_base != NULL, 'B');

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); } /* belt-and-suspenders serialization */

	/* Must be Thread mode (not Handler). */
	FIBER_REQUIRE(__get_IPSR() == 0u, 'I');

	/* Must be privileged and using MSP in Thread mode. */
	const uint32_t ctl0 = __get_CONTROL();
	FIBER_REQUIRE((ctl0 & 1u) == 0u, 'p'); /* nPRIV==0 => privileged */
	FIBER_REQUIRE((ctl0 & 2u) == 0u, 's'); /* SPSEL==0 => MSP selected in Thread */

	/* Entry must be Thumb (bit0==1) to ensure correct BX target. */
	const uintptr_t next_addr = (uintptr_t)next;
	FIBER_REQUIRE(((next_addr & 1u) == 1u), 'e');

	/* Optional: ensure target code address (stripped of Thumb bit) looks plausible. */
	FIBER_REQUIRE(fiber_addr_plausible_code(next_addr & ~(uintptr_t)1u) != 0, 'c');

	/* Align and validate PSP bounds. */
	const uintptr_t top_aligned = ((uintptr_t)psp_top) & ~(uintptr_t)7u; /* align down to 8 */
	const uintptr_t base        =  (uintptr_t)psp_base;
	FIBER_REQUIRE((base & 0x3u) == 0u, 'b'); /* base must be word-aligned */

	/* Red-zone start and 8-byte rounded limit for PSPLIM. */
	const uintptr_t redzone_base = base + (uintptr_t)FIBER_STACK_REDZONE_BYTES;
	const uintptr_t redzone8     = (redzone_base + 7u) & ~(uintptr_t)7u; /* align up to 8 */

	FIBER_REQUIRE(redzone8 >= base, 'r');       /* sanity: no wrap */
	FIBER_REQUIRE(top_aligned > redzone8, 'h'); /* non-empty region above redzone */

	/* Application-defined plausibility of the PSP region itself. */
	FIBER_REQUIRE(fiber_addr_plausible_ram(redzone8, top_aligned) != 0, 'P');

	/* Reserve: exactly one exception frame on PSP + extra prologue margin. */
	const size_t need  = (size_t)FIBER_EXC_PER_LEVEL * (size_t)FIBER_EXC_LEVELS_ON_PSP
			+ (size_t)FIBER_BOOT_EXTRA_BYTES;
	const size_t avail = (size_t)(top_aligned - redzone8);
	FIBER_REQUIRE(avail >= need, 'H');

	/* Platform hygiene before switching stacks. */
	fiber_platform_bootstrap();

	/* Program PSPLIM on Armv8-M Mainline (e.g. Cortex-M33). */
#if FIBER_HAS_PSPLIM
	__set_PSPLIM((uint32_t)redzone8);
	__ISB(); /* ensure PSPLIM is live before using PSP */
	FIBER_REQUIRE(__get_PSPLIM() == (uint32_t)redzone8, 'L'); /* read-back verify */
#else
	(void)redzone8;
#endif

#if FIBER_REWIND_MSP
	{ __DSB(); __ISB(); }

	/* Use vector table word 0 (initial MSP): VTOR if present, else 0x00000000. */
	uint32_t msp0a = fiber_read_initial_msp();
	__ISB();
	uint32_t msp0b = fiber_read_initial_msp();

	/* If VTOR/table is unstable or null, try app-provided fallback. */
	if ((msp0a == 0u) || (msp0a != msp0b)) {
		const uintptr_t fb = fiber_fallback_initial_msp();
		FIBER_REQUIRE(fb != 0u, 'f');           /* fallback must provide a non-zero MSP */
		msp0a = (uint32_t)fb;
		msp0b = (uint32_t)fb;
	}
	FIBER_REQUIRE(msp0a == msp0b, 'V');          /* verify MSP is now stable */

	const uintptr_t msp_top = ((uintptr_t)msp0a) & ~(uintptr_t)7u; /* align down to 8 */
	FIBER_REQUIRE(msp_top != 0u, 'M');           /* sanity: non-zero initial MSP */

	/* Basic plausibility check that initial MSP points into RAM. */
    const uintptr_t check_start = (msp_top >= 4u) ? (msp_top - 4u) : msp_top;
    FIBER_REQUIRE(fiber_addr_plausible_ram(check_start, msp_top) != 0, 'R');

	/* MSP must not land inside the PSP region [base..top_aligned]. */
	FIBER_REQUIRE(!(msp_top > base && msp_top <= top_aligned), 'O');

	/* Ensure a minimum gap between MSP and PSP stacks. */
	const size_t gap = (msp_top > top_aligned)
						? (size_t)(msp_top - top_aligned)
								: (size_t)(base - msp_top);
	FIBER_REQUIRE(gap >= (size_t)FIBER_STACK_REDZONE_BYTES, 'G');

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); } /* belt-and-suspenders serialization */
	fiber_boot_trampoline((void*)top_aligned, next, arg, (void*)msp_top);
#else
	/* Leave MSP as-is; verify it does not collide with PSP region anyway. */
	{ __DSB(); __ISB(); }
	const uintptr_t cur_msp = ((uintptr_t)__get_MSP()) & ~(uintptr_t)7u;

	/* Current MSP should plausibly be in RAM as well. */
    const uintptr_t check_start = (cur_msp >= 4u) ? (cur_msp - 4u) : cur_msp;
    FIBER_REQUIRE(fiber_addr_plausible_ram(check_start, cur_msp) != 0, 'r');

	FIBER_REQUIRE(!(cur_msp > base && cur_msp <= top_aligned), 'o'); /* no overlap */
	const size_t gap = (cur_msp > top_aligned)
						? (size_t)(cur_msp - top_aligned)
								: (size_t)(base - cur_msp);
	FIBER_REQUIRE(gap >= (size_t)FIBER_STACK_REDZONE_BYTES, 'g');     /* minimum separation */

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); } /* belt-and-suspenders serialization */
	fiber_boot_trampoline((void*)top_aligned, next, arg, 0);
#endif

	/* Getting here means the world is broken. Force a loud fault and park forever. */
	__ASM volatile ("udf #0" ::: "memory"); /* Guaranteed Usage/HardFault path */
	for (;;) { __WFE(); } /* never returns */
}
