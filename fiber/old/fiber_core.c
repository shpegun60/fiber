///* fiber_core.c */
//#include "fiber_core.h"
//
///* ----------------------------------------------------------------------
// * fiber_trampoline: enters user entry(arg) on PSP
// * Invariants checked:
// *  - ENTRY must be Thumb (LSB=1)
// *  - SP must be 8-byte aligned per AAPCS
// *  - Must be in Thread mode (IPSR==0)
// * Safety:
// *  - IRQs off during checks, then re-enabled before branch
// *  - LR forced to 0 so return from entry() triggers INVSTATE/HardFault
// * ---------------------------------------------------------------------- */
//
///* UDF trap opcode (portable between GCC/Clang and IAR) */
//#if defined(__ICCARM__)
//#  define FIBER_TRAP_UDF16 "DC16 0xDE00              \n"
//#else
//#  define FIBER_TRAP_UDF16 ".inst.n 0xDE00           \n"
//#endif
//
//FIBER_ATTR_SENSITIVE void fiber_task_return(void)
//{
//	/* If entry() ever returns, park CPU in low-power loop */
//	while (1) {
//		__WFI();
//	}
//}
//
//FIBER_ATTR_NAKED_ASM
//void fiber_trampoline(void)
//{
//	__ASM volatile(
//			/* ----------------------------------------------------------------------
//			 * Prologue: hard-mask IRQs and serialize before touching the stack
//			 * ---------------------------------------------------------------------- */
//			"cpsid i                   \n"  /* Globally disable IRQs (I-bit set) */
//			"dsb                       \n"  /* Complete all outstanding memory ops */
//			"isb                       \n"  /* Sync pipeline so mask takes effect */
//
//			/* ----------------------------------------------------------------------
//			 * Load arguments for entry: SP must currently point to [ARG][ENTRY]
//			 * ---------------------------------------------------------------------- */
//			"pop  {r0, r1}             \n"  /* r0=arg, r1=entry (pop 2 words from current PSP) */
//
//			/* ----------------------------------------------------------------------
//			 * ENTRY must be Thumb (LSB==1). Use only Thumb-1 safe sequences on v6-M.
//			 * ---------------------------------------------------------------------- */
//			"movs r2, #1               \n"  /* r2 = 1 (Thumb bit mask) */
//			"tst  r1, r2               \n"  /* test ENTRY & 1 -> Z==0 means not Thumb */
//#if defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_8M_BASE__)
//			"bne  0f                   \n"  /* if (Thumb) ok -> skip trap */
//			"bkpt #0                   \n"  /* else break into HardFault/Debugger (no UDF on v6-M) */
//			"b    .                    \n"  /* park CPU if debugger not attached */
//			"0:                        \n"  /* label: continue when ENTRY is Thumb */
//#else
//			"bne  0f                   \n"  /* if (Thumb) ok -> skip trap */
//			FIBER_TRAP_UDF16               	/* else generate UsageFault via UDF16 */
//			"b    .                    \n"  /* park CPU forever */
//			"0:                        \n"  /* label: continue when ENTRY is Thumb */
//#endif
//
//			/* ----------------------------------------------------------------------
//			 * AAPCS requires 8-byte SP alignment at public interface boundaries
//			 * ---------------------------------------------------------------------- */
//			"mov  r2, sp               \n"  /* r2 = current SP */
//			"movs r3, #7               \n"  /* r3 = 7 (mask for low 3 bits) */
//			"ands r2, r3               \n"  /* r2 = SP & 7; zero if 8-byte aligned */
//#if defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_8M_BASE__)
//			"beq  1f                   \n"  /* if aligned -> ok */
//			"bkpt #0                   \n"  /* else trap (no UDF on v6-M) */
//			"b    .                    \n"  /* park CPU */
//			"1:                        \n"  /* label: aligned path */
//#else
//			"beq  1f                   \n"  /* if aligned -> ok */
//			FIBER_TRAP_UDF16               	/* else UsageFault via UDF16 */
//			"b    .                    \n"  /* park CPU */
//			"1:                        \n"  /* label: aligned path */
//#endif
//
//			/* ----------------------------------------------------------------------
//			 * Must be in Thread mode (IPSR==0). v6-M lacks CBZ, use CMP/BEQ.
//			 * ---------------------------------------------------------------------- */
//			"mrs  r2, ipsr             \n"  /* r2 = IPSR (nonzero in Handler mode) */
//#if defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_8M_BASE__)
//			"cmp  r2, #0               \n"  /* compare IPSR with 0 */
//			"beq  2f                   \n"  /* if Thread mode -> ok */
//			"bkpt #0                   \n"  /* else trap */
//			"b    .                    \n"  /* park CPU */
//			"2:                        \n"  /* label: Thread mode path */
//#else
//			"cbz  r2, 2f               \n"  /* if IPSR==0 -> Thread mode -> ok */
//			FIBER_TRAP_UDF16               /* else UsageFault */
//			"b    .                    \n"  /* park CPU */
//			"2:                        \n"  /* label: Thread mode path */
//#endif
//
//			/* ----------------------------------------------------------------------
//			 * Safety: prevent returning from entry(). LR=0 => BX LR causes INVSTATE/HardFault
//			 * ---------------------------------------------------------------------- */
//			"movs r3, #0               \n"  /* r3 = 0 */
//			"mov  lr, r3               \n"  /* LR := 0 (invalid EXC_RETURN/pointer) */
//
//			/* ----------------------------------------------------------------------
//			 * Re-enable IRQs and serialize before branching to entry(arg)
//			 * ---------------------------------------------------------------------- */
//			"cpsie i                   \n"  /* Globally enable IRQs again */
//			"dsb                       \n"  /* Ensure all prior stores visible before user code */
//			"isb                       \n"  /* Sync pipeline before branch */
//
//			/* ----------------------------------------------------------------------
//			 * Enter user function: must not return. If it does, fall into parking loop.
//			 * ---------------------------------------------------------------------- */
//			"bx   r1                   \n"  /* branch to entry(arg); never returns */
//			"dsb                       \n"  /* (post-branch safety if it ever fell through) */
//			"isb                       \n"  /* synchronize state */
//
//			/* ----------------------------------------------------------------------
//			 * Fallback parking loop if entry() erroneously returns (should be unreachable)
//			 * ---------------------------------------------------------------------- */
//			"bl   fiber_task_return    \n"  /* call parking function (WFI loop, noreturn) */
//			"b    .                    \n"  /* absolute park if attribute differs */
//	);
//}
//
//#undef FIBER_TRAP_UDF16
///* --------------------------------------------------------------------------
// * fiber_init: build initial frame (no marker), leave one HW frame headroom.
// * Layouts (top -> bottom):
// *
// * v6-M:    [ r8..r11 ][ r4..r7 ][ PRIMASK ][ PC=tramp ][ ARG ][ ENTRY ]
// *
// * v7/v8 no FPU (header padded to keep even pop count before trampoline):
// *          [ r4..r11 ][ PRIMASK ][ BASEPRI ][ ALIGN0 ][ PC=tramp ][ ARG ][ ENTRY ]
// *
// * v7/v8 with FPU (always save FPU; order chosen for even pop count):
// *          [ s16..s31 ][ r4..r11 ][ FPSCR ][ PRIMASK ][ BASEPRI ][ PC=tramp ][ ARG ][ ENTRY ]
// * -------------------------------------------------------------------------- */
//
//static inline uint32_t fiber_read_r9(void) {
//    uint32_t v;
//    __asm__ __volatile__("mov %0, r9" : "=r"(v));
//    return v;
//}
//
//void fiber_init(FiberContext* ctx,
//		void*         stack_begin,
//		void*         stack_end,
//		entry_t       entry,
//		void*         arg)
//{
//	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
//
//	FIBER_REQUIRE(ctx         != NULL, 'C');
//	FIBER_REQUIRE(stack_begin != NULL, 'B');
//	FIBER_REQUIRE(stack_end   != NULL, 'T');
//	FIBER_REQUIRE(entry       != NULL, 'E');
//	FIBER_REQUIRE(stack_end > stack_begin, 'N');
//
//	{   /* entry must be Thumb and plausibly code */
//		const uintptr_t ea = (uintptr_t)entry;
//		FIBER_REQUIRE((ea & 1u) == 1u, 'e');
//		FIBER_REQUIRE(fiber_addr_plausible_code(ea & ~(uintptr_t)1u) != 0, 'c');
//	}
//
//	ctx->boot = fiber_create_boot(stack_begin, stack_end, entry, arg);
//	FIBER_REQUIRE(ctx->boot.avail >= (size_t)FIBER_EXC_PER_LEVEL, 'Z');
//
//#if defined(FIBER_STACK_CANARY) && !FIBER_HAS_PSPLIM
//	{   /* Canary at the low PSP bound when PSPLIM is unavailable */
//		const uintptr_t canary_cell = fiber_word_align_up((uintptr_t)ctx->boot.begin);
//		((volatile uint32_t*)canary_cell)[0] = FIBER_CANARY_VALUE;
//	}
//#endif
//
//	/* Reserve one hardware exception frame headroom */
//	uint32_t* sp = (uint32_t*)(ctx->boot.stack_top - (uintptr_t)FIBER_EXC_PER_LEVEL);
//
//#if defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_8M_BASE__)
//	/* v6-M (M0/M0+): [ r8..r11 ][ r4..r7 ][ PRIMASK ][ PC ][ ARG ][ ENTRY ] */
//	*(--sp) = (uint32_t)(uintptr_t)entry;                    /* ENTRY  */
//	*(--sp) = (uint32_t)(uintptr_t)arg;                      /* ARG    */
//	*(--sp) = ((uint32_t)(uintptr_t)&fiber_trampoline) | 1u; /* PC     */
//	*(--sp) = 1u;                                            /* PRIMASK (masked) */
//	*(--sp) = 0; /* r7 */
//	*(--sp) = 0; /* r6 */
//	*(--sp) = 0; /* r5 */
//	*(--sp) = 0; /* r4 */
//	*(--sp) = 0; /* r11 */
//	*(--sp) = 0; /* r10 */
//	//*(--sp) = 0; /* r9  */
//	*(--sp) = fiber_read_r9();  /* r9  — ВАЖЛИВО */
//	*(--sp) = 0; /* r8  */
//	ctx->sp = sp;
//
//#else /* ---------------- v7/v7E/v8-M ----------------- */
//
//# if !FIBER_HAS_FPU
//	/* v7/v8 (no FPU): [ r4..r11 ][ PRIMASK ][ BASEPRI ][ ALIGN0 ][ PC ][ ARG ][ ENTRY ]
//       Header is 4 words to keep an even pop count before trampoline. */
//	*(--sp) = (uint32_t)(uintptr_t)entry;                    /* ENTRY    */
//	*(--sp) = (uint32_t)(uintptr_t)arg;                      /* ARG      */
//	*(--sp) = ((uint32_t)(uintptr_t)&fiber_trampoline) | 1u; /* PC       */
//	*(--sp) = 0u;                                            /* ALIGN0   */
//	*(--sp) = 0u;                                            /* BASEPRI  */
//	*(--sp) = 1u;                                            /* PRIMASK  */
//
//	/* r11..r4 (pushed in reverse so that LDMIA reads r4..r11) */
//	*(--sp) = 0; /* r11 */
//	*(--sp) = 0; /* r10 */
//	//*(--sp) = 0; /* r9  */
//	*(--sp) = fiber_read_r9();  /* r9  — ВАЖЛИВО */
//	*(--sp) = 0; /* r8  */
//	*(--sp) = 0; /* r7  */
//	*(--sp) = 0; /* r6  */
//	*(--sp) = 0; /* r5  */
//	*(--sp) = 0; /* r4  */
//
//# else /* FIBER_HAS_FPU */
//
//	/* v7/v8 (with FPU, always saved):
//       [ s16..s31 ][ FPSCR ][ r4..r11 ][ PRIMASK ][ BASEPRI ][ PC ][ ARG ][ ENTRY ] */
//	*(--sp) = (uint32_t)(uintptr_t)entry;                    /* ENTRY    */
//	*(--sp) = (uint32_t)(uintptr_t)arg;                      /* ARG      */
//	*(--sp) = ((uint32_t)(uintptr_t)&fiber_trampoline) | 1u; /* PC       */
//	*(--sp) = 0u;                                            /* BASEPRI  */
//	*(--sp) = 1u;                                            /* PRIMASK  */
//
//	/* r11..r4 */
//	*(--sp) = 0; /* r11 */
//	*(--sp) = 0; /* r10 */
//	//*(--sp) = 0; /* r9  */
//	*(--sp) = fiber_read_r9();  /* r9  — ВАЖЛИВО */
//	*(--sp) = 0; /* r8  */
//	*(--sp) = 0; /* r7  */
//	*(--sp) = 0; /* r6  */
//	*(--sp) = 0; /* r5  */
//	*(--sp) = 0; /* r4  */
//
//	*(--sp) = 0u;                                            /* FPSCR    */
//	/* s16..s31 (reserve and zero) — vpop reads them in ascending order */
//	for (int i = 0; i < 16; ++i) { *(--sp) = 0u; }
//
//# endif /* FIBER_HAS_FPU */
//
//	ctx->sp = sp;
//#endif /* __ARM_ARCH_6M__ */
//
//	/* Final invariants */
//	FIBER_REQUIRE((((uintptr_t)ctx->sp) & 7u) == 0u, 'A');  /* 8B alignment */
//	FIBER_REQUIRE((uintptr_t)ctx->sp >= ctx->boot.stack_base, 'U');
//	FIBER_REQUIRE((uintptr_t)ctx->sp <= ctx->boot.stack_top - (uintptr_t)FIBER_EXC_PER_LEVEL, 'S');
//	FIBER_REQUIRE((((uintptr_t)&fiber_trampoline) & 1u) == 1u, 'T');
//
//	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
//}
//
///* ----------------------------------------------------------------------
// * fiber_switch_asm: context switch (save 'from', restore 'to')
// * - v6-M / v8-M Baseline path (no BASEPRI/PSPLIM/FPU)
// * - v7/v8-M Mainline with/without FPU (always-save FP context)
// * - Optional PSPLIM programming on v8-M Mainline
// * ---------------------------------------------------------------------- */
//
//#if FIBER_HAS_PSPLIM
//FIBER_ATTR_NAKED_ASM
//void fiber_switch_asm(uint32_t **from_sp_slot, uint32_t * const *to_sp_slot, uint32_t to_psplim_base)
//#else
//FIBER_ATTR_NAKED_ASM
//void fiber_switch_asm(uint32_t **from_sp_slot, uint32_t * const *to_sp_slot)
//#endif
//{
//	/* ----------------------------------------------------------------------
//	 * Inline assembly block
//	 * ---------------------------------------------------------------------- */
//	__ASM volatile(
//#if defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_8M_BASE__)
//			/* ----------------------------------------------------------------------
//			 * ARMv6-M & ARMv8-M Baseline path (M0/M0+, M23): no BASEPRI/PSPLIM/FPU
//			 * ---------------------------------------------------------------------- */
//
//			/* ===== prologue: snapshot PRIMASK and hard-mask IRQs ===== */
//			"mrs   r12, PRIMASK        \n"  /* r12 <- current PRIMASK (interrupt mask snapshot) */
//			"cpsid i                   \n"  /* globally disable IRQs (I-bit set) */
//			"dsb                       \n"  /* complete all memory accesses before continuing */
//			"isb                       \n"  /* flush pipeline to make PRIMASK/IRQ state visible */
//
//			/* ===== save PC placeholder and PRIMASK ===== */
//			"push  {lr}                \n"  /* push LR as a PC placeholder into the frame tail */
//			"sub   sp, sp, #4          \n"  /* make room for PRIMASK word */
//			"str   r12, [sp]           \n"  /* store saved PRIMASK at [SP] */
//
//			/* ===== save low regs r4..r7 ===== */
//			"push  {r4-r7}             \n"  /* push r4..r7 (callee-saved subset) */
//
//			/* ===== save high regs r8..r11 using temporaries ===== */
//			"mov   r4, r8              \n"  /* tmp r4 <- r8  */
//			"mov   r5, r9              \n"  /* tmp r5 <- r9  */
//			"mov   r6, r10             \n"  /* tmp r6 <- r10 */
//			"mov   r7, r11             \n"  /* tmp r7 <- r11 */
//			"push  {r4-r7}             \n"  /* push saved r8..r11 via r4..r7 temps */
//
//			/* ===== publish from->sp and switch SP to 'to' ===== */
//			"str   sp, [r0]            \n"  /* *from_sp_slot = current SP (top of saved frame) */
//			"ldr   r3, [r1]            \n"  /* r3 <- *to_sp_slot (target SP) */
//			"mov   sp, r3              \n"  /* SP = target SP (start of restore) */
//
//			/* ===== restore high regs r8..r11 ===== */
//			"pop   {r4-r7}             \n"  /* pop temps that hold r8..r11 values */
//			"mov   r8,  r4             \n"  /* r8  <- popped value */
//			"mov   r9,  r5             \n"  /* r9  <- popped value */
//			"mov   r10, r6             \n"  /* r10 <- popped value */
//			"mov   r11, r7             \n"  /* r11 <- popped value */
//
//			/* ===== restore low regs r4..r7 ===== */
//			"pop   {r4-r7}             \n"  /* restore r4..r7 */
//			"isb                       \n"  /* ensure restored core regs visible before tail */
//
//			/* ===== tail: restore PRIMASK and branch to PC ===== */
//			"ldr   r2, [sp]            \n"  /* r2 <- PRIMASK (saved earlier) */
//			"ldr   r3, [sp, #4]        \n"  /* r3 <- PC placeholder (tail of frame) */
//			"add   sp, #8              \n"  /* drop PRIMASK + PC words from stack */
//			"dmb                       \n"  /* order memory before re-enabling IRQs */
//			"msr   PRIMASK, r2         \n"  /* restore PRIMASK (interrupt mask level) */
//			"isb                       \n"  /* make PRIMASK change take effect immediately */
//#  if FIBER_SWITCH_STRICT_BARRIERS
//			"dsb                       \n"  /* (optional) serialize before branch */
//#  endif
//			"bx    r3                  \n"  /* branch to restored PC (does not return) */
//#else
//			/* ----------------------------------------------------------------------
//			 * ARMv7/8-M Mainline path (M3/M4/M7/M33/…): may have BASEPRI/PSPLIM/FPU
//			 * ---------------------------------------------------------------------- */
//
//			/* ===== prologue: snapshot PRIMASK/BASEPRI and hard-mask IRQs ===== */
//			"mrs   r12, PRIMASK        \n"  /* r12 <- current PRIMASK */
//			FBR_ASM_SNAP_BASEPRI           	/* r3  <- current BASEPRI (or PAD=0 if absent) */
//			"cpsid i                   \n"  /* globally disable IRQs */
//			"dsb                       \n"  /* complete all memory operations */
//			"isb                       \n"  /* sync pipeline after mask change */
//
//#  if FIBER_HAS_FPU
//			/* ----------------------------------------------------------------------
//			 * FPU path (always-save): save core regs + FPSCR + s16..s31, then tail
//			 * Header layout (12B at top of frame): [PRIMASK][(BASEPRI or PAD)][PC]
//			 * ---------------------------------------------------------------------- */
//
//			/* ===== reserve and fill 12-byte header at frame tail ===== */
//			"sub   sp, sp, #12         \n"  /* make room for header (3 words) */
//			"str   r12, [sp, #0]       \n"  /* header[0] = PRIMASK snapshot */
//			"str   r3,  [sp, #4]       \n"  /* header[1] = BASEPRI (or PAD if absent) */
//			"str   lr,  [sp, #8]       \n"  /* header[2] = PC placeholder (LR) */
//
//			/* ===== save callee-saved core registers ===== */
//			"stmdb sp!, {r4-r11}       \n"  /* push r4..r11 (descending stack) */
//
//			/* ===== save FP status and high FP regs (callee-saved) ===== */
//			"vmrs  r3, fpscr           \n"  /* r3 <- FPSCR (FP status/control) */
//			"push  {r3}                \n"  /* push FPSCR */
//			"vpush {s16-s31}           \n"  /* push s16..s31 (16 regs) */
//
//			/* ===== publish from->sp and (optionally) program PSPLIM ===== */
//			"str   sp, [r0]            \n"  /* *from_sp_slot = SP (top of full saved frame) */
//#   if FIBER_HAS_PSPLIM
//			"dsb                       \n"  /* ensure frame is fully stored before PSPLIM write */
//			"msr   psplim, r2          \n"  /* set PSPLIM to to_psplim_base (low PSP bound) */
//#   endif
//			"isb                       \n"  /* make PSPLIM/SP changes take effect before continue */
//
//			/* ===== switch to target SP ===== */
//			"ldr   r3, [r1]            \n"  /* r3 <- *to_sp_slot (target SP) */
//			"mov   sp, r3              \n"  /* SP = target SP */
//
//			/* ===== restore FP regs, FPSCR, then core regs ===== */
//			"vpop  {s16-s31}           \n"  /* restore s16..s31 */
//			"pop   {r3}                \n"  /* r3 <- FPSCR */
//			"vmsr  fpscr, r3           \n"  /* write back FPSCR */
//			"ldmia sp!, {r4-r11}       \n"  /* restore r4..r11 (ascending stack) */
//			"isb                       \n"  /* sync before tail masks */
//
//			/* ===== tail: restore masks from header and branch to PC ===== */
//			"ldr   r2, [sp, #0]        \n"  /* r2 <- PRIMASK (header[0]) */
//			"ldr   r3, [sp, #4]        \n"  /* r3 <- BASEPRI (header[1]) or PAD */
//			"ldr   r4, [sp, #8]        \n"  /* r4 <- PC (header[2]) */
//			"add   sp, #12             \n"  /* drop header */
//			"dmb                       \n"  /* order memory ops before unmasking */
//			FBR_ASM_RESTORE_BASEPRI        /* restore BASEPRI if present (no-op if absent) */
//			"msr   PRIMASK, r2         \n"  /* restore PRIMASK (global mask) */
//			"isb                       \n"  /* ensure mask changes are effective */
//#    if FIBER_SWITCH_STRICT_BARRIERS
//			"dsb                       \n"  /* (optional) serialize before branch */
//#    endif
//			"bx    r4                  \n"  /* branch to PC (does not return) */
//#  else
//			/* ----------------------------------------------------------------------
//			 * Non-FPU path: save/restore only core regs; header is 16B with ALIGN0
//			 * Header layout (16B): [PRIMASK][(BASEPRI or PAD)][ALIGN0][PC]
//			 * ---------------------------------------------------------------------- */
//
//			/* ===== reserve and fill 16-byte header (pad keeps even pop count) ===== */
//			"sub   sp, sp, #16         \n"  /* make room for 4 words: PRIMASK, BASEPRI/PAD, ALIGN0, PC */
//			"str   r12, [sp, #0]       \n"  /* header[0] = PRIMASK */
//			"str   r3,  [sp, #4]       \n"  /* header[1] = BASEPRI (or PAD=0) */
//#    if FIBER_HAS_PSPLIM
//			"mov   r12, r2             \n"  /* r12 <- to_psplim_base (preserve while using r2 as pad) */
//#    endif
//			"movs  r2,  #0             \n"  /* r2 = 0 (ALIGN0 pad to keep even word count before tramp) */
//			"str   r2,  [sp, #8]       \n"  /* header[2] = ALIGN0 (pad) */
//			"str   lr,  [sp, #12]      \n"  /* header[3] = PC placeholder (LR) */
//
//			/* ===== save callee-saved core registers ===== */
//			"stmdb sp!, {r4-r11}       \n"  /* push r4..r11 */
//
//			/* ===== publish from->sp and (optionally) program PSPLIM ===== */
//			"str   sp, [r0]            \n"  /* *from_sp_slot = SP (top of saved frame) */
//#    if FIBER_HAS_PSPLIM
//			"dsb                       \n"  /* complete stores before programming PSPLIM */
//			"msr   psplim, r12         \n"  /* PSPLIM = to_psplim_base (r12) */
//#    endif
//			"isb                       \n"  /* ensure PSPLIM/SP updates are visible */
//
//			/* ===== switch to target SP and restore core regs ===== */
//			"ldr   r2, [r1]            \n"  /* r2 <- *to_sp_slot (target SP) */
//			"mov   sp, r2              \n"  /* SP = target SP */
//			"ldmia sp!, {r4-r11}       \n"  /* restore r4..r11 */
//
//			/* ===== tail: restore masks from header and branch to PC ===== */
//			"ldr   r2, [sp, #0]        \n"  /* r2 <- PRIMASK */
//			"ldr   r3, [sp, #4]        \n"  /* r3 <- BASEPRI (or PAD) */
//			"ldr   r4, [sp, #12]       \n"  /* r4 <- PC */
//			"add   sp, #16             \n"  /* drop 16-byte header */
//			"dmb                       \n"  /* order memory before unmasking */
//			FBR_ASM_RESTORE_BASEPRI        	/* restore BASEPRI if present (no-op if absent) */
//			"msr   PRIMASK, r2         \n"  /* restore PRIMASK */
//			"isb                       \n"  /* synchronize after mask changes */
//#    if FIBER_SWITCH_STRICT_BARRIERS
//			"dsb                       \n"  /* (optional) serialize before branch */
//#    endif
//			"bx    r4                  \n"  /* branch to PC (does not return) */
//#  endif /* FIBER_HAS_FPU */
//#endif /* 6M || 8M_BASE */
//	);
//
//	/* ----------------------------------------------------------------------
//	 * Clobber list for GCC/Clang: tell compiler which regs/memory are modified
//	 * (prevents incorrect assumptions around the asm block)
//	 * ---------------------------------------------------------------------- */
//#if defined(__GNUC__) || defined(__clang__)
//	__ASM volatile("" :::           						/* empty barrier to apply clobbers below */
//			"r0","r1","r2","r3","r4","r5","r6","r7",  		/* core regs clobbered */
//			"r8","r9","r10","r11","r12","lr","cc","memory" 	/* plus flags & memory */
//#if FIBER_HAS_FPU
//			/* Map s16..s31 as D8..D15 clobbers (GCC/Clang FP aliasing) */
//			,"d8","d9","d10","d11","d12","d13","d14","d15"
//#endif
//	);
//#endif
//}
//
//
//
//
//
///* Прототип низькорівневої ASM-функції свічу (є в fiber_core.c) */
//
//
//
//FIBER_ATTR_SENSITIVE
//void fiber_switch(FiberContext *from, FiberContext *to)
//{
//#if FIBER_HAS_PSPLIM
//    fiber_switch_asm(&from->sp, (uint32_t * const *)&to->sp, (uint32_t)to->boot.stack_base);
//#else
//    fiber_switch_asm(&from->sp, (uint32_t * const *)&to->sp);
//#endif
//}
//
//
//
