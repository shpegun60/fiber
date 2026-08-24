/* ARM_CM33_NTZ exact non-MPU initial context frame. */

#include "fiber_port_private.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

enum FiberPortInitialFrameWord {
	fiber_portFRAME_PSPLIM = 0,
	fiber_portFRAME_EXC_RETURN = 1,
	fiber_portFRAME_R4 = 2,
	fiber_portFRAME_R5 = 3,
	fiber_portFRAME_R6 = 4,
	fiber_portFRAME_R7 = 5,
	fiber_portFRAME_R8 = 6,
	fiber_portFRAME_R9 = 7,
	fiber_portFRAME_R10 = 8,
	fiber_portFRAME_R11 = 9,
	fiber_portFRAME_R0 = 10,
	fiber_portFRAME_R1 = 11,
	fiber_portFRAME_R2 = 12,
	fiber_portFRAME_R3 = 13,
	fiber_portFRAME_R12 = 14,
	fiber_portFRAME_LR = 15,
	fiber_portFRAME_PC = 16,
	fiber_portFRAME_XPSR = 17,
	fiber_portFRAME_WORD_COUNT = 18
};

FIBER_STATIC_ASSERT(fiber_portFRAME_EXC_RETURN ==
		FIBER_PORT_EXC_RETURN_WORD_INDEX,
		"[fiber]: ARM_CM33_NTZ EXC_RETURN offset changed");
FIBER_STATIC_ASSERT(fiber_portFRAME_R0 == FIBER_PORT_SOFTWARE_FRAME_WORDS,
		"[fiber]: ARM_CM33_NTZ hardware frame offset changed");
FIBER_STATIC_ASSERT(fiber_portFRAME_WORD_COUNT * sizeof(uint32_t) ==
		FIBER_PORT_INITIAL_CONTEXT_BYTES,
		"[fiber]: ARM_CM33_NTZ initial frame size changed");

void fiber_port_init_context_frame(FiberContext *const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	fiber_port_boot_record_check(&ctx->boot);

	uint32_t *const frame = (uint32_t *)ctx->boot.stack_top -
			fiber_portFRAME_WORD_COUNT;

	/* This is the exact non-MPU Mainline frame seeded by FreeRTOS. PendSV will
	 * later replace word 0 with the live PSPLIM value before saving r4-r11. */
	frame[fiber_portFRAME_PSPLIM] = (uint32_t)ctx->boot.stack_base;
	frame[fiber_portFRAME_EXC_RETURN] = fiber_portINITIAL_EXC_RETURN;
	frame[fiber_portFRAME_R4] = 0u;
	frame[fiber_portFRAME_R5] = 0u;
	frame[fiber_portFRAME_R6] = 0u;
	frame[fiber_portFRAME_R7] = 0u;
	frame[fiber_portFRAME_R8] = 0u;
	frame[fiber_portFRAME_R9] = fiber_port_read_r9();
	frame[fiber_portFRAME_R10] = 0u;
	frame[fiber_portFRAME_R11] = 0u;
	frame[fiber_portFRAME_R0] = (uint32_t)(uintptr_t)ctx->boot.arg;
	frame[fiber_portFRAME_R1] = 0u;
	frame[fiber_portFRAME_R2] = 0u;
	frame[fiber_portFRAME_R3] = 0u;
	frame[fiber_portFRAME_R12] = 0u;
	frame[fiber_portFRAME_LR] =
			((uint32_t)(uintptr_t)&fiber_internal_task_return) | 1u;
	frame[fiber_portFRAME_PC] =
			fiber_port_stacked_pc((uintptr_t)ctx->boot.entry);
	frame[fiber_portFRAME_XPSR] = fiber_port_initial_xpsr();

	ctx->sp = frame;
	{
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
	}
}
