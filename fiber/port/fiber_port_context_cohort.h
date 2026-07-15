/*
 * fiber_port_context_cohort.h
 *
 * Link-time identity for one exact selected-port context cohort. One
 * always-linked mandatory port object defines the generated symbol. Every
 * other mandatory object retains a relocation to that exact spelling.
 */

#ifndef FIBER_PORT_FIBER_PORT_CONTEXT_COHORT_H_
#define FIBER_PORT_FIBER_PORT_CONTEXT_COHORT_H_

#include "fiber_compiler.h"
#include "fiber_port_select.h"

#if FIBER_PORT_ARMV6M
# define FIBER_PORT_CONTEXT_COHORT_PROFILE armv6m
#elif FIBER_PORT_ARMV7M
# define FIBER_PORT_CONTEXT_COHORT_PROFILE armv7m
#elif FIBER_PORT_ARMV7EM
# define FIBER_PORT_CONTEXT_COHORT_PROFILE armv7em
#elif FIBER_PORT_ARMV8M_BASELINE
# define FIBER_PORT_CONTEXT_COHORT_PROFILE armv8m_baseline
#elif FIBER_PORT_ARMV8M_MAINLINE
# define FIBER_PORT_CONTEXT_COHORT_PROFILE armv8m_mainline
#elif FIBER_PORT_ARMV81M_MAINLINE
# define FIBER_PORT_CONTEXT_COHORT_PROFILE armv81m_mainline
#else
# error "[fiber]: exact context cohort requires one selected port profile"
#endif

#ifndef FIBER_PORT_CONTEXT_ABI_PORT_ID
# error "[fiber]: exact context cohort requires FIBER_PORT_CONTEXT_ABI_PORT_ID"
#endif
#ifndef FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION
# error "[fiber]: exact context cohort requires FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION"
#endif
#ifndef FIBER_PORT_HAS_FPU
# error "[fiber]: exact context cohort requires FIBER_PORT_HAS_FPU"
#endif
#ifndef FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
# error "[fiber]: exact context cohort requires FIBER_PORT_HAS_EXTENDED_FP_CONTEXT"
#endif
#ifndef FIBER_PORT_HAS_BASEPRI
# error "[fiber]: exact context cohort requires FIBER_PORT_HAS_BASEPRI"
#endif
#ifndef FIBER_PORT_HAS_FAULTMASK
# error "[fiber]: exact context cohort requires FIBER_PORT_HAS_FAULTMASK"
#endif
#ifndef FIBER_PORT_HAS_VTOR
# error "[fiber]: exact context cohort requires FIBER_PORT_HAS_VTOR"
#endif
#ifndef FIBER_PORT_HAS_PSPLIM
# error "[fiber]: exact context cohort requires FIBER_PORT_HAS_PSPLIM"
#endif
#ifndef FIBER_PORT_USES_PSPLIM_REGISTER
# error "[fiber]: exact context cohort requires FIBER_PORT_USES_PSPLIM_REGISTER"
#endif
#ifndef FIBER_PORT_STACK_ALIGNMENT
# error "[fiber]: exact context cohort requires FIBER_PORT_STACK_ALIGNMENT"
#endif
#ifndef FIBER_PORT_BOOT_CLEARS_FPCA
# error "[fiber]: exact context cohort requires FIBER_PORT_BOOT_CLEARS_FPCA"
#endif
#ifndef FIBER_PORT_SCHEDULER_MASK_KIND
# error "[fiber]: exact context cohort requires FIBER_PORT_SCHEDULER_MASK_KIND"
#endif
#ifndef FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND
# error "[fiber]: exact context cohort requires the M7 errata policy"
#endif
#ifndef FIBER_PORT_INITIAL_EXC_RETURN
# error "[fiber]: exact context cohort requires FIBER_PORT_INITIAL_EXC_RETURN"
#endif
#ifndef FIBER_PORT_HAS_CONTROL_SLOT
# error "[fiber]: exact context cohort requires FIBER_PORT_HAS_CONTROL_SLOT"
#endif
#ifndef FIBER_PORT_HAS_PSPLIM_SLOT
# error "[fiber]: exact context cohort requires FIBER_PORT_HAS_PSPLIM_SLOT"
#endif
#ifndef FIBER_PORT_HAS_SECURE_CONTEXT_SLOT
# error "[fiber]: exact context cohort requires FIBER_PORT_HAS_SECURE_CONTEXT_SLOT"
#endif
#ifndef FIBER_PORT_HAS_MVE
# error "[fiber]: exact context cohort requires FIBER_PORT_HAS_MVE"
#endif
#ifndef FIBER_PORT_HAS_PAC
# error "[fiber]: exact context cohort requires FIBER_PORT_HAS_PAC"
#endif
#ifndef FIBER_PORT_HAS_BTI
# error "[fiber]: exact context cohort requires FIBER_PORT_HAS_BTI"
#endif
#ifndef FIBER_PORT_HAS_SECURITY_EXT
# error "[fiber]: exact context cohort requires FIBER_PORT_HAS_SECURITY_EXT"
#endif
#ifndef FIBER_PORT_RUNS_NONSECURE
# error "[fiber]: exact context cohort requires FIBER_PORT_RUNS_NONSECURE"
#endif
#ifndef FIBER_PORT_TARGETS_NS_BANK
# error "[fiber]: exact context cohort requires FIBER_PORT_TARGETS_NS_BANK"
#endif
#ifndef FIBER_PORT_HAS_PAC_KEY_SLOT
# error "[fiber]: exact context cohort requires FIBER_PORT_HAS_PAC_KEY_SLOT"
#endif

#define FIBER_PORT_CONTEXT_COHORT_SYMBOL_I( \
		profile, port_id, layout, fpu, ext_fp, basepri, faultmask, vtor, \
		psplim, psplim_reg, stack_align, boot_fpca, scheduler_mask, \
		m7_errata, exc_return, control_slot, psplim_slot, secure_slot, \
		mve, pac, bti, security_ext, runs_ns, targets_ns, pac_key_slot) \
	fiber_port_context_cohort_##profile##_p##port_id##_l##layout##_f##fpu \
	##_e##ext_fp##_h##basepri##_j##faultmask##_v##vtor##_d##psplim \
	##_r##psplim_reg##_z##stack_align##_y##boot_fpca##_w##scheduler_mask \
	##_i##m7_errata##_o##exc_return##_c##control_slot##_s##psplim_slot \
	##_x##secure_slot##_m##mve##_a##pac##_b##bti##_t##security_ext \
	##_n##runs_ns##_k##targets_ns##_q##pac_key_slot

#define FIBER_PORT_CONTEXT_COHORT_SYMBOL_EXPAND( \
		profile, port_id, layout, fpu, ext_fp, basepri, faultmask, vtor, \
		psplim, psplim_reg, stack_align, boot_fpca, scheduler_mask, \
		m7_errata, exc_return, control_slot, psplim_slot, secure_slot, \
		mve, pac, bti, security_ext, runs_ns, targets_ns, pac_key_slot) \
	FIBER_PORT_CONTEXT_COHORT_SYMBOL_I(profile, port_id, layout, fpu, \
		ext_fp, basepri, faultmask, vtor, psplim, psplim_reg, stack_align, \
		boot_fpca, scheduler_mask, m7_errata, exc_return, control_slot, \
		psplim_slot, secure_slot, mve, pac, bti, security_ext, runs_ns, \
		targets_ns, pac_key_slot)

#define FIBER_PORT_CONTEXT_COHORT_SYMBOL \
	FIBER_PORT_CONTEXT_COHORT_SYMBOL_EXPAND( \
		FIBER_PORT_CONTEXT_COHORT_PROFILE, \
		FIBER_PORT_CONTEXT_ABI_PORT_ID, \
		FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION, \
		FIBER_PORT_HAS_FPU, \
		FIBER_PORT_HAS_EXTENDED_FP_CONTEXT, \
		FIBER_PORT_HAS_BASEPRI, \
		FIBER_PORT_HAS_FAULTMASK, \
		FIBER_PORT_HAS_VTOR, \
		FIBER_PORT_HAS_PSPLIM, \
		FIBER_PORT_USES_PSPLIM_REGISTER, \
		FIBER_PORT_STACK_ALIGNMENT, \
		FIBER_PORT_BOOT_CLEARS_FPCA, \
		FIBER_PORT_SCHEDULER_MASK_KIND, \
		FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND, \
		FIBER_PORT_INITIAL_EXC_RETURN, \
		FIBER_PORT_HAS_CONTROL_SLOT, \
		FIBER_PORT_HAS_PSPLIM_SLOT, \
		FIBER_PORT_HAS_SECURE_CONTEXT_SLOT, \
		FIBER_PORT_HAS_MVE, \
		FIBER_PORT_HAS_PAC, \
		FIBER_PORT_HAS_BTI, \
		FIBER_PORT_HAS_SECURITY_EXT, \
		FIBER_PORT_RUNS_NONSECURE, \
		FIBER_PORT_TARGETS_NS_BANK, \
		FIBER_PORT_HAS_PAC_KEY_SLOT)

#ifdef __cplusplus
extern "C" {
#endif

extern const unsigned char FIBER_PORT_CONTEXT_COHORT_SYMBOL;

#ifdef __cplusplus
} /* extern "C" */
#endif

#define FIBER_PORT_CONTEXT_COHORT_DEFINE() \
	FIBER_USED const unsigned char FIBER_PORT_CONTEXT_COHORT_SYMBOL = 1u

/* A volatile one-byte read preserves a real relocation under optimization and
 * LTO. Calls belong only to one-shot init/start paths, never PendSV. */
#define FIBER_PORT_CONTEXT_COHORT_RETAIN() \
	((void)*(volatile const unsigned char *) \
			&FIBER_PORT_CONTEXT_COHORT_SYMBOL)

#endif /* FIBER_PORT_FIBER_PORT_CONTEXT_COHORT_H_ */
