/*
 * Build-owned exact selected-port expectation.
 *
 * Compile this source through the selected port's private include directory
 * and link it outside any precompiled selected-port archive. The linker script
 * must KEEP(.fiber_port_context_cohort_expectation). Its relocation then makes
 * a complete archive from a different exact cohort fail like any mixed stale
 * private-object set.
 */

#include "fiber_port_private.h"

static const unsigned char *const
fiber_port_context_cohort_build_expectation FIBER_USED
		__attribute__((section(".fiber_port_context_cohort_expectation"))) =
		&FIBER_PORT_CONTEXT_COHORT_SYMBOL;
