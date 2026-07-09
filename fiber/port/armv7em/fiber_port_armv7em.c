/*
 * fiber_port_armv7em.c
 *
 * ARMv7E-M port shell.
 *
 * This file is intentionally behavior-neutral for now. The validated
 * STM32H7/Cortex-M7 PendSV implementation still lives in fiber_core.c.
 * The next mechanical step is to move that implementation here without
 * changing save/restore behavior.
 */

#include "../fiber_port.h"

#if FIBER_PORT_ARMV7EM

/*
 * Reserved for the ARMv7E-M implementation.
 *
 * Do not add semantic scheduler policy here. The common runtime owns switch
 * validation, current-context ownership, and publication ordering. This port
 * file will own only CPU-specific start, save/restore, and exception-return
 * details.
 */

#endif /* FIBER_PORT_ARMV7EM */
