#ifndef CM33F_CONSTRUCTOR_REFERENCE_CONFIG_H
#define CM33F_CONSTRUCTOR_REFERENCE_CONFIG_H

#include "../../freertos_asm_parity/FreeRTOSConfig.h"
/* Avoid retaining kernel task-exit/scheduler dependencies solely for the
 * synthetic task LR. The actual pinned constructor remains unmodified. */
void constructor_reference_return(void);
#define configTASK_RETURN_ADDRESS constructor_reference_return

#endif
