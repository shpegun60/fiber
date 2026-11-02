#ifndef CM33F_FIRST_START_REFERENCE_CONFIG_H
#define CM33F_FIRST_START_REFERENCE_CONFIG_H
#include "../../freertos_asm_parity/FreeRTOSConfig.h"
void codegen_reference_task_return(void);
#define configTASK_RETURN_ADDRESS codegen_reference_task_return
#endif
