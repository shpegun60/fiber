#ifdef DUPLICATE_PENDSV
void PendSV_Handler(void) { __asm volatile ("udf #3"); }
#else
void SVC_Handler(void) { __asm volatile ("udf #3"); }
#endif
