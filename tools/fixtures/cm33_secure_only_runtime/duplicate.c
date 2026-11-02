#if DUPLICATE_SVC
void SVC_Handler(void) {__asm__ volatile("nop");}
#else
void PendSV_Handler(void) {__asm__ volatile("nop");}
#endif
