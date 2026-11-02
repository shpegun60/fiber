#if DUPLICATE_SVC
void SVC_Handler(void) {}
#else
void PendSV_Handler(void) {}
#endif
