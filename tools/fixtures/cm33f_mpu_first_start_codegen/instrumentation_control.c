/* Unprotected control: the same hostile options must genuinely take effect. */
volatile unsigned codegen_instrumentation_sink;
__attribute__((noinline)) void codegen_instrumentation_control(int index, int divisor)
{
    volatile char bytes[32];
    bytes[index] = (char)(index / divisor);
    codegen_instrumentation_sink += (unsigned)bytes[index];
}
