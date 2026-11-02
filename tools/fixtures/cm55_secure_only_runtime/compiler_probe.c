/* Deliberately unannotated: each raw compiler family must visibly affect this
 * control. Never linked into the executing runtime image. */
__attribute__((used,noinline))
int fixture_compiler_probe(volatile int *source,int n)
{
    volatile int local[8];
    for(int i=0;i<8;++i)local[i]=source[i]+n;
    return local[n&7]/(n+1);
}
