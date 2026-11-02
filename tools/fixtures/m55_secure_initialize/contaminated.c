/* Detector control only: no canonical attributes, never linked or executed. */
__attribute__((noinline, used)) int init_fixture_contaminated(int *pointer, int index)
{
    volatile char buffer[16];
    buffer[(unsigned)index & 15u] = (char)index;
    return pointer[index] + buffer[(unsigned)index & 15u] + index * index;
}
