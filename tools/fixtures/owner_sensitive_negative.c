/* Intentionally outside the sensitive contract: detector positive control. */
volatile unsigned fiber_owner_negative_words[32];

unsigned fiber_owner_unannotated(unsigned index)
{
    volatile unsigned char scratch[16];
    scratch[0] = (unsigned char)index;
    return fiber_owner_negative_words[index] + scratch[0];
}
