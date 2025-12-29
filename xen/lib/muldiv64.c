#include <xen/muldiv64.h>

uint64_t generic_muldiv64(uint64_t a, uint32_t b, uint32_t c)
{
#ifdef CONFIG_X86
    asm ( "mulq %1; divq %2" : "+a" (a)
                             : "rm" ((uint64_t)b), "rm" ((uint64_t)c)
                             : "rdx" );

    return a;
#else
    union {
        uint64_t ll;
        struct {
#if defined(__BIG_ENDIAN)
            uint32_t high, low;
#elif defined(__LITTLE_ENDIAN)
            uint32_t low, high;
#else
# error Unknown Endianness
#endif
        } l;
    } u, res;
    uint64_t rl, rh;

    u.ll = a;
    rl = (uint64_t)u.l.low * (uint64_t)b;
    rh = (uint64_t)u.l.high * (uint64_t)b;
    rh += (rl >> 32);
    res.l.high = rh / c;
    res.l.low = (((rh % c) << 32) + (uint32_t)rl) / c;

    return res.ll;
#endif
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
