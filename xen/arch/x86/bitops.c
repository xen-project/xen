
#include <xen/bitops.h>
#include <xen/lib.h>

unsigned int __find_first_bit(
    const unsigned long *addr, unsigned int size)
{
    unsigned long d0, d1, res;

    asm volatile (
        "1: xor %%eax,%%eax\n\t" /* also ensures ZF==1 if size==0 */
        "   repe; scas"__OS"\n\t"
        "   je 2f\n\t"
        "   bsf -"STR(BITS_PER_LONG/8)"(%2),%0\n\t"
        "   jz 1b\n\t"
        "   lea -"STR(BITS_PER_LONG/8)"(%2),%2\n\t"
        "2: sub %%ebx,%%edi\n\t"
        "   shl $3,%%edi\n\t"
        "   add %%edi,%%eax"
        : "=&a" (res), "=&c" (d0), "=&D" (d1)
        : "1" (BITS_TO_LONGS(size)), "2" (addr), "b" ((int)(long)addr)
        : "memory" );

    return res;
}

unsigned int __find_next_bit(
    const unsigned long *addr, unsigned int size, unsigned int offset)
{
    const unsigned long *p = addr + (offset / BITS_PER_LONG);
    unsigned int set, bit = offset & (BITS_PER_LONG - 1);

    ASSERT(offset <= size);

    if ( bit != 0 )
    {
        /* Look for a bit in the first word. */
        set = __scanbit(*p >> bit, BITS_PER_LONG - bit);
        if ( set < (BITS_PER_LONG - bit) )
            return (offset + set);
        offset += BITS_PER_LONG - bit;
        p++;
    }

    if ( offset >= size )
        return size;

    /* Search remaining full words for a bit. */
    set = __find_first_bit(p, size - offset);
    return (offset + set);
}

unsigned int __find_first_zero_bit(
    const unsigned long *addr, unsigned int size)
{
    unsigned long d0, d1, d2, res;

    asm volatile (
        "1: xor %%eax,%%eax ; not %3\n\t" /* rAX == ~0ul */
        "   xor %%edx,%%edx\n\t" /* also ensures ZF==1 if size==0 */
        "   repe; scas"__OS"\n\t"
        "   je 2f\n\t"
        "   xor -"STR(BITS_PER_LONG/8)"(%2),%3\n\t"
        "   jz 1b\n\t"
        "   bsf %3,%0\n\t"
        "   lea -"STR(BITS_PER_LONG/8)"(%2),%2\n\t"
        "2: sub %%ebx,%%edi\n\t"
        "   shl $3,%%edi\n\t"
        "   add %%edi,%%edx"
        : "=&d" (res), "=&c" (d0), "=&D" (d1), "=&a" (d2)
        : "1" (BITS_TO_LONGS(size)), "2" (addr), "b" ((int)(long)addr)
        : "memory" );

    return res;
}

unsigned int __find_next_zero_bit(
    const unsigned long *addr, unsigned int size, unsigned int offset)
{
    const unsigned long *p = addr + (offset / BITS_PER_LONG);
    unsigned int set, bit = offset & (BITS_PER_LONG - 1);

    ASSERT(offset <= size);

    if ( bit != 0 )
    {
        /* Look for zero in the first word. */
        set = __scanbit(~(*p >> bit), BITS_PER_LONG - bit);
        if ( set < (BITS_PER_LONG - bit) )
            return (offset + set);
        offset += BITS_PER_LONG - bit;
        p++;
    }

    if ( offset >= size )
        return size;

    /* Search remaining full words for a zero. */
    set = __find_first_zero_bit(p, size - offset);
    return (offset + set);
}
