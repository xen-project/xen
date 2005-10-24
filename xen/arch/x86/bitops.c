
#include <xen/bitops.h>
#include <xen/lib.h>

unsigned int __find_first_bit(
    const unsigned long *addr, unsigned int size)
{
    unsigned long d0, d1, res;

    __asm__ __volatile__ (
        "   xor %%eax,%%eax\n\t" /* also ensures ZF==1 if size==0 */
        "   repe; scas"__OS"\n\t"
        "   je 1f\n\t"
        "   lea -"STR(BITS_PER_LONG/8)"(%2),%2\n\t"
        "   bsf (%2),%0\n"
        "1: sub %%ebx,%%edi\n\t"
        "   shl $3,%%edi\n\t"
        "   add %%edi,%%eax"
        : "=&a" (res), "=&c" (d0), "=&D" (d1)
        : "1" ((size + BITS_PER_LONG - 1) / BITS_PER_LONG),
          "2" (addr), "b" ((int)(long)addr) : "memory" );

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
        __asm__ ( "bsf %1,%%"__OP"ax"
                  : "=a" (set) : "r" (*p >> bit), "0" (BITS_PER_LONG) );
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

    __asm__ (
        "   xor %%edx,%%edx\n\t" /* also ensures ZF==1 if size==0 */
        "   repe; scas"__OS"\n\t"
        "   je 1f\n\t"
        "   lea -"STR(BITS_PER_LONG/8)"(%2),%2\n\t"
        "   xor (%2),%3\n\t"
        "   bsf %3,%0\n"
        "1: sub %%ebx,%%edi\n\t"
        "   shl $3,%%edi\n\t"
        "   add %%edi,%%edx"
        : "=&d" (res), "=&c" (d0), "=&D" (d1), "=&a" (d2)
        : "1" ((size + BITS_PER_LONG - 1) / BITS_PER_LONG),
          "2" (addr), "b" ((int)(long)addr), "3" (-1L) : "memory" );

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
        __asm__ ( "bsf %1,%%"__OP"ax" : "=a" (set) : "r" (~(*p >> bit)) );
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
