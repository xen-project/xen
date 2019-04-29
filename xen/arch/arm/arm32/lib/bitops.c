/*
 * Copyright (C) 2018 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/bitops.h>
#include <xen/prefetch.h>
#include <asm/system.h>

/*
 * The atomic bit operations pass the number of bit in a signed number
 * (not sure why). This has the drawback to increase the complexity of
 * the resulting assembly.
 *
 * To generate simpler code, the number of bit (nr) will be cast to
 * unsigned int.
 *
 * XXX: Rework the interface to use unsigned int.
 */

#define bitop(name, instr)                                                  \
static always_inline bool int_##name(int nr, volatile void *p, bool timeout,\
                                     unsigned int max_try)                  \
{                                                                           \
    volatile uint32_t *ptr = (uint32_t *)p + BIT_WORD((unsigned int)nr);    \
    const uint32_t mask = BIT_MASK((unsigned int)nr);                       \
    unsigned long res, tmp;                                                 \
                                                                            \
    ASSERT(((vaddr_t)p & 0x3) == 0);                                        \
    prefetchw((const void *)ptr);                                           \
                                                                            \
    do                                                                      \
    {                                                                       \
        asm volatile ("// " __stringify(name) "\n"                          \
        "   ldrex   %2, %1\n"                                               \
        "   " __stringify(instr) "     %2, %2, %3\n"                        \
        "   strex   %0, %2, %1\n"                                           \
        : "=&r" (res), "+Qo" (*ptr), "=&r" (tmp)                            \
        : "r" (mask));                                                      \
                                                                            \
        if ( !res )                                                         \
            break;                                                          \
    } while ( !timeout || ((--max_try) > 0) );                              \
                                                                            \
    return !res;                                                            \
}                                                                           \
                                                                            \
void name(int nr, volatile void *p)                                         \
{                                                                           \
    if ( !int_##name(nr, p, false, 0) )                                     \
        ASSERT_UNREACHABLE();                                               \
}                                                                           \
                                                                            \
bool name##_timeout(int nr, volatile void *p, unsigned int max_try)         \
{                                                                           \
    return int_##name(nr, p, true, max_try);                                \
}

#define testop(name, instr)                                                 \
static always_inline bool int_##name(int nr, volatile void *p, int *oldbit, \
                                     bool timeout, unsigned int max_try)    \
{                                                                           \
    volatile uint32_t *ptr = (uint32_t *)p + BIT_WORD((unsigned int)nr);    \
    unsigned int bit = (unsigned int)nr % BITS_PER_WORD;                    \
    const uint32_t mask = BIT_MASK(bit);                                    \
    unsigned long res, tmp;                                                 \
                                                                            \
    ASSERT(((vaddr_t)p & 0x3) == 0);                                        \
    smp_mb();                                                               \
                                                                            \
    prefetchw((const void *)ptr);                                           \
                                                                            \
    do                                                                      \
    {                                                                       \
        asm volatile ("// " __stringify(name) "\n"                          \
        "   ldrex   %3, %2\n"                                               \
        "   lsr     %1, %3, %5 // Save old value of bit\n"                  \
        "   " __stringify(instr) "  %3, %3, %4 // Toggle bit\n"             \
        "   strex  %0, %3, %2\n"                                            \
        : "=&r" (res), "=&r" (*oldbit), "+Qo" (*ptr), "=&r" (tmp)           \
        : "r" (mask), "r" (bit));                                           \
                                                                            \
        if ( !res )                                                         \
            break;                                                          \
    } while ( !timeout || ((--max_try) > 0) );                              \
                                                                            \
    smp_mb();                                                               \
                                                                            \
    *oldbit &= 1;                                                           \
                                                                            \
    return !res;                                                            \
}                                                                           \
                                                                            \
int name(int nr, volatile void *p)                                          \
{                                                                           \
    int oldbit;                                                             \
                                                                            \
    if ( !int_##name(nr, p, &oldbit, false, 0) )                            \
        ASSERT_UNREACHABLE();                                               \
                                                                            \
    return oldbit;                                                          \
}                                                                           \
                                                                            \
bool name##_timeout(int nr, volatile void *p,                               \
                    int *oldbit, unsigned int max_try)                      \
{                                                                           \
    return int_##name(nr, p, oldbit, true, max_try);                        \
}

bitop(change_bit, eor)
bitop(clear_bit, bic)
bitop(set_bit, orr)

testop(test_and_change_bit, eor)
testop(test_and_clear_bit, bic)
testop(test_and_set_bit, orr)

static always_inline bool int_clear_mask16(uint16_t mask, volatile uint16_t *p,
                                           bool timeout, unsigned int max_try)
{
    unsigned long res, tmp;

    prefetchw((const uint16_t *)p);

    do
    {
        asm volatile ("// int_clear_mask16\n"
        "   ldrexh  %2, %1\n"
        "   bic     %2, %2, %3\n"
        "   strexh  %0, %2, %1\n"
        : "=&r" (res), "+Qo" (*p), "=&r" (tmp)
        : "r" (mask));

        if ( !res )
            break;
    } while ( !timeout || ((--max_try) > 0) );

    return !res;
}

void clear_mask16(uint16_t mask, volatile void *p)
{
    if ( !int_clear_mask16(mask, p, false, 0) )
        ASSERT_UNREACHABLE();
}

bool clear_mask16_timeout(uint16_t mask, volatile void *p,
                          unsigned int max_try)
{
    return int_clear_mask16(mask, p, true, max_try);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
