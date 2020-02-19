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
    volatile uint32_t *ptr = (uint32_t *)p + BITOP_WORD((unsigned int)nr);  \
    const uint32_t mask = BITOP_MASK((unsigned int)nr);                     \
    unsigned long res, tmp;                                                 \
                                                                            \
    do                                                                      \
    {                                                                       \
        asm volatile ("// " __stringify(name) "\n"                          \
        "   ldxr    %w2, %1\n"                                              \
        "   " __stringify(instr) "     %w2, %w2, %w3\n"                     \
        "   stxr    %w0, %w2, %1\n"                                         \
        : "=&r" (res), "+Q" (*ptr), "=&r" (tmp)                             \
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
    volatile uint32_t *ptr = (uint32_t *)p + BITOP_WORD((unsigned int)nr);  \
    unsigned int bit = (unsigned int)nr % BITOP_BITS_PER_WORD;              \
    const uint32_t mask = BITOP_MASK(bit);                                  \
    unsigned long res, tmp;                                                 \
                                                                            \
    do                                                                      \
    {                                                                       \
        asm volatile ("// " __stringify(name) "\n"                          \
        "   ldxr    %w3, %2\n"                                              \
        "   lsr     %w1, %w3, %w5 // Save old value of bit\n"               \
        "   " __stringify(instr) "  %w3, %w3, %w4 // Toggle bit\n"          \
        "   stlxr   %w0, %w3, %2\n"                                         \
        : "=&r" (res), "=&r" (*oldbit), "+Q" (*ptr), "=&r" (tmp)            \
        : "r" (mask), "r" (bit)                                             \
        : "memory");                                                        \
                                                                            \
        if ( !res )                                                         \
            break;                                                          \
    } while ( !timeout || ((--max_try) > 0) );                              \
                                                                            \
    dmb(ish);                                                               \
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

    do
    {
        asm volatile ("//  int_clear_mask16\n"
        "   ldxrh   %w2, %1\n"
        "   bic     %w2, %w2, %w3\n"
        "   stxrh   %w0, %w2, %1\n"
        : "=&r" (res), "+Q" (*p), "=&r" (tmp)
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
