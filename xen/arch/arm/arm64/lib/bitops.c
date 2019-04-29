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
void name(int nr, volatile void *p)                                         \
{                                                                           \
    volatile uint32_t *ptr = (uint32_t *)p + BIT_WORD((unsigned int)nr);    \
    const uint32_t mask = BIT_MASK((unsigned int)nr);                       \
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
    } while ( res );                                                        \
}                                                                           \

#define testop(name, instr)                                                 \
int name(int nr, volatile void *p)                                          \
{                                                                           \
    volatile uint32_t *ptr = (uint32_t *)p + BIT_WORD((unsigned int)nr);    \
    unsigned int bit = (unsigned int)nr % BITS_PER_WORD;                    \
    const uint32_t mask = BIT_MASK(bit);                                    \
    unsigned long res, tmp;                                                 \
    unsigned long oldbit;                                                   \
                                                                            \
    do                                                                      \
    {                                                                       \
        asm volatile ("// " __stringify(name) "\n"                          \
        "   ldxr    %w3, %2\n"                                              \
        "   lsr     %w1, %w3, %w5 // Save old value of bit\n"               \
        "   " __stringify(instr) "  %w3, %w3, %w4 // Toggle bit\n"          \
        "   stlxr   %w0, %w3, %2\n"                                         \
        : "=&r" (res), "=&r" (oldbit), "+Q" (*ptr), "=&r" (tmp)             \
        : "r" (mask), "r" (bit)                                             \
        : "memory");                                                        \
    } while ( res );                                                        \
                                                                            \
    dmb(ish);                                                               \
                                                                            \
    return oldbit & 1;                                                      \
}

bitop(change_bit, eor)
bitop(clear_bit, bic)
bitop(set_bit, orr)

testop(test_and_change_bit, eor)
testop(test_and_clear_bit, bic)
testop(test_and_set_bit, orr)

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
