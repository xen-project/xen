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
void name(int nr, volatile void *p)                                         \
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
    } while ( res );                                                        \
}

#define testop(name, instr)                                                 \
int name(int nr, volatile void *p)                                          \
{                                                                           \
    volatile uint32_t *ptr = (uint32_t *)p + BIT_WORD((unsigned int)nr);    \
    unsigned int bit = (unsigned int)nr % BITS_PER_WORD;                    \
    const uint32_t mask = BIT_MASK(bit);                                    \
    unsigned long res, tmp;                                                 \
    int oldbit;                                                             \
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
        : "=&r" (res), "=&r" (oldbit), "+Qo" (*ptr), "=&r" (tmp)            \
        : "r" (mask), "r" (bit));                                           \
    } while ( res );                                                        \
                                                                            \
    smp_mb();                                                               \
                                                                            \
    return oldbit & 1;                                                      \
}                                                                           \

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
