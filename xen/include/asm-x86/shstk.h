/******************************************************************************
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2022 Citrix Systems Ltd.
 */
#ifndef XEN_ASM_SHSTK_H
#define XEN_ASM_SHSTK_H

/*
 * RDSSP is a nop when shadow stacks are inactive.  Also, SSP has a minimum
 * alignment of 4 which is enforced by hardware.
 *
 * We load 1 into a register, then RDSSP.  If shadow stacks are not enabled,
 * RDSSP is a nop, and the 1 is preserved.  Otherwise, the 1 is clobbered with
 * the real SSP, which has the bottom two bits clear.
 */
#define SSP_NO_SHSTK 1

static inline unsigned long rdssp(void)
{
    unsigned long ssp;

    asm volatile ( "rdsspq %0" : "=r" (ssp) : "0" (SSP_NO_SHSTK) );

    return ssp;
}

static inline void wrss(unsigned long val, unsigned long *ptr)
{
    asm ( "wrssq %[val], %[ptr]"
          : [ptr] "=m" (*ptr)
          : [val] "r" (val) );
}

#endif /* XEN_ASM_SHSTK_H */
