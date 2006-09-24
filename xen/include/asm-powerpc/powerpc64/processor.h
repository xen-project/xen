/*
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
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ASM_64_PROCESSOR_H_
#define _ASM_64_PROCESSOR_H_

#ifdef __ASSEMBLY__

#define LOADADDR(rn,name)           \
    lis     rn,name##@highest;      \
    ori     rn,rn,name##@higher;    \
    rldicr  rn,rn,32,31;            \
    oris    rn,rn,name##@h;         \
    ori     rn,rn,name##@l

#define SET_REG_TO_CONST(reg, value)                \
    lis     reg,(((value)>>48)&0xFFFF);             \
    ori     reg,reg,(((value)>>32)&0xFFFF);         \
    rldicr  reg,reg,32,31;                          \
    oris    reg,reg,(((value)>>16)&0xFFFF);         \
    ori     reg,reg,((value)&0xFFFF);

#define SET_REG_TO_LABEL(reg, label)                \
    lis     reg,(label)@highest;                    \
    ori     reg,reg,(label)@higher;                 \
    rldicr  reg,reg,32,31;                          \
    oris    reg,reg,(label)@h;                      \
    ori     reg,reg,(label)@l;

#define XGLUE(a,b) a##b
#define GLUE(a,b) XGLUE(a,b)

#define _GLOBAL(name) \
    .section ".text"; \
    .align 2 ; \
    .globl name; \
    .globl GLUE(.,name); \
    .section ".opd","aw"; \
name: \
    .quad GLUE(.,name); \
    .quad .TOC.@tocbase; \
    .quad 0; \
    .previous; \
    .type GLUE(.,name),@function; \
GLUE(.,name):

#define _STATIC(name) \
    .section ".text"; \
    .align 2 ; \
    .section ".opd","aw"; \
name: \
    .quad GLUE(.,name); \
    .quad .TOC.@tocbase; \
    .quad 0; \
    .previous; \
    .type GLUE(.,name),@function; \
GLUE(.,name):

#define _ENTRY(name) GLUE(.,name)
#else /* __ASSEMBLY__ */

#include <xen/types.h>
#include <asm/powerpc64/procarea.h>

static inline void mtmsrd(ulong msr)
{
    __asm__ __volatile__ ("mtmsrd %0" : : "r" (msr));
}

static inline unsigned long mftb(void)
{
    unsigned long tb;
    __asm__ __volatile__ ("mftb %0" : "=r" (tb));
    return tb;
}

static inline void mttbl(unsigned low)
{
    __asm__ __volatile__ ("mtspr %0, %1" : : "i"(SPRN_TBWL), "r" (low));
}

static inline void mttbu(unsigned upper)
{
    __asm__ __volatile__ ("mtspr %0, %1" : : "i"(SPRN_TBWU), "r" (upper));
}

static inline void mthdec(unsigned ticks)
{
    __asm__ __volatile__ ("mtspr %0, %1" : : "i"(SPRN_HDEC), "r" (ticks));
}

static inline unsigned int mfhdec(void)
{
    unsigned int val;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r"(val) : "i"(SPRN_HDEC));
    return val;
}

static inline void mthsprg0(ulong val)
{
    __asm__ __volatile__ ("mtspr %0, %1" : : "i"(SPRN_HSPRG0), "r"(val));
}
static inline ulong mfhsprg0(void)
{
    ulong val;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r"(val) : "i"(SPRN_HSPRG0));
    return val;
}

static inline void slbia(void)
{
    __asm__ __volatile__ ("isync; slbia; isync":::"memory");
}

static inline void slbie(ulong entry)
{
    __asm__ __volatile__ (
            "isync\n"
            "slbie %0\n"
            "isync\n"
            : : "r" (entry) : "memory");
}

static inline ulong mfhid0(void)
{
    ulong val;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r"(val) : "i"(SPRN_HID0));
    return val;
}
static inline void mthid0(ulong val)
{
    __asm__ __volatile__ (
            "sync\n"
            "mtspr %0, %1\n"
            "mfspr %1, %0\n"
            "mfspr %1, %0\n"
            "mfspr %1, %0\n"
            "mfspr %1, %0\n"
            "mfspr %1, %0\n"
            "isync\n"
            : : "i"(SPRN_HID0), "r"(val));
}

static inline ulong mfhid1(void)
{
    ulong val;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r"(val) : "i"(SPRN_HID1));
    return val;
}
static inline void mthid1(ulong val)
{
    __asm__ __volatile__ (
            "sync\n"
            "mtspr %0, %1\n"
            "mtspr %0, %1\n"
            "isync\n"
            : : "i"(SPRN_HID1), "r"(val));
}

static inline ulong mfhid4(void)
{
    ulong hid4;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r"(hid4) : "i"(SPRN_HID4));
    return hid4;
}

static inline void mthid4(ulong hid4)
{
    __asm__ __volatile__ (
        "sync\n"
        "mtspr %0, %1\n"
        "isync\n"
        : : "i"(SPRN_HID4), "r"(hid4));
}

static inline ulong mfhid5(void)
{
    ulong val;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r"(val) : "i"(SPRN_HID5));
    return val;
}

static inline void mthid5(ulong val)
{
    __asm__ __volatile__ (
            "sync\n"
            "mtspr %0, %1\n"
            "isync\n"
            : : "i"(SPRN_HID5), "r"(val));
}

static inline void mthrmor(ulong val)
{
    __asm__ __volatile__ (
            "sync\n"
            "mtspr %0, %1\n"
            "isync\n"
            : : "i"(SPRN_HRMOR), "r"(val));
}

static inline void mthior(ulong val)
{
    __asm__ __volatile__ (
            "sync\n"
            "mtspr %0, %1\n"
            "isync\n"
            : : "i"(SPRN_HIOR), "r"(val));
}

#endif /* __ASSEMBLY__ */
#endif
