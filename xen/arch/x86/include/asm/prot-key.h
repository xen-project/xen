/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021-2022 Citrix Systems Ltd.
 */
#ifndef ASM_PROT_KEY_H
#define ASM_PROT_KEY_H

#include <xen/types.h>

#define PKEY_AD 1 /* Access Disable */
#define PKEY_WD 2 /* Write Disable */

#define PKEY_WIDTH 2 /* Two bits per protection key */

static inline uint32_t rdpkru(void)
{
    uint32_t pkru;

    asm volatile ( ".byte 0x0f,0x01,0xee"
                   : "=a" (pkru) : "c" (0) : "dx" );

    return pkru;
}

static inline void wrpkru(uint32_t pkru)
{
    asm volatile ( ".byte 0x0f,0x01,0xef"
                   :: "a" (pkru), "d" (0), "c" (0) );
}

#endif /* ASM_PROT_KEY_H */
