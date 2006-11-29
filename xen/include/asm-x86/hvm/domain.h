/*
 * domain.h: HVM per domain definitions
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#ifndef __ASM_X86_HVM_DOMAIN_H__
#define __ASM_X86_HVM_DOMAIN_H__

#include <asm/hvm/irq.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/io.h>
#include <public/hvm/params.h>

struct hvm_domain {
    unsigned long          shared_page_va;
    unsigned long          buffered_io_va;
    spinlock_t             buffered_io_lock;
    s64                    tsc_frequency;
    struct pl_time         pl_time;

    struct hvm_io_handler  io_handler;

    struct hvm_irq         irq;

    /* hvm_print_line() logging. */
    char                   pbuf[80];
    int                    pbuf_idx;
    spinlock_t             pbuf_lock;

    uint64_t               params[HVM_NR_PARAMS];
};

#endif /* __ASM_X86_HVM_DOMAIN_H__ */

