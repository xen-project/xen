/*
 * PV event decoding.
 *
 * Copyright (C) 2012 Citrix Systems R&D Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */
#ifndef __PV_H

#include "analyze.h"
#include <xen/trace.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ARG_MISSING 0x0
#define ARG_32BIT 0x1
#define ARG_64BIT 0x2

#define MMU_UPDATE_PREEMPTED          (~(~0U>>1))

static inline uint32_t pv_hypercall_op(const struct record_info *ri)
{
    return ri->d[0] & ~TRC_PV_HYPERCALL_V2_ARG_MASK;
}

static inline int pv_hypercall_arg_present(const struct record_info *ri, int arg)
{
    return (ri->d[0] >> (20 + 2*arg)) & 0x3;
}

void pv_hypercall_gather_args(const struct record_info *ri, uint64_t *args);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
