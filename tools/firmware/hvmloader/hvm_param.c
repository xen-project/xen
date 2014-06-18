/*
 * hvm_param.c: get/set HVM params.
 *
 * Copyright (C) 2014 Citrix Systems R&D Ltd.
 */
#include "util.h"
#include "config.h"
#include "hypercall.h"

#include <xen/hvm/params.h>

int hvm_param_get(uint32_t index, uint64_t *value)
{
    struct xen_hvm_param p;
    int ret;

    p.domid = DOMID_SELF;
    p.index = index;

    ret = hypercall_hvm_op(HVMOP_get_param, &p);
    if (ret == 0)
        *value = p.value;

    return ret;
}

int hvm_param_set(uint32_t index, uint64_t value)
{
    struct xen_hvm_param p;

    p.domid = DOMID_SELF;
    p.index = index;
    p.value = value;

    return hypercall_hvm_op(HVMOP_set_param, &p);
}
