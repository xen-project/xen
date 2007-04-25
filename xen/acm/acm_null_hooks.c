/****************************************************************
 * acm_null_hooks.c
 * 
 * Copyright (C) 2005 IBM Corporation
 *
 * Author:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <acm/acm_hooks.h>

static int
null_init_domain_ssid(void **ssid, ssidref_t ssidref)
{
    return ACM_OK;
}

static void
null_free_domain_ssid(void *ssid)
{
    return;
}

static int
null_dump_binary_policy(u8 *buf, u32 buf_size)
{ 
    return 0;
}

static int
null_test_binary_policy(u8 *buf, u32 buf_size, int is_bootpolicy,
                        struct acm_sized_buffer *errors)
{
    return ACM_OK;
}

static int
null_set_binary_policy(u8 *buf, u32 buf_size)
{ 
    return ACM_OK;
}
 
static int 
null_dump_stats(u8 *buf, u16 buf_size)
{
    /* no stats for NULL policy */
    return 0;
}

static int
null_dump_ssid_types(ssidref_t ssidref, u8 *buffer, u16 buf_size)
{
    /* no types */
    return 0;
}


/* now define the hook structure similarly to LSM */
struct acm_operations acm_null_ops = {
    .init_domain_ssid = null_init_domain_ssid,
    .free_domain_ssid = null_free_domain_ssid,
    .dump_binary_policy = null_dump_binary_policy,
    .test_binary_policy = null_test_binary_policy,
    .set_binary_policy = null_set_binary_policy,
    .dump_statistics = null_dump_stats,
    .dump_ssid_types = null_dump_ssid_types,
    /* domain management control hooks */
    .domain_create = NULL,
    .domain_destroy = NULL,
    /* event channel control hooks */
    .pre_eventchannel_unbound = NULL,
    .fail_eventchannel_unbound = NULL,
    .pre_eventchannel_interdomain = NULL,
    .fail_eventchannel_interdomain = NULL,
    /* grant table control hooks */
    .pre_grant_map_ref = NULL,
    .fail_grant_map_ref = NULL,
    .pre_grant_setup = NULL,
    .fail_grant_setup = NULL
};

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
