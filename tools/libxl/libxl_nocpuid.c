/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"

int libxl__cpuid_policy_is_empty(libxl_cpuid_policy_list *pl)
{
    return 1;
}

void libxl_cpuid_dispose(libxl_cpuid_policy_list *p_cpuid_list)
{
}

int libxl_cpuid_parse_config(libxl_cpuid_policy_list *cpuid, const char* str)
{
    return 0;
}

int libxl_cpuid_parse_config_xend(libxl_cpuid_policy_list *cpuid,
                                  const char* str)
{
    return 0;
}

void libxl__cpuid_legacy(libxl_ctx *ctx, uint32_t domid,
                         libxl_domain_config *d_config)
{
}

yajl_gen_status libxl_cpuid_policy_list_gen_json(yajl_gen hand,
                                libxl_cpuid_policy_list *pcpuid)
{
    return 0;
}

int libxl__cpuid_policy_list_parse_json(libxl__gc *gc,
                                        const libxl__json_object *o,
                                        libxl_cpuid_policy_list *p)
{
    return 0;
}

void libxl_cpuid_policy_list_copy(libxl_ctx *ctx,
                                  libxl_cpuid_policy_list *dst,
                                  const libxl_cpuid_policy_list *src)
{
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
