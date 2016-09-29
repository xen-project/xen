/*
 * Copyright (C) 2016      Linaro Ltd.
 *
 * Author: Shannon Zhao <shannon.zhao@linaro.org>
 *
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

#include "libxl_internal.h"
#include "libxl_arch.h"

#include <xc_dom.h>

_hidden
int libxl__prepare_acpi(libxl__gc *gc, libxl_domain_build_info *info,
                        struct xc_dom_image *dom);

_hidden
int libxl__get_acpi_size(libxl__gc *gc,
                         const libxl_domain_build_info *info,
                         uint64_t *out);

static inline uint64_t libxl__compute_mpdir(unsigned int cpuid)
{
    /*
     * According to ARM CPUs bindings, the reg field should match
     * the MPIDR's affinity bits. We will use AFF0 and AFF1 when
     * constructing the reg value of the guest at the moment, for it
     * is enough for the current max vcpu number.
     */
    return (cpuid & 0x0f) | (((cpuid >> 4) & 0xff) << 8);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
