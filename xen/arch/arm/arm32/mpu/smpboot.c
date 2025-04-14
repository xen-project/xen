/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/stdbool.h>

int prepare_secondary_mm(int cpu)
{
    BUG_ON("unimplemented");
    return -EINVAL;
}

void update_boot_mapping(bool enable)
{
    BUG_ON("unimplemented");
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
