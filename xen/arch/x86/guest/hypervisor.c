/******************************************************************************
 * arch/x86/guest/hypervisor.c
 *
 * Support for detecting and running under a hypervisor.
 *
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
 * Copyright (c) 2019 Microsoft.
 */
#include <xen/init.h>
#include <xen/types.h>

#include <asm/cache.h>
#include <asm/guest.h>

static struct hypervisor_ops __read_mostly ops;

const char *__init hypervisor_probe(void)
{
    const struct hypervisor_ops *fns;

    if ( !cpu_has_hypervisor )
        return NULL;

    fns = xg_probe();
    if ( !fns )
        /*
         * Detection of Hyper-V must come after Xen to avoid false positive due
         * to viridian support
         */
        fns = hyperv_probe();

    if ( fns )
        ops = *fns;

    return ops.name;
}

void __init hypervisor_setup(void)
{
    if ( ops.setup )
        ops.setup();
}

int hypervisor_ap_setup(void)
{
    if ( ops.ap_setup )
        return ops.ap_setup();

    return 0;
}

void hypervisor_resume(void)
{
    if ( ops.resume )
        ops.resume();
}

void __init hypervisor_e820_fixup(struct e820map *e820)
{
    if ( ops.e820_fixup )
        ops.e820_fixup(e820);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
