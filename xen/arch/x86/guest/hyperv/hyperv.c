/******************************************************************************
 * arch/x86/guest/hyperv/hyperv.c
 *
 * Support for detecting and running under Hyper-V.
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

#include <asm/guest.h>

static const struct hypervisor_ops ops = {
    .name = "Hyper-V",
};

const struct hypervisor_ops *__init hyperv_probe(void)
{
    uint32_t eax, ebx, ecx, edx;

    cpuid(0x40000000, &eax, &ebx, &ecx, &edx);
    if ( !((ebx == 0x7263694d) &&  /* "Micr" */
           (ecx == 0x666f736f) &&  /* "osof" */
           (edx == 0x76482074)) )  /* "t Hv" */
        return NULL;

    cpuid(0x40000001, &eax, &ebx, &ecx, &edx);
    if ( eax != 0x31237648 )    /* Hv#1 */
        return NULL;

    return &ops;
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
