/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
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

#include <xenctrl.h>
#include <xenguest.h>
#include <sys/mman.h>
#include <xen/hvm/hvm_info_table.h>
#include <string.h>

#include "libxl.h"
#include "libxl_internal.h"

int hvm_build_set_params(xc_interface *handle, uint32_t domid,
                         libxl_domain_build_info *info,
                         int store_evtchn, unsigned long *store_mfn,
                         int console_evtchn, unsigned long *console_mfn)
{
    struct hvm_info_table *va_hvm;
    uint8_t *va_map, sum;
    int i;

    va_map = xc_map_foreign_range(handle, domid,
                                  XC_PAGE_SIZE, PROT_READ | PROT_WRITE,
                                  HVM_INFO_PFN);
    if (va_map == NULL)
        return -1;

    va_hvm = (struct hvm_info_table *)(va_map + HVM_INFO_OFFSET);
    va_hvm->acpi_enabled = info->u.hvm.acpi;
    va_hvm->apic_mode = info->u.hvm.apic;
    va_hvm->nr_vcpus = info->max_vcpus;
    memcpy(va_hvm->vcpu_online, &info->cur_vcpus, sizeof(info->cur_vcpus));
    for (i = 0, sum = 0; i < va_hvm->length; i++)
        sum += ((uint8_t *) va_hvm)[i];
    va_hvm->checksum -= sum;
    munmap(va_map, XC_PAGE_SIZE);

    xc_get_hvm_param(handle, domid, HVM_PARAM_STORE_PFN, store_mfn);
    xc_get_hvm_param(handle, domid, HVM_PARAM_CONSOLE_PFN, console_mfn);
    xc_set_hvm_param(handle, domid, HVM_PARAM_PAE_ENABLED, info->u.hvm.pae);
#if defined(__i386__) || defined(__x86_64__)
    xc_set_hvm_param(handle, domid, HVM_PARAM_VIRIDIAN, info->u.hvm.viridian);
    xc_set_hvm_param(handle, domid, HVM_PARAM_HPET_ENABLED, (unsigned long) info->u.hvm.hpet);
#endif
    xc_set_hvm_param(handle, domid, HVM_PARAM_TIMER_MODE, (unsigned long) info->u.hvm.timer_mode);
    xc_set_hvm_param(handle, domid, HVM_PARAM_VPT_ALIGN, (unsigned long) info->u.hvm.vpt_align);
    xc_set_hvm_param(handle, domid, HVM_PARAM_STORE_EVTCHN, store_evtchn);
    xc_set_hvm_param(handle, domid, HVM_PARAM_CONSOLE_EVTCHN, console_evtchn);
    return 0;
}
