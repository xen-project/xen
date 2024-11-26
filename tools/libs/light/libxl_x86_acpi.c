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
 *
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 */

#include "libxl_internal.h"
#include "libxl_arch.h"
#include <xen/hvm/hvm_info_table.h>
#include <xen/hvm/e820.h>
#include "libacpi.h"

 /* Number of pages holding ACPI tables */
#define NUM_ACPI_PAGES 16
/* Hard-coded size of RSDP */
#define RSDP_LEN 64
#define ALIGN(p, a) (((p) + ((a) - 1)) & ~((a) - 1))

struct libxl_acpi_ctxt {
    struct acpi_ctxt c;

    unsigned int page_size;
    unsigned int page_shift;

    /* Memory allocator */
    unsigned long guest_start;
    unsigned long guest_curr;
    unsigned long guest_end;
    void *buf;
};

extern const unsigned char dsdt_pvh[];
extern const unsigned int dsdt_pvh_len;

/* Assumes contiguous physical space */
static unsigned long virt_to_phys(struct acpi_ctxt *ctxt, void *v)
{
    struct libxl_acpi_ctxt *libxl_ctxt =
        CONTAINER_OF(ctxt, struct libxl_acpi_ctxt, c);

    return libxl_ctxt->guest_start + (v - libxl_ctxt->buf);
}

static void *mem_alloc(struct acpi_ctxt *ctxt,
                       uint32_t size, uint32_t align)
{
    struct libxl_acpi_ctxt *libxl_ctxt =
        CONTAINER_OF(ctxt, struct libxl_acpi_ctxt, c);
    unsigned long s, e;

    /* Align to at least 16 bytes. */
    if (align < 16)
        align = 16;

    s = ALIGN(libxl_ctxt->guest_curr, align);
    e = s + size - 1;

    /* TODO: Reallocate memory */
    if ((e < s) || (e >= libxl_ctxt->guest_end))
        return NULL;

    libxl_ctxt->guest_curr = e;

    return libxl_ctxt->buf + (s - libxl_ctxt->guest_start);
}

static void acpi_mem_free(struct acpi_ctxt *ctxt,
                          void *v, uint32_t size)
{
}

static uint32_t acpi_lapic_id(unsigned cpu)
{
    return cpu * 2;
}

static int init_acpi_config(libxl__gc *gc, 
                            struct xc_dom_image *dom,
                            const libxl_domain_build_info *b_info,
                            struct acpi_config *config)
{
    xc_interface *xch = dom->xch;
    uint32_t domid = dom->guest_domid;
    xc_domaininfo_t info;
    struct hvm_info_table *hvminfo;
    int r, rc;

    config->dsdt_anycpu = config->dsdt_15cpu = dsdt_pvh;
    config->dsdt_anycpu_len = config->dsdt_15cpu_len = dsdt_pvh_len;

    r = xc_domain_getinfo_single(xch, domid, &info);
    if (r < 0) {
        LOGED(ERROR, domid, "getdomaininfo failed");
        rc = ERROR_FAIL;
        goto out;
    }

    hvminfo = libxl__zalloc(gc, sizeof(*hvminfo));

    hvminfo->apic_mode = libxl_defbool_val(b_info->apic);

    if (dom->nr_vnodes) {
        unsigned int *vcpu_to_vnode, *vdistance;
        struct xen_vmemrange *vmemrange;
        struct acpi_numa *numa = &config->numa;

        r = xc_domain_getvnuma(xch, domid, &numa->nr_vnodes,
                               &numa->nr_vmemranges,
                               &hvminfo->nr_vcpus, NULL, NULL, NULL);
        if (r) {
            LOG(ERROR, "xc_domain_getvnuma failed (rc=%d)", r);
            rc = ERROR_FAIL;
            goto out;
        }

        vmemrange = libxl__zalloc(gc, dom->nr_vmemranges * sizeof(*vmemrange));
        vdistance = libxl__zalloc(gc, dom->nr_vnodes * sizeof(*vdistance));
        vcpu_to_vnode = libxl__zalloc(gc, hvminfo->nr_vcpus *
                                      sizeof(*vcpu_to_vnode));
        r = xc_domain_getvnuma(xch, domid, &numa->nr_vnodes,
                               &numa->nr_vmemranges, &hvminfo->nr_vcpus,
                               vmemrange, vdistance, vcpu_to_vnode);
        if (r) {
            LOG(ERROR, "xc_domain_getvnuma failed (rc=%d)", r);
            rc = ERROR_FAIL;
            goto out;
        }
        numa->vmemrange = vmemrange;
        numa->vdistance = vdistance;
        numa->vcpu_to_vnode = vcpu_to_vnode;
    } else {
        hvminfo->nr_vcpus = info.max_vcpu_id + 1;
    }

    memcpy(hvminfo->vcpu_online, b_info->avail_vcpus.map,
           b_info->avail_vcpus.size);

    config->hvminfo = hvminfo;

    config->lapic_base_address = LAPIC_BASE_ADDRESS;
    config->lapic_id = acpi_lapic_id;
    config->acpi_revision = 5;

    rc = 0;
out:
    return rc;
}

int libxl__dom_load_acpi(libxl__gc *gc,
                         const libxl_domain_build_info *b_info,
                         struct xc_dom_image *dom)
{
    struct acpi_config config = {0};
    struct libxl_acpi_ctxt libxl_ctxt;
    int rc = 0, acpi_pages_num;

    if (b_info->type != LIBXL_DOMAIN_TYPE_PVH)
        goto out;

    libxl_ctxt.page_size = XC_DOM_PAGE_SIZE(dom);
    libxl_ctxt.page_shift =  XC_DOM_PAGE_SHIFT(dom);

    libxl_ctxt.c.mem_ops.alloc = mem_alloc;
    libxl_ctxt.c.mem_ops.v2p = virt_to_phys;
    libxl_ctxt.c.mem_ops.free = acpi_mem_free;

    rc = init_acpi_config(gc, dom, b_info, &config);
    if (rc) {
        LOG(ERROR, "init_acpi_config failed (rc=%d)", rc);
        goto out;
    }

    /* These are all copied into guest memory, so use zero-ed memory. */
    config.rsdp = (unsigned long)libxl__zalloc(gc, RSDP_LEN);
    config.infop = (unsigned long)libxl__zalloc(gc, libxl_ctxt.page_size);
    /* Pages to hold ACPI tables */
    libxl_ctxt.buf = libxl__zalloc(gc, NUM_ACPI_PAGES *
                                   libxl_ctxt.page_size);

    /*
     * Set up allocator memory.
     * Start next to acpi_info page to avoid fracturing e820.
     */
    libxl_ctxt.guest_start = libxl_ctxt.guest_curr = libxl_ctxt.guest_end =
        ACPI_INFO_PHYSICAL_ADDRESS + libxl_ctxt.page_size;

    libxl_ctxt.guest_end += NUM_ACPI_PAGES * libxl_ctxt.page_size;

    /* Build the tables. */
    rc = acpi_build_tables(&libxl_ctxt.c, &config);
    if (rc) {
        LOG(ERROR, "acpi_build_tables failed with %d", rc);
        goto out;
    }

    /* Calculate how many pages are needed for the tables. */
    acpi_pages_num = (ALIGN(libxl_ctxt.guest_curr, libxl_ctxt.page_size) -
                      libxl_ctxt.guest_start) >> libxl_ctxt.page_shift;

    dom->acpi_modules[0].data = (void *)config.rsdp;
    dom->acpi_modules[0].length = RSDP_LEN;
    /*
     * Some Linux versions cannot properly process hvm_start_info.rsdp_paddr
     * and so we need to put RSDP in location that can be discovered by ACPI's
     * standard search method, in R-O BIOS memory (we chose last RSDP_LEN bytes)
     */
    if (strcmp(xc_dom_guest_os(dom), "linux") ||
        xc_dom_feature_get(dom, XENFEAT_linux_rsdp_unrestricted))
        dom->acpi_modules[0].guest_addr_out = ACPI_INFO_PHYSICAL_ADDRESS +
            (1 + acpi_pages_num) * libxl_ctxt.page_size;
    else
        dom->acpi_modules[0].guest_addr_out = 0x100000 - RSDP_LEN;

    dom->acpi_modules[1].data = (void *)config.infop;
    dom->acpi_modules[1].length = libxl_ctxt.page_size;
    dom->acpi_modules[1].guest_addr_out = ACPI_INFO_PHYSICAL_ADDRESS;

    dom->acpi_modules[2].data = libxl_ctxt.buf;
    dom->acpi_modules[2].length = acpi_pages_num  << libxl_ctxt.page_shift;
    dom->acpi_modules[2].guest_addr_out = ACPI_INFO_PHYSICAL_ADDRESS +
        libxl_ctxt.page_size;

out:
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
