/*
 * Copyright (C) 2014 Citrix Systems R&D Ltd.
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

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"

#include <xenctrl.h>
#include <xen/hvm/params.h>

/*
 * Generate a random VM generation ID.
 *
 * Returns ERROR_FAIL if a suitable source of random numbers is not
 * available.
 *
 * See Microsoft's "Virtual Machine Generation ID" specification for
 * further details, including when a new generation ID is required.
 *
 *   http://www.microsoft.com/en-us/download/details.aspx?id=30707
 */
int libxl_ms_vm_genid_generate(libxl_ctx *ctx, libxl_ms_vm_genid *id)
{
    GC_INIT(ctx);
    int ret;

    ret = libxl__random_bytes(gc, id->bytes, LIBXL_MS_VM_GENID_LEN);

    GC_FREE;
    return ret;
}

/*
 * Is this VM generation ID all zeros?
 */
bool libxl_ms_vm_genid_is_zero(const libxl_ms_vm_genid *id)
{
    static const libxl_ms_vm_genid zero;

    return memcmp(id->bytes, zero.bytes, LIBXL_MS_VM_GENID_LEN) == 0;
}

void libxl_ms_vm_genid_copy(libxl_ctx *ctx, libxl_ms_vm_genid *dst,
                            libxl_ms_vm_genid *src)
{
    memcpy(dst, src, LIBXL_MS_VM_GENID_LEN);
}

int libxl__ms_vm_genid_set(libxl__gc *gc, uint32_t domid,
                           const libxl_ms_vm_genid *id)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    const char *dom_path;
    uint64_t genid[2];
    uint64_t paddr = 0;
    int rc;

    memcpy(genid, id->bytes, LIBXL_MS_VM_GENID_LEN);

    /*
     * Set the "platform/generation-id" XenStore key to pass the ID to
     * hvmloader.
     */
    dom_path = libxl__xs_get_dompath(gc, domid);
    if (!dom_path) {
        rc = ERROR_FAIL;
        goto out;
    }
    rc = libxl__xs_write(gc, XBT_NULL,
                         GCSPRINTF("%s/platform/generation-id", dom_path),
                         "%"PRIu64 ":%" PRIu64, genid[0], genid[1]);
    if (rc < 0)
        goto out;

    /*
     * Update the ID in guest memory (if available).
     */
    xc_hvm_param_get(ctx->xch, domid, HVM_PARAM_VM_GENERATION_ID_ADDR, &paddr);
    if (paddr) {
        void *vaddr;

        vaddr = xc_map_foreign_range(ctx->xch, domid, XC_PAGE_SIZE,
                                     PROT_READ | PROT_WRITE,
                                     paddr >> XC_PAGE_SHIFT);
        if (vaddr == NULL) {
            rc = ERROR_FAIL;
            goto out;
        }
        memcpy(vaddr + (paddr & ~XC_PAGE_MASK), genid, 2 * sizeof(*genid));
        munmap(vaddr, XC_PAGE_SIZE);

        /*
         * The spec requires an ACPI Notify event is injected into the
         * guest when the generation ID is changed.
         *
         * This is only called for domains that are suspended or newly
         * created and they won't be in a state to receive such an
         * event.
         */
    }

    rc = 0;

  out:
    return rc;
}
