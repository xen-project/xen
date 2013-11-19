/*
 * Xen domain builder -- ARM zImage bits
 *
 * Parse and load ARM zImage kernel images.
 *
 * Copyright (C) 2012, Citrix Systems.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "xg_private.h"
#include "xc_dom.h"

#include <arpa/inet.h> /* XXX ntohl is not the right function... */

struct minimal_dtb_header {
    uint32_t magic;
    uint32_t total_size;
    /* There are other fields but we don't use them yet. */
};

#define DTB_MAGIC 0xd00dfeed

/* ------------------------------------------------------------ */
/* 32-bit zImage Support                                        */
/* ------------------------------------------------------------ */

#define ZIMAGE32_MAGIC_OFFSET 0x24
#define ZIMAGE32_START_OFFSET 0x28
#define ZIMAGE32_END_OFFSET   0x2c

#define ZIMAGE32_MAGIC 0x016f2818

static int xc_dom_probe_zimage32_kernel(struct xc_dom_image *dom)
{
    uint32_t *zimage;
    uint32_t end;

    if ( dom->kernel_blob == NULL )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: no kernel image loaded", __FUNCTION__);
        return -EINVAL;
    }

    if ( dom->kernel_size < 0x30 /*sizeof(struct setup_header)*/ )
    {
        xc_dom_printf(dom->xch, "%s: kernel image too small", __FUNCTION__);
        return -EINVAL;
    }

    zimage = (uint32_t *)dom->kernel_blob;
    if ( zimage[ZIMAGE32_MAGIC_OFFSET/4] != ZIMAGE32_MAGIC )
    {
        xc_dom_printf(dom->xch, "%s: kernel is not an arm32 zImage", __FUNCTION__);
        return -EINVAL;
    }

    end = zimage[ZIMAGE32_END_OFFSET/4];

    /*
     * Check for an appended DTB.
     */
    if ( end + sizeof(struct minimal_dtb_header) < dom->kernel_size ) {
        struct minimal_dtb_header *dtb_hdr;
        dtb_hdr = (struct minimal_dtb_header *)(dom->kernel_blob + end);
        if (ntohl/*be32_to_cpu*/(dtb_hdr->magic) == DTB_MAGIC) {
            xc_dom_printf(dom->xch, "%s: found an appended DTB", __FUNCTION__);
            end += ntohl/*be32_to_cpu*/(dtb_hdr->total_size);
        }
    }

    dom->kernel_size = end;

    return 0;
}

static int xc_dom_parse_zimage32_kernel(struct xc_dom_image *dom)
{
    uint32_t *zimage;
    uint32_t start, entry_addr;
    uint64_t v_start, v_end;
    uint64_t rambase = dom->rambase_pfn << XC_PAGE_SHIFT;

    DOMPRINTF_CALLED(dom->xch);

    zimage = (uint32_t *)dom->kernel_blob;

    /* Do not load kernel at the very first RAM address */
    v_start = rambase + 0x8000;
    v_end = v_start + dom->kernel_size;

    start = zimage[ZIMAGE32_START_OFFSET/4];

    if (start == 0)
        entry_addr = v_start;
    else
        entry_addr = start;

    /* find kernel segment */
    dom->kernel_seg.vstart = v_start;
    dom->kernel_seg.vend   = v_end;

    dom->parms.virt_entry = entry_addr;
    dom->parms.virt_base = rambase;

    dom->guest_type = "xen-3.0-armv7l";
    DOMPRINTF("%s: %s: 0x%" PRIx64 " -> 0x%" PRIx64 "",
              __FUNCTION__, dom->guest_type,
              dom->kernel_seg.vstart, dom->kernel_seg.vend);
    return 0;
}

/* ------------------------------------------------------------ */
/* 64-bit zImage Support                                        */
/* ------------------------------------------------------------ */

#define ZIMAGE64_MAGIC_V0 0x14000008
#define ZIMAGE64_MAGIC_V1 0x644d5241 /* "ARM\x64" */

/* linux/Documentation/arm64/booting.txt */
struct zimage64_hdr {
    uint32_t magic0;
    uint32_t res0;
    uint64_t text_offset;  /* Image load offset */
    uint64_t res1;
    uint64_t res2;
    /* zImage V1 only from here */
    uint64_t res3;
    uint64_t res4;
    uint64_t res5;
    uint32_t magic1;
    uint32_t res6;
};
static int xc_dom_probe_zimage64_kernel(struct xc_dom_image *dom)
{
    struct zimage64_hdr *zimage;

    if ( dom->kernel_blob == NULL )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: no kernel image loaded", __FUNCTION__);
        return -EINVAL;
    }

    if ( dom->kernel_size < sizeof(*zimage) )
    {
        xc_dom_printf(dom->xch, "%s: kernel image too small", __FUNCTION__);
        return -EINVAL;
    }

    zimage =  dom->kernel_blob;
    if ( zimage->magic0 != ZIMAGE64_MAGIC_V0 &&
         zimage->magic1 != ZIMAGE64_MAGIC_V1 )
    {
        xc_dom_printf(dom->xch, "%s: kernel is not an arm64 Image", __FUNCTION__);
        return -EINVAL;
    }

    return 0;
}

static int xc_dom_parse_zimage64_kernel(struct xc_dom_image *dom)
{
    struct zimage64_hdr *zimage;
    uint64_t v_start, v_end;
    uint64_t rambase = dom->rambase_pfn << XC_PAGE_SHIFT;

    DOMPRINTF_CALLED(dom->xch);

    zimage = dom->kernel_blob;

    v_start = rambase + zimage->text_offset;
    v_end = v_start + dom->kernel_size;

    dom->kernel_seg.vstart = v_start;
    dom->kernel_seg.vend   = v_end;

    /* Call the kernel at offset 0 */
    dom->parms.virt_entry = v_start;
    dom->parms.virt_base = rambase;

    dom->guest_type = "xen-3.0-aarch64";
    DOMPRINTF("%s: %s: 0x%" PRIx64 " -> 0x%" PRIx64 "",
              __FUNCTION__, dom->guest_type,
              dom->kernel_seg.vstart, dom->kernel_seg.vend);

    return 0;
}

/* ------------------------------------------------------------ */
/* Common zImage Support                                        */
/* ------------------------------------------------------------ */

static int xc_dom_load_zimage_kernel(struct xc_dom_image *dom)
{
    void *dst;

    DOMPRINTF_CALLED(dom->xch);

    dst = xc_dom_seg_to_ptr(dom, &dom->kernel_seg);
    if ( dst == NULL )
    {
        DOMPRINTF("%s: xc_dom_seg_to_ptr(dom, &dom->kernel_seg) => NULL",
                  __func__);
        return -1;
    }

    DOMPRINTF("%s: kernel seg %#"PRIx64"-%#"PRIx64,
              __func__, dom->kernel_seg.vstart, dom->kernel_seg.vend);
    DOMPRINTF("%s: copy %zd bytes from blob %p to dst %p",
              __func__, dom->kernel_size, dom->kernel_blob, dst);

    memcpy(dst, dom->kernel_blob, dom->kernel_size);

    return 0;
}

static struct xc_dom_loader zimage32_loader = {
    .name = "Linux zImage (ARM32)",
    .probe = xc_dom_probe_zimage32_kernel,
    .parser = xc_dom_parse_zimage32_kernel,
    .loader = xc_dom_load_zimage_kernel,
};

static struct xc_dom_loader zimage64_loader = {
    .name = "Linux zImage (ARM64)",
    .probe = xc_dom_probe_zimage64_kernel,
    .parser = xc_dom_parse_zimage64_kernel,
    .loader = xc_dom_load_zimage_kernel,
};

static void __init register_loader(void)
{
    xc_dom_register_loader(&zimage32_loader);
    xc_dom_register_loader(&zimage64_loader);
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
