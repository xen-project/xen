/*
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
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include "ofh.h"
#include "papr.h"
#include <xen/string.h>
#include <asm/system.h>

union chpack {
    u64 oct[2];
    u32 quad[4];
    char c[16];
};

/* used for internal printing */
static struct ofh_ihandle *ofh_ihp;

static s32 ofh_papr_read(s32 chan, void *buf, u32 count, s32 *actual, ulong b)
{
    s32 rc;
    ulong ret[5];
    ulong sz = 0;

    rc = papr_get_term_char(ret, chan);
    if (rc == H_Success && ret[0] > 0) {
        sz = MIN(count, ret[0]);
        memcpy(buf, &ret[1], sz);
    }
    *actual = sz;
    return OF_SUCCESS;
}

static s32 ofh_papr_write(s32 chan, const void *buf, u32 count, s32 *actual,
                          ulong b)
{
    const char *str = (const char *)buf;
    u32 i;
    union chpack ch;
    s32 ret;

    for (i = 0; i < count; i++) {
        int m = i % sizeof(ch);
        ch.c[m] = str[i];
        if (m == sizeof(ch) - 1 || i == count - 1) {
            for (;;) {
                if (sizeof (ulong) == sizeof (u64)) {
                    ret = papr_put_term_char(NULL,
                                             chan,
                                             m + 1,
                                             ch.oct[0],
                                             ch.oct[1]);
                } else {
                    ret = papr_put_term_char(NULL,
                                             chan,
                                             m + 1,
                                             ch.quad[0],
                                             ch.quad[1],
                                             ch.quad[2],
                                             ch.quad[3]);
                }
                if (ret != H_Busy) {
                    break;
                }
                /* yielding here would be nice */
            }
            if (ret != H_Success) {
                return -1;
            }
        }
    }
    *actual = count;
    if (*actual == -1) {
        return OF_FAILURE;
    }
    return OF_SUCCESS;
}

#define __HYPERVISOR_console_io 18
#define CONSOLEIO_write         0
#define CONSOLEIO_read          1
#define XEN_MARK(a) ((a) | (~0UL << 16))
extern long xen_hvcall(ulong code, ...);

#define XENCOMM_MINI_AREA (sizeof(struct xencomm_mini) * 2)
static s32 ofh_xen_dom0_read(s32 chan, void *buf, u32 count, s32 *actual,
                             ulong b)
{
    char __storage[XENCOMM_MINI_AREA];
    struct xencomm_desc *desc;
    s32 rc;
    char *s = buf;
    s32 ret = 0;

    while (count > 0) {
        if (xencomm_create_mini(__storage, XENCOMM_MINI_AREA, s, count, &desc))
            return ret;

        rc = xen_hvcall(XEN_MARK(__HYPERVISOR_console_io), CONSOLEIO_read,
                        count, desc);
        if (rc <= 0) {
            return ret;
        }
        count -= rc;
        s += rc;
        ret += rc;
    }
    *actual = ret;
    return OF_SUCCESS;
}

static s32 ofh_xen_dom0_write(s32 chan, const void *buf, u32 count,
                              s32 *actual, ulong b)
{
    char __storage[XENCOMM_MINI_AREA];
    struct xencomm_desc *desc;
    s32 rc;
    char *s = (char *)buf;
    s32 ret = 0;

    while (count > 0) {
        if (xencomm_create_mini(__storage, XENCOMM_MINI_AREA, s, count, &desc))
            return ret;

        rc = xen_hvcall(XEN_MARK(__HYPERVISOR_console_io), CONSOLEIO_write,
                        count, desc);
        if (rc <= 0) {
            return ret;
        }
        count -= rc;
        s += rc;
        ret += rc;
    }
    *actual = ret;
    if (*actual == -1) {
        return OF_FAILURE;
    }
    return OF_SUCCESS;
}

static s32 ofh_xen_domu_read(s32 chan, void *buf, u32 count, s32 *actual,
                             ulong b)
{
    struct xencons_interface *intf;
    XENCONS_RING_IDX cons, prod;
    s32 ret;

    intf = DRELA(ofh_ihp, b)->ofi_intf;
    cons = intf->in_cons;
    prod = intf->in_prod;
    mb();

    ret = prod - cons;

    if (ret > 0) {
        ret = (ret < count) ? ret : count;
        memcpy(buf, intf->in+MASK_XENCONS_IDX(cons,intf->in), ret);
    }

    *actual = (ret < 0) ? 0 : ret;
    return OF_SUCCESS;
}

static s32 ofh_xen_domu_write(s32 chan, const void *buf, u32 count,
                              s32 *actual, ulong b)
{
    struct xencons_interface *intf;
    XENCONS_RING_IDX cons, prod;
    s32 ret;

    intf = DRELA(ofh_ihp, b)->ofi_intf;
    cons = intf->in_cons;
    prod = intf->in_prod;
    mb();

    ret = prod - cons;
    /* FIXME: Do we have to write the whole thing or are partial writes ok? */
    if (ret > 0) {
        ret = (ret < count) ? ret : count;
        memcpy(intf->in+MASK_XENCONS_IDX(cons,intf->in), buf, ret);
    }

    *actual = (ret < 0) ? 0 : ret;
    return OF_SUCCESS;
}

/* for emergency printing in the OFH */
s32 ofh_cons_write(const void *buf, u32 count, s32 *actual)
{
    ulong b = get_base();
    struct ofh_ihandle *ihp = DRELA(ofh_ihp, b);

    return ihp->ofi_write(ihp->ofi_chan, buf, count, actual, b);
}

s32 ofh_cons_close(void)
{
    return OF_SUCCESS;
}

void
ofh_cons_init(struct ofh_ihandle *ihp, ulong b)
{
    if (ihp->ofi_chan == OFH_CONS_XEN) {
        if (ihp->ofi_intf == NULL) {
            ihp->ofi_write = ofh_xen_dom0_write;
            ihp->ofi_read = ofh_xen_dom0_read;
        } else {
            ihp->ofi_write = ofh_xen_domu_write;
            ihp->ofi_read = ofh_xen_domu_read;
        }
    } else {
        ihp->ofi_write = ofh_papr_write;
        ihp->ofi_read = ofh_papr_read;
    }
    *DRELA(&ofh_ihp, b) = ihp;
}
