/*
 * Xen domain builder -- compatibility code.
 *
 * Replacements for xc_linux_build & friends,
 * as example code and to make the new builder
 * usable as drop-in replacement.
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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * written 2006 by Gerd Hoffmann <kraxel@suse.de>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <zlib.h>

#include "xenctrl.h"
#include "xg_private.h"
#include "xc_dom.h"

/* ------------------------------------------------------------------------ */

static int xc_linux_build_internal(struct xc_dom_image *dom,
                                   xc_interface *xch, uint32_t domid,
                                   unsigned int mem_mb,
                                   unsigned long flags,
                                   unsigned int store_evtchn,
                                   unsigned long *store_mfn,
                                   unsigned int console_evtchn,
                                   unsigned long *console_mfn)
{
    int rc;

    dom->flags = flags;
    dom->console_evtchn = console_evtchn;
    dom->xenstore_evtchn = store_evtchn;

    if ( (rc = xc_dom_boot_xen_init(dom, xch, domid)) != 0 )
        goto out;
    if ( (rc = xc_dom_parse_image(dom)) != 0 )
        goto out;
    if ( (rc = xc_dom_mem_init(dom, mem_mb)) != 0 )
        goto out;
    if ( (rc = xc_dom_boot_mem_init(dom)) != 0 )
        goto out;
    if ( (rc = xc_dom_build_image(dom)) != 0 )
        goto out;
    if ( (rc = xc_dom_boot_image(dom)) != 0 )
        goto out;
    if ( (rc = xc_dom_gnttab_init(dom)) != 0)
        goto out;

    *console_mfn = xc_dom_p2m_host(dom, dom->console_pfn);
    *store_mfn = xc_dom_p2m_host(dom, dom->xenstore_pfn);

 out:
    return rc;
}

int xc_linux_build_mem(xc_interface *xch, uint32_t domid,
                       unsigned int mem_mb,
                       const char *image_buffer,
                       unsigned long image_size,
                       const char *initrd,
                       unsigned long initrd_len,
                       const char *cmdline,
                       const char *features,
                       unsigned long flags,
                       unsigned int store_evtchn,
                       unsigned long *store_mfn,
                       unsigned int console_evtchn,
                       unsigned long *console_mfn)
{
    struct xc_dom_image *dom;
    int rc;

    xc_dom_loginit(xch);
    dom = xc_dom_allocate(xch, cmdline, features);
    if (dom == NULL)
        return -1;
    if ( (rc = xc_dom_kernel_mem(dom, image_buffer, image_size)) != 0 )
        goto out;
    if ( initrd && ((rc = xc_dom_ramdisk_mem(dom, initrd, initrd_len)) != 0) )
        goto out;

    rc = xc_linux_build_internal(dom, xch, domid,
                                 mem_mb, flags,
                                 store_evtchn, store_mfn,
                                 console_evtchn, console_mfn);

 out:
    xc_dom_release(dom);
    return rc;
}

int xc_linux_build(xc_interface *xch, uint32_t domid,
                   unsigned int mem_mb,
                   const char *image_name,
                   const char *initrd_name,
                   const char *cmdline,
                   const char *features,
                   unsigned long flags,
                   unsigned int store_evtchn,
                   unsigned long *store_mfn,
                   unsigned int console_evtchn,
                   unsigned long *console_mfn)
{
    struct xc_dom_image *dom;
    int rc;

    xc_dom_loginit(xch);
    dom = xc_dom_allocate(xch, cmdline, features);
    if (dom == NULL)
        return -1;
    if ( (rc = xc_dom_kernel_file(dom, image_name)) != 0 )
        goto out;
    if ( initrd_name && strlen(initrd_name) &&
         ((rc = xc_dom_ramdisk_file(dom, initrd_name)) != 0) )
        goto out;

    rc = xc_linux_build_internal(dom, xch, domid,
                                 mem_mb, flags,
                                 store_evtchn, store_mfn,
                                 console_evtchn, console_mfn);

 out:
    xc_dom_release(dom);
    return rc;
}
int xc_get_bit_size(xc_interface *xch,
                    const char *image_name, const char *cmdline, 
                    const char *features, int *bit_size)
{
    struct xc_dom_image *dom;
    int rc;
    *bit_size = 0;
    dom = xc_dom_allocate(xch, cmdline, features);
    if (dom == NULL)
        return -1;
    if ( (rc = xc_dom_kernel_file(dom, image_name)) != 0 )
        goto out;
    if ( (rc = xc_dom_parse_image(dom)) != 0 )
        goto out;
    if( dom->guest_type != NULL){
        if(strstr(dom->guest_type, "x86_64") != NULL)
            *bit_size = X86_64_B_SIZE; //64bit Guest 
        if(strstr(dom->guest_type, "x86_32") != NULL)
            *bit_size = X86_32_B_SIZE; //32bit Guest
    }

out:
    xc_dom_release(dom);
    return rc;
}

int xc_dom_linux_build(xc_interface *xch,
                       struct xc_dom_image *dom,
                       uint32_t domid,
                       unsigned int mem_mb,
                       const char *image_name,
                       const char *initrd_name,
                       unsigned long flags,
                       unsigned int store_evtchn,
                       unsigned long *store_mfn,
                       unsigned int console_evtchn, unsigned long *console_mfn)
{
    int rc;

    if ( (rc = xc_dom_kernel_file(dom, image_name)) != 0 )
        return rc;
    if ( initrd_name && strlen(initrd_name) &&
         ((rc = xc_dom_ramdisk_file(dom, initrd_name)) != 0) )
        return rc;

    return xc_linux_build_internal(dom, xch, domid,
                                   mem_mb, flags,
                                   store_evtchn, store_mfn,
                                   console_evtchn, console_mfn);
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
