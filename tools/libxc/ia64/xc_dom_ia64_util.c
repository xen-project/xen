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
 * Copyright (c) 2007 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *
 */

#include "xg_private.h"
#include "xc_dom.h"
#include "asm/dom_fw.h"
#include "asm/dom_fw_common.h"
#include "ia64/xc_dom_ia64_util.h"

uint32_t
xen_ia64_version(struct xc_dom_image *dom)
{
    return xc_version(dom->guest_xc, XENVER_version, NULL);   
}

int
xen_ia64_fpswa_revision(struct xc_dom_image *dom, unsigned int *revision)
{
    int ret = -1;
    DECLARE_HYPERCALL;
    hypercall.op     = __HYPERVISOR_ia64_dom0vp_op;
    hypercall.arg[0] = IA64_DOM0VP_fpswa_revision;
    hypercall.arg[1] = (unsigned long)revision;

    if (lock_pages(revision, sizeof(*revision)) != 0) {
        PERROR("Could not lock memory for xen fpswa hypercall");
        goto out;
    }

    ret = do_xen_hypercall(dom->guest_xc, &hypercall);
    
    unlock_pages(revision, sizeof(*revision));
out:
    return ret;
}

int xen_ia64_is_running_on_sim(struct xc_dom_image *dom)
{
    /*
     * This is only used by dom_fw_init() as
     * "!xen_ia64_is_dom0() || xen_ia64_is_running_on_sim()".
     * So this doesn't affect the result.
     */
    return 0;
}

int
xen_ia64_is_dom0(struct xc_dom_image *unused)
{
    /* libxc is for non-dom0 domain builder */
    return 0;
}

void*
xen_ia64_dom_fw_map(struct xc_dom_image *dom, unsigned long mpaddr)
{
    unsigned long page_size = XC_DOM_PAGE_SIZE(dom);
    void* ret;
    
    ret = xc_map_foreign_range(dom->guest_xc, dom->guest_domid,
                               page_size, PROT_READ | PROT_WRITE,
                               mpaddr / page_size);
    if (ret != NULL)
        ret = (void*)((unsigned long)ret | (mpaddr & (page_size - 1)));
    return ret;
}

void
xen_ia64_dom_fw_unmap(struct xc_dom_image *dom, void *vaddr)
{
    unsigned long page_size = XC_DOM_PAGE_SIZE(dom);
    munmap((void*)((unsigned long)vaddr & ~(page_size - 1)), page_size);
}

int
xen_ia64_is_vcpu_allocated(struct xc_dom_image *dom, uint32_t vcpu)
{
    // return d->vcpu[vcpu] != NULL;

    int rc;
    xc_vcpuinfo_t info;

    rc = xc_vcpu_getinfo(dom->guest_xc, dom->guest_domid,
                         vcpu, &info);
    if (rc == 0)
        return 1;

    if (rc != -ESRCH)
        PERROR("Could not get vcpu info");
    return 0;
}

int
xen_ia64_dom_fw_setup(struct xc_dom_image *d, uint64_t brkimm,
                      unsigned long bp_mpa, unsigned long maxmem)
{
    int rc = 0;
    void *imva_hypercall_base = NULL;
    void *imva_tables_base = NULL;
    struct fake_acpi_tables *imva = NULL;
    struct xen_ia64_boot_param *bp = NULL;

    BUILD_BUG_ON(sizeof(struct fw_tables) >
                 (FW_TABLES_END_PADDR - FW_TABLES_BASE_PADDR));

    /* Create page for hypercalls.  */
    imva_hypercall_base = xen_ia64_dom_fw_map(d, FW_HYPERCALL_BASE_PADDR);
    if (imva_hypercall_base == NULL) {
        rc = -errno;
        goto out;
    }

    /* Create page for FW tables.  */
    imva_tables_base = xen_ia64_dom_fw_map(d, FW_TABLES_BASE_PADDR);
    if (imva_tables_base == NULL) {
        rc = -errno;
        goto out;
    }
        
    /* Create page for acpi tables.  */
    imva = (struct fake_acpi_tables *)
        xen_ia64_dom_fw_map(d, FW_ACPI_BASE_PADDR);
    if (imva == NULL) {
        rc = -errno;
        goto out;
    }
    dom_fw_fake_acpi(d, imva);

    /* Create page for boot_param.  */
    bp = xen_ia64_dom_fw_map(d, bp_mpa);
    if (bp == NULL) {
        rc = -errno;
        goto out;
    }
    rc = dom_fw_init(d, brkimm, bp, imva_tables_base,
                     (unsigned long)imva_hypercall_base, maxmem);
 out:
    if (imva_hypercall_base != NULL)
        xen_ia64_dom_fw_unmap(d, imva_hypercall_base);
    if (imva_tables_base != NULL)
        xen_ia64_dom_fw_unmap(d, imva_tables_base);
    if (imva != NULL)
        xen_ia64_dom_fw_unmap(d, imva);
    if (bp != NULL)
        xen_ia64_dom_fw_unmap(d, bp);
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
