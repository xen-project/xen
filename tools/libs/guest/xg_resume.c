/*
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
 */

#include "xg_private.h"
#include "xenguest.h"

#if defined(__i386__) || defined(__x86_64__)

#include <xen/foreign/x86_32.h>
#include <xen/foreign/x86_64.h>
#include <xen/hvm/params.h>
#include "xg_core.h"

static int modify_returncode(xc_interface *xch, uint32_t domid)
{
    vcpu_guest_context_any_t ctxt;
    xc_domaininfo_t info;
    xen_capabilities_info_t caps;
    struct domain_info_context _dinfo = {};
    struct domain_info_context *dinfo = &_dinfo;
    int rc;

    if ( xc_domain_getinfo_single(xch, domid, &info) < 0 )
    {
        PERROR("Could not get info for dom%u", domid);
        return -1;
    }

    if ( !dominfo_shutdown_with(&info, SHUTDOWN_suspend) )
    {
        ERROR("Dom %d not suspended: (shutdown %d, reason %d)", domid,
              info.flags & XEN_DOMINF_shutdown,
              dominfo_shutdown_reason(&info));
        errno = EINVAL;
        return -1;
    }

    if ( info.flags & XEN_DOMINF_hvm_guest )
    {
        /* HVM guests without PV drivers have no return code to modify. */
        uint64_t irq = 0;
        xc_hvm_param_get(xch, domid, HVM_PARAM_CALLBACK_IRQ, &irq);
        if ( !irq )
            return 0;

        /* HVM guests have host address width. */
        if ( xc_version(xch, XENVER_capabilities, &caps) != 0 )
        {
            PERROR("Could not get Xen capabilities");
            return -1;
        }
        dinfo->guest_width = strstr(caps, "x86_64") ? 8 : 4;
    }
    else
    {
        /* Probe PV guest address width. */
        if ( xc_domain_get_guest_width(xch, domid, &dinfo->guest_width) )
            return -1;
    }

    if ( (rc = xc_vcpu_getcontext(xch, domid, 0, &ctxt)) != 0 )
        return rc;

    SET_FIELD(&ctxt, user_regs.eax, 1, dinfo->guest_width);

    if ( (rc = xc_vcpu_setcontext(xch, domid, 0, &ctxt)) != 0 )
        return rc;

    return 0;
}

#else

static int modify_returncode(xc_interface *xch, uint32_t domid)
{
    return 0;

}

#endif

static int xc_domain_resume_cooperative(xc_interface *xch, uint32_t domid)
{
    DECLARE_DOMCTL;
    int rc;

    /*
     * Set hypercall return code to indicate that suspend is cancelled
     * (rather than resuming in a new domain context).
     */
    if ( (rc = modify_returncode(xch, domid)) != 0 )
        return rc;

    domctl.cmd = XEN_DOMCTL_resumedomain;
    domctl.domain = domid;
    return do_domctl(xch, &domctl);
}

#if defined(__i386__) || defined(__x86_64__)
static int xc_domain_resume_hvm(xc_interface *xch, uint32_t domid)
{
    DECLARE_DOMCTL;

    /*
     * The domctl XEN_DOMCTL_resumedomain unpause each vcpu. After
     * the domctl, the guest will run.
     *
     * If it is PVHVM, the guest called the hypercall
     *    SCHEDOP_shutdown:SHUTDOWN_suspend
     * to suspend itself. We don't modify the return code, so the PV driver
     * will disconnect and reconnect.
     *
     * If it is a HVM, the guest will continue running.
     */
    domctl.cmd = XEN_DOMCTL_resumedomain;
    domctl.domain = domid;
    return do_domctl(xch, &domctl);
}
#endif

static int xc_domain_resume_any(xc_interface *xch, uint32_t domid)
{
    DECLARE_DOMCTL;
    xc_domaininfo_t info;
    int i, rc = -1;
#if defined(__i386__) || defined(__x86_64__)
    struct domain_info_context _dinfo = { .guest_width = 0,
                                          .p2m_size = 0 };
    struct domain_info_context *dinfo = &_dinfo;
    xen_pfn_t mfn, store_mfn, console_mfn;
    vcpu_guest_context_any_t ctxt;
    start_info_any_t *start_info;
    shared_info_any_t *shinfo = NULL;
    xen_pfn_t *p2m = NULL;
#endif

    if ( xc_domain_getinfo_single(xch, domid, &info) < 0 )
    {
        PERROR("Could not get domain info");
        return rc;
    }

    /*
     * (x86 only) Rewrite store_mfn and console_mfn back to MFN (from PFN).
     */
#if defined(__i386__) || defined(__x86_64__)
    if ( info.flags & XEN_DOMINF_hvm_guest )
        return xc_domain_resume_hvm(xch, domid);

    if ( xc_domain_get_guest_width(xch, domid, &dinfo->guest_width) != 0 )
    {
        PERROR("Could not get domain width");
        return rc;
    }

    /* Map the shared info frame */
    shinfo = xc_map_foreign_range(xch, domid, PAGE_SIZE,
                                  PROT_READ, info.shared_info_frame);
    if ( shinfo == NULL )
    {
        ERROR("Couldn't map shared info");
        goto out;
    }

    /* Map the p2m list */
    if ( xc_core_arch_map_p2m(xch, dinfo, &info, shinfo, &p2m) )
    {
        ERROR("Couldn't map p2m table");
        goto out;
    }

    if ( xc_vcpu_getcontext(xch, domid, 0, &ctxt) )
    {
        ERROR("Could not get vcpu context");
        goto out;
    }

    mfn = GET_FIELD(&ctxt, user_regs.edx, dinfo->guest_width);

    start_info = xc_map_foreign_range(xch, domid, PAGE_SIZE,
                                      PROT_READ | PROT_WRITE, mfn);
    if ( start_info == NULL )
    {
        ERROR("Couldn't map start_info");
        goto out;
    }

    store_mfn = GET_FIELD(start_info, store_mfn, dinfo->guest_width);
    console_mfn = GET_FIELD(start_info, console.domU.mfn, dinfo->guest_width);
    if ( dinfo->guest_width == 4 )
    {
        store_mfn = ((uint32_t *)p2m)[store_mfn];
        console_mfn = ((uint32_t *)p2m)[console_mfn];
    }
    else
    {
        store_mfn = ((uint64_t *)p2m)[store_mfn];
        console_mfn = ((uint64_t *)p2m)[console_mfn];
    }
    SET_FIELD(start_info, store_mfn, store_mfn, dinfo->guest_width);
    SET_FIELD(start_info, console.domU.mfn, console_mfn, dinfo->guest_width);

    munmap(start_info, PAGE_SIZE);
#endif /* defined(__i386__) || defined(__x86_64__) */

    /* Reset all secondary CPU states. */
    for ( i = 1; i <= info.max_vcpu_id; i++ )
        if ( xc_vcpu_setcontext(xch, domid, i, NULL) != 0 )
        {
            ERROR("Couldn't reset vcpu state");
            goto out;
        }

    /* Ready to resume domain execution now. */
    domctl.cmd = XEN_DOMCTL_resumedomain;
    domctl.domain = domid;
    rc = do_domctl(xch, &domctl);

out:
#if defined(__i386__) || defined(__x86_64__)
    if (p2m)
        munmap(p2m, dinfo->p2m_frames * PAGE_SIZE);
    if (shinfo)
        munmap(shinfo, PAGE_SIZE);
#endif

    return rc;
}

/*
 * Resume execution of a domain after suspend shutdown.
 * This can happen in one of two ways:
 *  1. (fast=1) Resume the guest without resetting the domain environment.
 *     The guests's call to SCHEDOP_shutdown(SHUTDOWN_suspend) will return 1.
 *
 *  2. (fast=0) Reset guest environment so it believes it is resumed in a new
 *     domain context. The guests's call to SCHEDOP_shutdown(SHUTDOWN_suspend)
 *     will return 0.
 *
 * (1) should only by used for guests which can handle the special return
 * code. Also note that the insertion of the return code is quite interesting
 * and that the guest MUST be paused - otherwise we would be corrupting
 * the guest vCPU state.
 *
 * (2) should be used only for guests which cannot handle the special
 * new return code - and it is always safe (but slower).
 */
int xc_domain_resume(xc_interface *xch, uint32_t domid, int fast)
{
    return (fast
            ? xc_domain_resume_cooperative(xch, domid)
            : xc_domain_resume_any(xch, domid));
}
