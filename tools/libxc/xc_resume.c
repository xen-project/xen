#include "xc_private.h"


#if defined(__i386__) || defined(__x86_64__)
static int modify_returncode(int xc_handle, uint32_t domid)
{
    vcpu_guest_context_t ctxt;
    int rc;

    if ( (rc = xc_vcpu_getcontext(xc_handle, domid, 0, &ctxt)) != 0 )
        return rc;
    ctxt.user_regs.eax = 1;
    if ( (rc = xc_vcpu_setcontext(xc_handle, domid, 0, &ctxt)) != 0 )
        return rc;

    return 0;
}
#else
static int modify_returncode(int xc_handle, uint32_t domid)
{
    return 0;
}
#endif


/*
 * Resume execution of a domain after suspend shutdown.
 * This can happen in one of two ways:
 *  1. Resume with special return code.
 *  2. Reset guest environment so it believes it is resumed in a new
 *     domain context.
 * (2) should be used only for guests which cannot handle the special
 * new return code. (1) is always safe (but slower).
 * 
 * XXX Only (2) is implemented below. We need to use (1) by default!
 */
int xc_domain_resume(int xc_handle, uint32_t domid)
{
    DECLARE_DOMCTL;
    int rc;

    /*
     * Set hypercall return code to indicate that suspend is cancelled
     * (rather than resuming in a new domain context).
     */
    if ( (rc = modify_returncode(xc_handle, domid)) != 0 )
        return rc;

    domctl.cmd = XEN_DOMCTL_resumedomain;
    domctl.domain = domid;
    return do_domctl(xc_handle, &domctl);
}
