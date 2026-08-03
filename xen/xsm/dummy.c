/*
 *  This work is based on the LSM implementation in Linux 2.6.13.4.
 *
 *  Author:  George Coker, <gscoker@alpha.ncsc.mil>
 *
 *  Contributors: Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#define XSM_NO_WRAPPERS
#include <xsm/dummy.h>

static const struct xsm_ops __initconst_cf_clobber dummy_ops = {
    .set_system_active             = xsm_set_system_active,
    .security_domaininfo           = xsm_security_domaininfo,

#define XSM_HOOK0(rtype, name) .name = xsm_ ## name,
#define XSM_HOOK1(rtype, name, ...) XSM_HOOK0(rtype, name)
#define XSM_HOOK2(rtype, name, ...) XSM_HOOK0(rtype, name)
#define XSM_HOOK3(rtype, name, ...) XSM_HOOK0(rtype, name)
#define XSM_HOOK4(rtype, name, ...) XSM_HOOK0(rtype, name)
#define XSM_HOOK5(rtype, name, ...) XSM_HOOK0(rtype, name)

#include <xsm/hooks.h>

    .evtchn_close_post             = xsm_evtchn_close_post,

    .alloc_security_domain         = xsm_alloc_security_domain,
    .free_security_domain          = xsm_free_security_domain,
    .alloc_security_evtchns        = xsm_alloc_security_evtchns,
    .free_security_evtchns         = xsm_free_security_evtchns,
    .show_security_evtchn          = xsm_show_security_evtchn,

    .show_irq_sid                  = xsm_show_irq_sid,

    .do_xsm_op                     = xsm_do_xsm_op,
#ifdef CONFIG_COMPAT
    .do_compat_op                  = xsm_do_compat_op,
#endif

#ifdef CONFIG_ARGO
    .argo_enable                   = xsm_argo_enable,
    .argo_register_single_source   = xsm_argo_register_single_source,
    .argo_register_any_source      = xsm_argo_register_any_source,
    .argo_send                     = xsm_argo_send,
#endif
};

void __init xsm_fixup_ops(struct xsm_ops *ops)
{
    /*
     * We make some simplifying assumptions about struct xsm_ops; that it is
     * made exclusively of function pointers to non-init text.
     *
     * This allows us to walk over struct xsm_ops as if it were an array of
     * unsigned longs.
     */
    unsigned long *dst = _p(ops);
    const unsigned long *src = _p(&dummy_ops);

    for ( ; dst < (unsigned long *)(ops + 1); src++, dst++ )
    {
        /*
         * If you encounter this BUG(), then you've most likely added a new
         * XSM hook but failed to provide the default implementation in
         * dummy_ops.
         *
         * If not, then perhaps a function pointer to an init function, or
         * something which isn't a function pointer at all.
         */
        BUG_ON(!is_kernel_text(*src));

        if ( !*dst )
            *dst = *src;
    }
}
