/*
 *  Default XSM hooks - IS_PRIV and IS_PRIV_FOR checks
 *
 *  Author: Daniel De Graaf <dgdegra@tyhco.nsa.gov>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 *
 *
 *  Each XSM hook implementing an access check should have its first parameter
 *  preceded by XSM_DEFAULT_ARG (or use XSM_DEFAULT_VOID if it has no
 *  arguments). The first non-declaration statement shold be XSM_ASSERT_ACTION
 *  with the expected type of the hook, which will either define or check the
 *  value of action.
 */

#include <xen/sched.h>
#include <xsm/xsm.h>

/* Cannot use BUILD_BUG_ON here because the expressions we check are not
 * considered constant at compile time. Instead, rely on constant propagation to
 * inline out the calls to this invalid function, which will cause linker errors
 * if references remain at link time.
 */
#define LINKER_BUG_ON(x) do { if (x) __xsm_action_mismatch_detected(); } while (0)

#if defined(CONFIG_COVERAGE) && defined(__clang__)
/*
 * LLVM coverage support seems to disable some of the optimizations needed in
 * order for XSM to compile. Since coverage should not be used in production
 * provide an implementation of __xsm_action_mismatch_detected to satisfy the
 * linker.
 */
static inline void __xsm_action_mismatch_detected(void)
{
    ASSERT_UNREACHABLE();
}
#else
/* DO NOT implement this function; it is supposed to trigger link errors */
void __xsm_action_mismatch_detected(void);
#endif

#ifdef CONFIG_XSM

/* In CONFIG_XSM builds, this header file is included from xsm/dummy.c, and
 * contains static (not inline) functions compiled to the dummy XSM module.
 * There is no xsm_default_t argument available, so the value from the assertion
 * is used to initialize the variable.
 */
#define XSM_INLINE __maybe_unused

#define XSM_DEFAULT_ARG /* */
#define XSM_DEFAULT_VOID void
#define XSM_ASSERT_ACTION(def) xsm_default_t action = def; (void)action

#else /* CONFIG_XSM */

/* In !CONFIG_XSM builds, this header file is included from xsm/xsm.h, and
 * contains inline functions for each XSM hook. These functions also perform
 * compile-time checks on the xsm_default_t argument to ensure that the behavior
 * of the dummy XSM module is the same as the behavior with XSM disabled.
 */
#define XSM_INLINE always_inline
#define XSM_DEFAULT_ARG xsm_default_t action,
#define XSM_DEFAULT_VOID xsm_default_t action
#define XSM_ASSERT_ACTION(def) LINKER_BUG_ON(def != action)

#endif /* CONFIG_XSM */

static always_inline int xsm_default_action(
    xsm_default_t action, struct domain *src, struct domain *target)
{
    switch ( action ) {
    case XSM_HOOK:
        return 0;
    case XSM_TARGET:
        if ( src == target )
        {
            return 0;
    case XSM_XS_PRIV:
            if ( is_xenstore_domain(src) )
                return 0;
        }
        /* fall through */
    case XSM_DM_PRIV:
        if ( target && src->target == target )
            return 0;
        /* fall through */
    case XSM_PRIV:
        if ( src->is_privileged )
            return 0;
        return -EPERM;
    default:
        LINKER_BUG_ON(1);
        return -EPERM;
    }
}

static XSM_INLINE void xsm_security_domaininfo(struct domain *d,
                                    struct xen_domctl_getdomaininfo *info)
{
    return;
}

static XSM_INLINE int xsm_domain_create(XSM_DEFAULT_ARG struct domain *d, u32 ssidref)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_getdomaininfo(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_domctl_scheduler_op(XSM_DEFAULT_ARG struct domain *d, int cmd)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_sysctl_scheduler_op(XSM_DEFAULT_ARG int cmd)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_set_target(XSM_DEFAULT_ARG struct domain *d, struct domain *e)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_domctl(XSM_DEFAULT_ARG struct domain *d, int cmd)
{
    XSM_ASSERT_ACTION(XSM_OTHER);
    switch ( cmd )
    {
    case XEN_DOMCTL_ioport_mapping:
    case XEN_DOMCTL_memory_mapping:
    case XEN_DOMCTL_bind_pt_irq:
    case XEN_DOMCTL_unbind_pt_irq:
        return xsm_default_action(XSM_DM_PRIV, current->domain, d);
    case XEN_DOMCTL_getdomaininfo:
        return xsm_default_action(XSM_XS_PRIV, current->domain, d);
    default:
        return xsm_default_action(XSM_PRIV, current->domain, d);
    }
}

static XSM_INLINE int xsm_sysctl(XSM_DEFAULT_ARG int cmd)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_readconsole(XSM_DEFAULT_ARG uint32_t clear)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_alloc_security_domain(struct domain *d)
{
    return 0;
}

static XSM_INLINE void xsm_free_security_domain(struct domain *d)
{
    return;
}

static XSM_INLINE int xsm_grant_mapref(XSM_DEFAULT_ARG struct domain *d1, struct domain *d2,
                                                                uint32_t flags)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, d1, d2);
}

static XSM_INLINE int xsm_grant_unmapref(XSM_DEFAULT_ARG struct domain *d1, struct domain *d2)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, d1, d2);
}

static XSM_INLINE int xsm_grant_setup(XSM_DEFAULT_ARG struct domain *d1, struct domain *d2)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, d1, d2);
}

static XSM_INLINE int xsm_grant_transfer(XSM_DEFAULT_ARG struct domain *d1, struct domain *d2)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, d1, d2);
}

static XSM_INLINE int xsm_grant_copy(XSM_DEFAULT_ARG struct domain *d1, struct domain *d2)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, d1, d2);
}

static XSM_INLINE int xsm_grant_query_size(XSM_DEFAULT_ARG struct domain *d1, struct domain *d2)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, d1, d2);
}

static XSM_INLINE int xsm_memory_exchange(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_memory_adjust_reservation(XSM_DEFAULT_ARG struct domain *d1,
                                                            struct domain *d2)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, d1, d2);
}

static XSM_INLINE int xsm_memory_stat_reservation(XSM_DEFAULT_ARG struct domain *d1, struct domain *d2)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, d1, d2);
}

static XSM_INLINE int xsm_console_io(XSM_DEFAULT_ARG struct domain *d, int cmd)
{
    XSM_ASSERT_ACTION(XSM_OTHER);
    if ( d->is_console )
        return xsm_default_action(XSM_HOOK, d, NULL);
#ifdef CONFIG_VERBOSE_DEBUG
    if ( cmd == CONSOLEIO_write )
        return xsm_default_action(XSM_HOOK, d, NULL);
#endif
    return xsm_default_action(XSM_PRIV, d, NULL);
}

static XSM_INLINE int xsm_profile(XSM_DEFAULT_ARG struct domain *d, int op)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, d, NULL);
}

static XSM_INLINE int xsm_kexec(XSM_DEFAULT_VOID)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_schedop_shutdown(XSM_DEFAULT_ARG struct domain *d1, struct domain *d2)
{
    XSM_ASSERT_ACTION(XSM_DM_PRIV);
    return xsm_default_action(action, d1, d2);
}

static XSM_INLINE int xsm_memory_pin_page(XSM_DEFAULT_ARG struct domain *d1, struct domain *d2,
                                          struct page_info *page)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, d1, d2);
}

static XSM_INLINE int xsm_claim_pages(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_evtchn_unbound(XSM_DEFAULT_ARG struct domain *d, struct evtchn *chn,
                                         domid_t id2)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_evtchn_interdomain(XSM_DEFAULT_ARG struct domain *d1, struct evtchn
                                *chan1, struct domain *d2, struct evtchn *chan2)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, d1, d2);
}

static XSM_INLINE void xsm_evtchn_close_post(struct evtchn *chn)
{
    return;
}

static XSM_INLINE int xsm_evtchn_send(XSM_DEFAULT_ARG struct domain *d, struct evtchn *chn)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, d, NULL);
}

static XSM_INLINE int xsm_evtchn_status(XSM_DEFAULT_ARG struct domain *d, struct evtchn *chn)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_evtchn_reset(XSM_DEFAULT_ARG struct domain *d1, struct domain *d2)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, d1, d2);
}

static XSM_INLINE int xsm_alloc_security_evtchn(struct evtchn *chn)
{
    return 0;
}

static XSM_INLINE void xsm_free_security_evtchn(struct evtchn *chn)
{
    return;
}

static XSM_INLINE char *xsm_show_security_evtchn(struct domain *d, const struct evtchn *chn)
{
    return NULL;
}

static XSM_INLINE int xsm_init_hardware_domain(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_get_pod_target(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_set_pod_target(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_get_vnumainfo(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, current->domain, d);
}

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_PCI)
static XSM_INLINE int xsm_get_device_group(XSM_DEFAULT_ARG uint32_t machine_bdf)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_assign_device(XSM_DEFAULT_ARG struct domain *d, uint32_t machine_bdf)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_deassign_device(XSM_DEFAULT_ARG struct domain *d, uint32_t machine_bdf)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

#endif /* HAS_PASSTHROUGH && HAS_PCI */

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_DEVICE_TREE)
static XSM_INLINE int xsm_assign_dtdevice(XSM_DEFAULT_ARG struct domain *d,
                                          const char *dtpath)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_deassign_dtdevice(XSM_DEFAULT_ARG struct domain *d,
                                            const char *dtpath)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

#endif /* HAS_PASSTHROUGH && HAS_DEVICE_TREE */

static XSM_INLINE int xsm_resource_plug_core(XSM_DEFAULT_VOID)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_resource_unplug_core(XSM_DEFAULT_VOID)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_resource_plug_pci(XSM_DEFAULT_ARG uint32_t machine_bdf)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_resource_unplug_pci(XSM_DEFAULT_ARG uint32_t machine_bdf)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_resource_setup_pci(XSM_DEFAULT_ARG uint32_t machine_bdf)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_resource_setup_gsi(XSM_DEFAULT_ARG int gsi)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_resource_setup_misc(XSM_DEFAULT_VOID)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_page_offline(XSM_DEFAULT_ARG uint32_t cmd)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE long xsm_do_xsm_op(XEN_GUEST_HANDLE_PARAM(xsm_op_t) op)
{
    return -ENOSYS;
}

#ifdef CONFIG_COMPAT
static XSM_INLINE int xsm_do_compat_op(XEN_GUEST_HANDLE_PARAM(xsm_op_t) op)
{
    return -ENOSYS;
}
#endif

static XSM_INLINE char *xsm_show_irq_sid(int irq)
{
    return NULL;
}

static XSM_INLINE int xsm_map_domain_pirq(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_DM_PRIV);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_map_domain_irq(XSM_DEFAULT_ARG struct domain *d,
                                         int irq, const void *data)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_unmap_domain_pirq(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_DM_PRIV);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_bind_pt_irq(XSM_DEFAULT_ARG struct domain *d, struct xen_domctl_bind_pt_irq *bind)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_unbind_pt_irq(XSM_DEFAULT_ARG struct domain *d, struct xen_domctl_bind_pt_irq *bind)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_unmap_domain_irq(XSM_DEFAULT_ARG struct domain *d,
                                           int irq, const void *data)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_irq_permission(XSM_DEFAULT_ARG struct domain *d, int pirq, uint8_t allow)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_iomem_permission(XSM_DEFAULT_ARG struct domain *d, uint64_t s, uint64_t e, uint8_t allow)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_iomem_mapping(XSM_DEFAULT_ARG struct domain *d, uint64_t s, uint64_t e, uint8_t allow)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_pci_config_permission(XSM_DEFAULT_ARG struct domain *d, uint32_t machine_bdf,
                                        uint16_t start, uint16_t end,
                                        uint8_t access)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_add_to_physmap(XSM_DEFAULT_ARG struct domain *d1, struct domain *d2)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, d1, d2);
}

static XSM_INLINE int xsm_remove_from_physmap(XSM_DEFAULT_ARG struct domain *d1, struct domain *d2)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, d1, d2);
}

static XSM_INLINE int xsm_map_gmfn_foreign(XSM_DEFAULT_ARG struct domain *d, struct domain *t)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, d, t);
}

static XSM_INLINE int xsm_hvm_param(XSM_DEFAULT_ARG struct domain *d, unsigned long op)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_hvm_control(XSM_DEFAULT_ARG struct domain *d, unsigned long op)
{
    XSM_ASSERT_ACTION(XSM_DM_PRIV);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_hvm_param_nested(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_hvm_param_altp2mhvm(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_hvm_altp2mhvm_op(XSM_DEFAULT_ARG struct domain *d, uint64_t mode, uint32_t op)
{
    XSM_ASSERT_ACTION(XSM_OTHER);

    switch ( mode )
    {
    case XEN_ALTP2M_mixed:
        return xsm_default_action(XSM_TARGET, current->domain, d);
    case XEN_ALTP2M_external:
        return xsm_default_action(XSM_DM_PRIV, current->domain, d);
    case XEN_ALTP2M_limited:
        if ( HVMOP_altp2m_vcpu_enable_notify == op )
            return xsm_default_action(XSM_TARGET, current->domain, d);
        return xsm_default_action(XSM_DM_PRIV, current->domain, d);
    default:
        return -EPERM;
    }
}

static XSM_INLINE int xsm_vm_event_control(XSM_DEFAULT_ARG struct domain *d, int mode, int op)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, d);
}

#ifdef CONFIG_MEM_ACCESS
static XSM_INLINE int xsm_mem_access(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_DM_PRIV);
    return xsm_default_action(action, current->domain, d);
}
#endif

#ifdef CONFIG_HAS_MEM_PAGING
static XSM_INLINE int xsm_mem_paging(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_DM_PRIV);
    return xsm_default_action(action, current->domain, d);
}
#endif

#ifdef CONFIG_MEM_SHARING
static XSM_INLINE int xsm_mem_sharing(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_DM_PRIV);
    return xsm_default_action(action, current->domain, d);
}
#endif

static XSM_INLINE int xsm_platform_op(XSM_DEFAULT_ARG uint32_t op)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, NULL);
}

#ifdef CONFIG_X86
static XSM_INLINE int xsm_do_mca(XSM_DEFAULT_VOID)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_shadow_control(XSM_DEFAULT_ARG struct domain *d, uint32_t op)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_mem_sharing_op(XSM_DEFAULT_ARG struct domain *d, struct domain *cd, int op)
{
    XSM_ASSERT_ACTION(XSM_DM_PRIV);
    return xsm_default_action(action, current->domain, cd);
}

static XSM_INLINE int xsm_apic(XSM_DEFAULT_ARG struct domain *d, int cmd)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, d, NULL);
}

static XSM_INLINE int xsm_machine_memory_map(XSM_DEFAULT_VOID)
{
    XSM_ASSERT_ACTION(XSM_PRIV);
    return xsm_default_action(action, current->domain, NULL);
}

static XSM_INLINE int xsm_domain_memory_map(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_mmu_update(XSM_DEFAULT_ARG struct domain *d, struct domain *t,
                                     struct domain *f, uint32_t flags)
{
    int rc = 0;
    XSM_ASSERT_ACTION(XSM_TARGET);
    if ( f != dom_io )
        rc = xsm_default_action(action, d, f);
    if ( t && !rc )
        rc = xsm_default_action(action, d, t);
    return rc;
}

static XSM_INLINE int xsm_mmuext_op(XSM_DEFAULT_ARG struct domain *d, struct domain *f)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, d, f);
}

static XSM_INLINE int xsm_update_va_mapping(XSM_DEFAULT_ARG struct domain *d, struct domain *f, 
                                                            l1_pgentry_t pte)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, d, f);
}

static XSM_INLINE int xsm_priv_mapping(XSM_DEFAULT_ARG struct domain *d, struct domain *t)
{
    XSM_ASSERT_ACTION(XSM_TARGET);
    return xsm_default_action(action, d, t);
}

static XSM_INLINE int xsm_ioport_permission(XSM_DEFAULT_ARG struct domain *d, uint32_t s, uint32_t e, uint8_t allow)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_ioport_mapping(XSM_DEFAULT_ARG struct domain *d, uint32_t s, uint32_t e, uint8_t allow)
{
    XSM_ASSERT_ACTION(XSM_HOOK);
    return xsm_default_action(action, current->domain, d);
}

static XSM_INLINE int xsm_pmu_op (XSM_DEFAULT_ARG struct domain *d, unsigned int op)
{
    XSM_ASSERT_ACTION(XSM_OTHER);
    switch ( op )
    {
    case XENPMU_init:
    case XENPMU_finish:
    case XENPMU_lvtpc_set:
    case XENPMU_flush:
        return xsm_default_action(XSM_HOOK, d, current->domain);
    default:
        return xsm_default_action(XSM_PRIV, d, current->domain);
    }
}

static XSM_INLINE int xsm_dm_op(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_DM_PRIV);
    return xsm_default_action(action, current->domain, d);
}

#endif /* CONFIG_X86 */

#ifdef CONFIG_ARGO
static XSM_INLINE int xsm_argo_enable(const struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_argo_register_single_source(const struct domain *d,
                                                      const struct domain *t)
{
    return 0;
}

static XSM_INLINE int xsm_argo_register_any_source(const struct domain *d)
{
    return 0;
}

static XSM_INLINE int xsm_argo_send(const struct domain *d,
                                    const struct domain *t)
{
    return 0;
}

#endif /* CONFIG_ARGO */

#include <public/version.h>
static XSM_INLINE int xsm_xen_version (XSM_DEFAULT_ARG uint32_t op)
{
    XSM_ASSERT_ACTION(XSM_OTHER);
    switch ( op )
    {
    case XENVER_version:
    case XENVER_platform_parameters:
    case XENVER_get_features:
        /* These sub-ops ignore the permission checks and return data. */
        return 0;
    case XENVER_extraversion:
    case XENVER_compile_info:
    case XENVER_capabilities:
    case XENVER_changeset:
    case XENVER_pagesize:
    case XENVER_guest_handle:
        /* These MUST always be accessible to any guest by default. */
        return xsm_default_action(XSM_HOOK, current->domain, NULL);
    default:
        return xsm_default_action(XSM_PRIV, current->domain, NULL);
    }
}

static XSM_INLINE int xsm_domain_resource_map(XSM_DEFAULT_ARG struct domain *d)
{
    XSM_ASSERT_ACTION(XSM_DM_PRIV);
    return xsm_default_action(action, current->domain, d);
}
