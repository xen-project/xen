/******************************************************************************
 * compat/acm_ops.c
 */

#include <compat/acm.h>
#include <compat/acm_ops.h>

#define COMPAT
#define ret_t int

#define do_acm_op compat_acm_op

static inline XEN_GUEST_HANDLE(void) acm_xlat_handle(COMPAT_HANDLE(void) cmp)
{
    XEN_GUEST_HANDLE(void) nat;

    guest_from_compat_handle(nat, cmp);
    return nat;
}

#define acm_setpolicy compat_acm_setpolicy
#define acm_set_policy(h, sz) acm_set_policy(acm_xlat_handle(h), sz)

#define acm_getpolicy compat_acm_getpolicy
#define acm_get_policy(h, sz) acm_get_policy(acm_xlat_handle(h), sz)

#define acm_dumpstats compat_acm_dumpstats
#define acm_dump_statistics(h, sz) acm_dump_statistics(acm_xlat_handle(h), sz)

#define acm_getssid compat_acm_getssid
#define acm_get_ssid(r, h, sz) acm_get_ssid(r, acm_xlat_handle(h), sz)

#define xen_acm_getdecision acm_getdecision
CHECK_acm_getdecision;
#undef xen_acm_getdecision

#include "../acm_ops.c"

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
