/******************************************************************************
 * multicall.c
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/multicall.h>

#define COMPAT
typedef int ret_t;
#undef do_multicall_call

static inline void xlat_multicall_entry(struct mc_state *mcs)
{
    int i;
    for (i=0; i<6; i++)
        mcs->compat_call.args[i] = mcs->call.args[i];
}

DEFINE_XEN_GUEST_HANDLE(multicall_entry_compat_t);
#define multicall_entry      compat_multicall_entry
#define multicall_entry_t    multicall_entry_compat_t
#define do_multicall_call    compat_multicall_call
#define call                 compat_call
#define do_multicall(l, n)   compat_multicall(_##l, n)
#define _XEN_GUEST_HANDLE(t) XEN_GUEST_HANDLE(t)

#include "../multicall.c"

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
