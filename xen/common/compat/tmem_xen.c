/******************************************************************************
 * tmem_xen.c
 *
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <compat/tmem.h>

#define xen_tmem_op tmem_op
/*CHECK_tmem_op;*/
#undef xen_tmem_op

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
