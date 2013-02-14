/*
 *  This code maintains a list of active profiling data structures.
 *
 *    Copyright IBM Corp. 2009
 *    Author(s): Peter Oberparleiter <oberpar@linux.vnet.ibm.com>
 *
 *    Uses gcc-internal data definitions.
 *    Based on the gcov-kernel patch by:
 *       Hubertus Franke <frankeh@us.ibm.com>
 *       Nigel Hinds <nhinds@us.ibm.com>
 *       Rajan Ravindran <rajancr@us.ibm.com>
 *       Peter Oberparleiter <oberpar@linux.vnet.ibm.com>
 *       Paul Larson
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/hypercall.h>
#include <xen/gcov.h>
#include <xen/errno.h>

static struct gcov_info *info_list;

/*
 * __gcov_init is called by gcc-generated constructor code for each object
 * file compiled with -fprofile-arcs.
 *
 * Although this function is called only during initialization is called from
 * a .text section which is still present after initialization so not declare
 * as __init.
 */
void __gcov_init(struct gcov_info *info)
{
    /* add new profiling data structure to list */
    info->next = info_list;
    info_list = info;
}

/*
 * These functions may be referenced by gcc-generated profiling code but serve
 * no function for Xen.
 */
void __gcov_flush(void)
{
    /* Unused. */
}

void __gcov_merge_add(gcov_type *counters, unsigned int n_counters)
{
    /* Unused. */
}

void __gcov_merge_single(gcov_type *counters, unsigned int n_counters)
{
    /* Unused. */
}

void __gcov_merge_delta(gcov_type *counters, unsigned int n_counters)
{
    /* Unused. */
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
