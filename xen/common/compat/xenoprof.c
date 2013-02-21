/*
 * compat/xenoprof.c
 */

#include <compat/xenoprof.h>

#define COMPAT
#define ret_t int

#define do_xenoprof_op compat_xenoprof_op

#define xen_oprof_init xenoprof_init
CHECK_oprof_init;
#undef xen_oprof_init

#define xenoprof_get_buffer compat_oprof_get_buffer
#define xenoprof_op_get_buffer compat_oprof_op_get_buffer
#define xenoprof_arch_counter compat_oprof_arch_counter

#define xen_domid_t domid_t
#define compat_domid_t domid_compat_t
CHECK_TYPE(domid);
#undef compat_domid_t
#undef xen_domid_t

#define xen_oprof_passive xenoprof_passive
CHECK_oprof_passive;
#undef xen_oprof_passive

#define xenoprof_counter compat_oprof_counter

#include "../xenoprof.c"

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
