/*
 * compat/kexec.c
 */

#include <compat/kexec.h>

#define COMPAT
#define ret_t int

#define do_kexec_op compat_kexec_op

#define kexec_load_unload compat_kexec_load_unload
#define xen_kexec_load    compat_kexec_load
#define xen_kexec_load_t  compat_kexec_load_t

CHECK_kexec_exec;

#include "../kexec.c"

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
