/*
 * compat/kexec.c
 */

#include <compat/kexec.h>

#define COMPAT

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
