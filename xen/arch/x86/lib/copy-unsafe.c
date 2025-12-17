/*
 * "Unsafe" access functions.
 */

#include <asm/uaccess.h>

#define GUARD UA_DROP
#define copy_to_guest_ll copy_to_unsafe_ll
#define copy_from_guest_ll copy_from_unsafe_ll
#undef __user
#define __user
#include "copy-guest.c"

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
