#include <xen/guest_access.h>
#include <compat/platform.h>

#define efi_get_info efi_compat_get_info
#define xenpf_efi_info compat_pf_efi_info

#define COMPAT
#undef DEFINE_XEN_GUEST_HANDLE
#define DEFINE_XEN_GUEST_HANDLE DEFINE_COMPAT_HANDLE
#undef guest_handle_okay
#define guest_handle_okay compat_handle_okay
#undef guest_handle_cast
#define guest_handle_cast compat_handle_cast
#undef __copy_to_guest_offset
#define __copy_to_guest_offset __copy_to_compat_offset
#include "runtime.c"
