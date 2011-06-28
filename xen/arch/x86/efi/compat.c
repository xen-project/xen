#include <xen/guest_access.h>
#include <compat/platform.h>

#define efi_get_info efi_compat_get_info
#define xenpf_efi_info compat_pf_efi_info

#define efi_runtime_call efi_compat_runtime_call
#define xenpf_efi_runtime_call compat_pf_efi_runtime_call

#define xenpf_efi_guid compat_pf_efi_guid
#define xenpf_efi_time compat_pf_efi_time

#define COMPAT
#undef DEFINE_XEN_GUEST_HANDLE
#define DEFINE_XEN_GUEST_HANDLE DEFINE_COMPAT_HANDLE
#undef XEN_GUEST_HANDLE
#define XEN_GUEST_HANDLE COMPAT_HANDLE
#undef guest_handle_okay
#define guest_handle_okay compat_handle_okay
#undef guest_handle_cast
#define guest_handle_cast compat_handle_cast
#undef __copy_from_guest
#define __copy_from_guest __copy_from_compat
#undef copy_from_guest_offset
#define copy_from_guest_offset copy_from_compat_offset
#undef copy_to_guest
#define copy_to_guest copy_to_compat
#undef __copy_to_guest_offset
#define __copy_to_guest_offset __copy_to_compat_offset
#include "runtime.c"
