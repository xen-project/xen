#ifndef __XEN_X86_VENDORS_H__
#define __XEN_X86_VENDORS_H__

/*
 * CPU vendor IDs
 *
 * - X86_VENDOR_* are Xen-internal identifiers.  Values and order are
 *   arbitrary.
 * - X86_VENDOR_*_E?X are architectural information from CPUID leaf 0
 */
#define X86_VENDOR_UNKNOWN 0

#define X86_VENDOR_INTEL 1
#define X86_VENDOR_INTEL_EBX 0x756e6547U /* "GenuineIntel" */
#define X86_VENDOR_INTEL_ECX 0x6c65746eU
#define X86_VENDOR_INTEL_EDX 0x49656e69U

#define X86_VENDOR_AMD 2
#define X86_VENDOR_AMD_EBX 0x68747541U /* "AuthenticAMD" */
#define X86_VENDOR_AMD_ECX 0x444d4163U
#define X86_VENDOR_AMD_EDX 0x69746e65U

#define X86_VENDOR_CENTAUR 3
#define X86_VENDOR_CENTAUR_EBX 0x746e6543U /* "CentaurHauls" */
#define X86_VENDOR_CENTAUR_ECX 0x736c7561U
#define X86_VENDOR_CENTAUR_EDX 0x48727561U

#define X86_VENDOR_SHANGHAI 4
#define X86_VENDOR_SHANGHAI_EBX 0x68532020U /* "  Shanghai  " */
#define X86_VENDOR_SHANGHAI_ECX 0x20206961U
#define X86_VENDOR_SHANGHAI_EDX 0x68676e61U

#define X86_VENDOR_NUM 5

#endif	/* __XEN_X86_VENDORS_H__ */
