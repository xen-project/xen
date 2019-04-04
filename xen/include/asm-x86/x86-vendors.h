#ifndef __XEN_X86_VENDORS_H__
#define __XEN_X86_VENDORS_H__

/*
 * CPU vendor IDs
 *
 * - X86_VENDOR_* are Xen-internal identifiers.  The order is arbitrary, but
 *   values form a bitmap so vendor checks can be made against multiple
 *   vendors at once.
 * - X86_VENDOR_*_E?X are architectural information from CPUID leaf 0
 */
#define X86_VENDOR_UNKNOWN 0

#define X86_VENDOR_INTEL (1 << 0)
#define X86_VENDOR_INTEL_EBX 0x756e6547U /* "GenuineIntel" */
#define X86_VENDOR_INTEL_ECX 0x6c65746eU
#define X86_VENDOR_INTEL_EDX 0x49656e69U

#define X86_VENDOR_AMD (1 << 1)
#define X86_VENDOR_AMD_EBX 0x68747541U /* "AuthenticAMD" */
#define X86_VENDOR_AMD_ECX 0x444d4163U
#define X86_VENDOR_AMD_EDX 0x69746e65U

#define X86_VENDOR_CENTAUR (1 << 2)
#define X86_VENDOR_CENTAUR_EBX 0x746e6543U /* "CentaurHauls" */
#define X86_VENDOR_CENTAUR_ECX 0x736c7561U
#define X86_VENDOR_CENTAUR_EDX 0x48727561U

#define X86_VENDOR_SHANGHAI (1 << 3)
#define X86_VENDOR_SHANGHAI_EBX 0x68532020U /* "  Shanghai  " */
#define X86_VENDOR_SHANGHAI_ECX 0x20206961U
#define X86_VENDOR_SHANGHAI_EDX 0x68676e61U

#define X86_VENDOR_HYGON (1 << 4)
#define X86_VENDOR_HYGON_EBX 0x6f677948U /* "HygonGenuine" */
#define X86_VENDOR_HYGON_ECX 0x656e6975U
#define X86_VENDOR_HYGON_EDX 0x6e65476eU

#endif	/* __XEN_X86_VENDORS_H__ */
