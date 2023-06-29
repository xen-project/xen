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
#define X86_VENDOR_INTEL_EBX _AC(0x756e6547, U) /* "GenuineIntel" */
#define X86_VENDOR_INTEL_ECX _AC(0x6c65746e, U)
#define X86_VENDOR_INTEL_EDX _AC(0x49656e69, U)

#define X86_VENDOR_AMD (1 << 1)
#define X86_VENDOR_AMD_EBX _AC(0x68747541, U) /* "AuthenticAMD" */
#define X86_VENDOR_AMD_ECX _AC(0x444d4163, U)
#define X86_VENDOR_AMD_EDX _AC(0x69746e65, U)

#define X86_VENDOR_CENTAUR (1 << 2)
#define X86_VENDOR_CENTAUR_EBX _AC(0x746e6543, U) /* "CentaurHauls" */
#define X86_VENDOR_CENTAUR_ECX _AC(0x736c7561, U)
#define X86_VENDOR_CENTAUR_EDX _AC(0x48727561, U)

#define X86_VENDOR_SHANGHAI (1 << 3)
#define X86_VENDOR_SHANGHAI_EBX _AC(0x68532020, U) /* "  Shanghai  " */
#define X86_VENDOR_SHANGHAI_ECX _AC(0x20206961, U)
#define X86_VENDOR_SHANGHAI_EDX _AC(0x68676e61, U)

#define X86_VENDOR_HYGON (1 << 4)
#define X86_VENDOR_HYGON_EBX _AC(0x6f677948, U) /* "HygonGenuine" */
#define X86_VENDOR_HYGON_ECX _AC(0x656e6975, U)
#define X86_VENDOR_HYGON_EDX _AC(0x6e65476e, U)

#endif	/* __XEN_X86_VENDORS_H__ */
