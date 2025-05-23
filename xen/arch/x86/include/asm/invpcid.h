#ifndef _ASM_X86_INVPCID_H_
#define _ASM_X86_INVPCID_H_

#include <xen/types.h>

extern bool use_invpcid;

static inline void invpcid(unsigned int pcid, unsigned long addr,
                           unsigned int type)
{
    struct {
        uint64_t pcid:12;
        uint64_t reserved:52;
        uint64_t addr;
    } desc = { .pcid = pcid, .addr = addr };

    asm volatile ( "invpcid %[desc], %q[type]"
                   :
                   : [desc] "m" (desc), [type] "r" (type)
                   : "memory" );
}

/* Flush all mappings for a given PCID and addr, not including globals */
static inline void invpcid_flush_one(unsigned int pcid, unsigned long addr)
{
    invpcid(pcid, addr, X86_INVPCID_INDIV_ADDR);
}

/* Flush all mappings for a given PCID, not including globals */
static inline void invpcid_flush_single_context(unsigned int pcid)
{
    invpcid(pcid, 0, X86_INVPCID_SINGLE_CTXT);
}

/* Flush all mappings, including globals, for all PCIDs */
static inline void invpcid_flush_all(void)
{
    invpcid(0, 0, X86_INVPCID_ALL_INCL_GLOBAL);
}

/* Flush all mappings for all PCIDs, excluding globals */
static inline void invpcid_flush_all_nonglobals(void)
{
    invpcid(0, 0, X86_INVPCID_ALL_NON_GLOBAL);
}

#endif	/* _ASM_X86_INVPCID_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
