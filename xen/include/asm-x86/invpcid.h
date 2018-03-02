#ifndef _ASM_X86_INVPCID_H_
#define _ASM_X86_INVPCID_H_

#include <xen/types.h>

#define INVPCID_TYPE_INDIV_ADDR      0
#define INVPCID_TYPE_SINGLE_CTXT     1
#define INVPCID_TYPE_ALL_INCL_GLOBAL 2
#define INVPCID_TYPE_ALL_NON_GLOBAL  3

#define INVPCID_OPCODE ".byte 0x66, 0x0f, 0x38, 0x82\n"
#define MODRM_ECX_01   ".byte 0x01\n"

static inline void invpcid(unsigned int pcid, unsigned long addr,
                           unsigned int type)
{
    struct {
        uint64_t pcid:12;
        uint64_t reserved:52;
        uint64_t addr;
    } desc = { .pcid = pcid, .addr = addr };

    asm volatile (
#ifdef HAVE_AS_INVPCID
                  "invpcid %[desc], %q[type]"
                  : /* No output */
                  : [desc] "m" (desc), [type] "r" (type)
#else
                  INVPCID_OPCODE MODRM_ECX_01
                  : /* No output */
                  : "a" (type), "c" (&desc)
#endif
                  : "memory" );
}

/* Flush all mappings for a given PCID and addr, not including globals */
static inline void invpcid_flush_one(unsigned int pcid, unsigned long addr)
{
    invpcid(pcid, addr, INVPCID_TYPE_INDIV_ADDR);
}

/* Flush all mappings for a given PCID, not including globals */
static inline void invpcid_flush_single_context(unsigned int pcid)
{
    invpcid(pcid, 0, INVPCID_TYPE_SINGLE_CTXT);
}

/* Flush all mappings, including globals, for all PCIDs */
static inline void invpcid_flush_all(void)
{
    invpcid(0, 0, INVPCID_TYPE_ALL_INCL_GLOBAL);
}

/* Flush all mappings for all PCIDs, excluding globals */
static inline void invpcid_flush_all_nonglobals(void)
{
    invpcid(0, 0, INVPCID_TYPE_ALL_NON_GLOBAL);
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
