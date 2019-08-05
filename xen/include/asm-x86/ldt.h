
#ifndef __ARCH_LDT_H
#define __ARCH_LDT_H

#ifndef __ASSEMBLY__

static inline void load_LDT(struct vcpu *v)
{
    seg_desc_t *desc;
    unsigned long ents;

    if ( (ents = v->arch.pv.ldt_ents) == 0 )
        lldt(0);
    else
    {
        desc = (!is_pv_32bit_vcpu(v) ? this_cpu(gdt) : this_cpu(compat_gdt))
               + LDT_ENTRY - FIRST_RESERVED_GDT_ENTRY;
        _set_tssldt_desc(desc, LDT_VIRT_START(v), ents*8-1, SYS_DESC_ldt);
        lldt(LDT_ENTRY << 3);
    }
}

#endif /* !__ASSEMBLY__ */

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
