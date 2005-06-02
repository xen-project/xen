
#ifndef __ARCH_LDT_H
#define __ARCH_LDT_H

#ifndef __ASSEMBLY__

static inline void load_LDT(struct vcpu *v)
{
    unsigned int cpu;
    struct desc_struct *desc;
    unsigned long ents;

    if ( (ents = v->arch.guest_context.ldt_ents) == 0 )
    {
        __asm__ __volatile__ ( "lldt %%ax" : : "a" (0) );
    }
    else
    {
        cpu = smp_processor_id();
        desc = gdt_table + __LDT(cpu) - FIRST_RESERVED_GDT_ENTRY;
        desc->a = ((LDT_VIRT_START(v)&0xffff)<<16) | (ents*8-1);
        desc->b = (LDT_VIRT_START(v)&(0xff<<24)) | 0x8200 |
            ((LDT_VIRT_START(v)&0xff0000)>>16);
        __asm__ __volatile__ ( "lldt %%ax" : : "a" (__LDT(cpu)<<3) );
    }
}

#endif /* !__ASSEMBLY__ */

#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
