#ifndef __ARCH_LDT_H
#define __ARCH_LDT_H

#ifndef __ASSEMBLY__

static inline void load_LDT(struct exec_domain *p)
{
    unsigned int cpu;
    struct desc_struct *desc;
    unsigned long ents;
                                                                                                
    if ( (ents = p->mm.ldt_ents) == 0 )
    {
        __asm__ __volatile__ ( "lldt %%ax" : : "a" (0) );
    }
    else
    {
        cpu = smp_processor_id();
        desc = (struct desc_struct *)GET_GDT_ADDRESS(p) + __LDT(cpu);
        desc->a = ((LDT_VIRT_START(p)&0xffff)<<16) | (ents*8-1);
        desc->b = (LDT_VIRT_START(p)&(0xff<<24)) | 0x8200 |
            ((LDT_VIRT_START(p)&0xff0000)>>16);
        __asm__ __volatile__ ( "lldt %%ax" : : "a" (__LDT(cpu)<<3) );
    }
}

#endif /* !__ASSEMBLY__ */

#endif
