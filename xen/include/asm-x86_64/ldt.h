#ifndef __ARCH_LDT_H
#define __ARCH_LDT_H

#ifndef __ASSEMBLY__

static inline void load_LDT(struct task_struct *p)
{
    unsigned long ents;

    if ( (ents = p->mm.ldt_ents) == 0 )
    {
        __asm__ __volatile__ ( "lldt %%rax" : : "a" (0) );
    }
    else
    {
	unsigned int cpu;
	struct ldttss_desc *desc;

        cpu = smp_processor_id();
        desc = (struct desc_struct *)((char *)GET_GDT_ADDRESS(p) + __CPU_DESC_INDEX(cpu, ldt));
	desc->limit0 = ents*8-1;
	desc->base0 = LDT_VIRT_START&0xffff;
	desc->base1 = (LDT_VIRT_START&0xff0000)>>16;
	desc->type = DESC_LDT;
	desc->dpl = 0;
	desc->p = 1;
	desc->limit = 0;
	desc->zero0 = 0;
	desc->g = 0;
	desc->base2 = (LDT_VIRST_START&0xff000000)>>24;
	desc->base3 = LDT_VIRT_START>>32;
	desc->zero1 = 0;
	__load_LDT(cpu);
    }
}

#endif /* !__ASSEMBLY__ */

#endif
