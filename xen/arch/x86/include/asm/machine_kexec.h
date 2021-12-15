#ifndef __X86_MACHINE_KEXEC_H__
#define __X86_MACHINE_KEXEC_H__

#define KEXEC_RELOC_FLAG_COMPAT 0x1 /* 32-bit image */

#ifndef __ASSEMBLY__

extern void kexec_reloc(unsigned long reloc_code, unsigned long reloc_pt,
                        unsigned long ind_maddr, unsigned long entry_maddr,
                        unsigned long flags);

extern unsigned int kexec_reloc_size;

#endif

#endif /* __X86_MACHINE_KEXEC_H__ */
