#ifndef _I386_REGS_H
#define _I386_REGS_H

struct xen_regs {
	long ebx;
	long ecx;
	long edx;
	long esi;
	long edi;
	long ebp;
	long eax;
	int  xds;
	int  xes;
	int  xfs;
	int  xgs;
	long orig_eax;
	long eip;
	int  xcs;
	long eflags;
	long esp;
	int  xss;
};

enum EFLAGS {
        EF_CF   = 0x00000001,
        EF_PF   = 0x00000004,
        EF_AF   = 0x00000010,
        EF_ZF   = 0x00000040,
        EF_SF   = 0x00000080,
        EF_TF   = 0x00000100,
        EF_IE   = 0x00000200,
        EF_DF   = 0x00000400,
        EF_OF   = 0x00000800,
        EF_IOPL = 0x00003000,
        EF_IOPL_RING0 = 0x00000000,
        EF_IOPL_RING1 = 0x00001000,
        EF_IOPL_RING2 = 0x00002000,
        EF_NT   = 0x00004000,   /* nested task */
        EF_RF   = 0x00010000,   /* resume */
        EF_VM   = 0x00020000,   /* virtual mode */
        EF_AC   = 0x00040000,   /* alignment */
        EF_VIF  = 0x00080000,   /* virtual interrupt */
        EF_VIP  = 0x00100000,   /* virtual interrupt pending */
        EF_ID   = 0x00200000,   /* id */
};

#endif
