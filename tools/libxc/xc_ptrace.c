#include <sys/ptrace.h>
#include <sys/wait.h>
#include "xc_private.h"
#include <asm/elf.h>
#include <time.h>


#define BSD_PAGE_MASK	(PAGE_SIZE-1)
#define	PG_FRAME	(~((unsigned long)BSD_PAGE_MASK)
#define PDRSHIFT        22
#define	PSL_T		0x00000100	/* trace enable bit */


/*
 * long  
 * ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
 */

long xc_ptrace(enum __ptrace_request request, 
	       pid_t pid, void *addr, void *data);
int waitdomain(int domain, int *status, int options);

char * ptrace_names[] = {
    "PTRACE_TRACEME",
    "PTRACE_PEEKTEXT",
    "PTRACE_PEEKDATA",
    "PTRACE_PEEKUSER",
    "PTRACE_POKETEXT",
    "PTRACE_POKEDATA",
    "PTRACE_POKEUSER",
    "PTRACE_CONT",
    "PTRACE_KILL",
    "PTRACE_SINGLESTEP",
    "PTRACE_INVALID",
    "PTRACE_INVALID",
    "PTRACE_GETREGS",
    "PTRACE_SETREGS",
    "PTRACE_GETFPREGS",
    "PTRACE_SETFPREGS",
    "PTRACE_ATTACH",
    "PTRACE_DETACH",
    "PTRACE_GETFPXREGS",
    "PTRACE_SETFPXREGS",
    "PTRACE_INVALID",
    "PTRACE_INVALID",
    "PTRACE_INVALID",
    "PTRACE_INVALID",
    "PTRACE_SYSCALL",
};

struct gdb_regs {
        long ebx; /* 0 */
        long ecx; /* 4 */
        long edx; /* 8 */
        long esi; /* 12 */
        long edi; /* 16 */
        long ebp; /* 20 */
        long eax; /* 24 */ 
        int  xds; /* 28 */
        int  xes; /* 32 */
	int  xfs; /* 36 */
	int  xgs; /* 40 */
	long orig_eax; /* 44 */
        long eip;    /* 48 */
        int  xcs;    /* 52 */
        long eflags; /* 56 */
        long esp;    /* 60 */     
	int  xss;    /* 64 */
};
#define printval(x) printf("%s = %lx\n", #x, (long)x);
#define SET_PT_REGS(pt, xc) \
{ \
pt.ebx = xc.ebx; \
pt.ecx = xc.ecx; \
pt.edx = xc.edx; \
pt.esi = xc.esi; \
pt.edi = xc.edi; \
pt.ebp = xc.ebp; \
pt.eax = xc.eax; \
pt.eip = xc.eip; \
pt.xcs = xc.cs; \
pt.eflags = xc.eflags; \
pt.esp = xc.esp; \
pt.xss = xc.ss; \
pt.xes = xc.es; \
pt.xds = xc.ds; \
pt.xfs = xc.fs; \
pt.xgs = xc.gs; \
}

#define SET_XC_REGS(pt, xc) \
{ \
xc.ebx = pt->ebx; \
xc.ecx = pt->ecx; \
xc.edx = pt->edx; \
xc.esi = pt->esi; \
xc.edi = pt->edi; \
xc.ebp = pt->ebp; \
xc.eax = pt->eax; \
xc.eip = pt->eip; \
xc.cs = pt->xcs; \
xc.eflags = pt->eflags; \
xc.esp = pt->esp; \
xc.ss = pt->xss; \
xc.es = pt->xes; \
xc.ds = pt->xds; \
xc.fs = pt->xfs; \
xc.gs = pt->xgs; \
}


#define vtopdi(va) ((va) >> PDRSHIFT)
#define vtopti(va) (((va) >> PAGE_SHIFT) & BSD_PAGE_MASK)

/* XXX application state */


static int xc_handle;
static int regs_valid;
static unsigned long cr3;
static full_execution_context_t ctxt;

/* --------------------- */

static void *
map_domain_va(unsigned long domid, void * guest_va)
{
    unsigned long pde, page;
    unsigned long va = (unsigned long)guest_va;

    static unsigned long cr3_phys;
    static unsigned long *cr3_virt;
    static unsigned long pde_phys;
    static unsigned long *pde_virt;
    static unsigned long page_phys;
    static unsigned long *page_virt;

    if (cr3 != cr3_phys) 
    {
	cr3_phys = cr3;
	if (cr3_virt)
	    munmap(cr3_virt, PAGE_SIZE);
	if ((cr3_virt = xc_map_foreign_range(xc_handle, domid, PAGE_SIZE,
					     PROT_READ,
					     cr3_phys >> PAGE_SHIFT)) == NULL)
	    goto error_out;
    } 
    pde = cr3_virt[vtopdi(va)];
    if (pde != pde_phys) 
    {
	pde_phys = pde;
	if (pde_virt)
	    munmap(pde_virt, PAGE_SIZE);
	if ((pde_virt = xc_map_foreign_range(xc_handle, domid, PAGE_SIZE,
					     PROT_READ,
					     pde_phys >> PAGE_SHIFT)) == NULL)
	    goto error_out;
    }
    page = pde_virt[vtopti(va)];
    if (page != page_phys) 
    {
	page_phys = page;
	if (page_virt)
	    munmap(page_virt, PAGE_SIZE);
	if ((page_virt = xc_map_foreign_range(xc_handle, domid, PAGE_SIZE,
					     PROT_READ|PROT_WRITE,
					     page_phys >> PAGE_SHIFT)) == NULL)
	    goto error_out;
    }	
    return (void *)(((unsigned long)page_virt) | (va & BSD_PAGE_MASK));

 error_out:
    return 0;
}

int 
waitdomain(int domain, int *status, int options)
{
    dom0_op_t op;
    int retval;
    full_execution_context_t ctxt;
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 10*1000*1000;

    if (!xc_handle)
	if ((xc_handle = xc_interface_open()) < 0) 
	{
	    printf("xc_interface_open failed\n");
	    return -1;
	}
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = domain;
    op.u.getdomaininfo.exec_domain = 0;
    op.u.getdomaininfo.ctxt = &ctxt;
 retry:

    retval = do_dom0_op(xc_handle, &op);
    if (retval) {
	printf("getdomaininfo failed\n");
	goto done;
    }
    *status = op.u.getdomaininfo.flags;
    
    if (options & WNOHANG)
	goto done;
	

    if (!(op.u.getdomaininfo.flags & DOMFLAGS_PAUSED)) {	
	nanosleep(&ts,NULL);
	goto retry;
    }
 done:
    return retval;

}

long
xc_ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data)
{
    dom0_op_t op;
    int status = 0;
    xc_domaininfo_t info;
    struct gdb_regs pt;
    long retval = 0;
    long *guest_va;

    op.interface_version = DOM0_INTERFACE_VERSION;
    
    if (!xc_handle)
	if ((xc_handle = xc_interface_open()) < 0)
	    return -1;
#if 0
    printf("%20s %d, %p, %p \n", ptrace_names[request], pid, addr, data);
#endif
    switch (request) {	
    case PTRACE_PEEKTEXT:
    case PTRACE_PEEKDATA:
    case PTRACE_POKETEXT:
    case PTRACE_POKEDATA:
	if ((guest_va = (unsigned long *)map_domain_va(pid, addr)) == NULL)
	    goto done;

	if (request == PTRACE_PEEKTEXT || request == PTRACE_PEEKDATA)
	    retval = *guest_va;
	else
	    *guest_va = (unsigned long)data;
	break;
    case PTRACE_GETREGS:
    case PTRACE_GETFPREGS:
    case PTRACE_GETFPXREGS:
	/* XXX hard-coding UP */
	retval = xc_domain_getfullinfo(xc_handle, pid, 0, &info, &ctxt);

	if (retval) {
	    printf("getfullinfo failed\n");
	    goto done;
	}
	if (request == PTRACE_GETREGS) {
		SET_PT_REGS(pt, ctxt.cpu_ctxt); 
		memcpy(data, &pt, sizeof(elf_gregset_t));
	} else if (request == PTRACE_GETFPREGS)
	    memcpy(data, &ctxt.fpu_ctxt, sizeof(elf_fpregset_t));
	else /*if (request == PTRACE_GETFPXREGS)*/
	    memcpy(data, &ctxt.fpu_ctxt, sizeof(elf_fpxregset_t));
	cr3 = ctxt.pt_base;
	regs_valid = 1;
	break;
    case PTRACE_SETREGS:
	op.cmd = DOM0_SETDOMAININFO;
	SET_XC_REGS(((struct gdb_regs *)data), ctxt.cpu_ctxt);
	op.u.setdomaininfo.domain = pid;
	/* XXX need to understand multiple exec_domains */
	op.u.setdomaininfo.exec_domain = 0;
	op.u.setdomaininfo.ctxt = &ctxt;
	retval = do_dom0_op(xc_handle, &op);
	if (retval)
	    goto done;

	break;
    case PTRACE_ATTACH:
	op.cmd = DOM0_GETDOMAININFO;
	op.u.getdomaininfo.domain = pid;
	op.u.getdomaininfo.exec_domain = 0;
	op.u.getdomaininfo.ctxt = &ctxt;
	retval = do_dom0_op(xc_handle, &op);
	if (retval) {
	    perror("dom0 op failed");
	    goto done;
	}
	if (op.u.getdomaininfo.flags & DOMFLAGS_PAUSED) {
	    printf("domain currently paused\n");
	    goto done;
	}
	printf("domain not currently paused\n");
	op.cmd = DOM0_PAUSEDOMAIN;
	op.u.pausedomain.domain = pid;
	retval = do_dom0_op(xc_handle, &op);
	break;
    case PTRACE_SINGLESTEP:
	ctxt.cpu_ctxt.eflags |= PSL_T;
	op.cmd = DOM0_SETDOMAININFO;
	op.u.setdomaininfo.domain = pid;
	op.u.setdomaininfo.exec_domain = 0;
	op.u.setdomaininfo.ctxt = &ctxt;
	retval = do_dom0_op(xc_handle, &op);	
	if (retval) {
	    perror("dom0 op failed");
	    goto done;
	}
    case PTRACE_CONT:
    case PTRACE_DETACH:
	regs_valid = 0;
	op.cmd = DOM0_UNPAUSEDOMAIN;
	op.u.unpausedomain.domain = pid > 0 ? pid : -pid;
	retval = do_dom0_op(xc_handle, &op);
	break;
    case PTRACE_SETFPREGS:
    case PTRACE_SETFPXREGS:
    case PTRACE_PEEKUSER:
    case PTRACE_POKEUSER:
    case PTRACE_SYSCALL:
    case PTRACE_KILL:
#ifdef DEBUG
	printf("unsupported xc_ptrace request %s\n", ptrace_names[request]);
#endif
	/* XXX not yet supported */
	status = ENOSYS;
	break;
    case PTRACE_TRACEME:
	printf("PTRACE_TRACEME is an invalid request under Xen\n");
	status = EINVAL;
    }
    
    if (status) {
	errno = status;
	retval = -1;
    }
 done:
    return retval;
}
