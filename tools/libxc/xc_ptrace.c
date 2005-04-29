#include <sys/ptrace.h>
#include <sys/wait.h>
#include "xc_private.h"
#include <asm/elf.h>
#include <time.h>


#define BSD_PAGE_MASK	(PAGE_SIZE-1)
#define	PG_FRAME	(~((unsigned long)BSD_PAGE_MASK)
#define PDRSHIFT        22
#define	PSL_T		0x00000100	/* trace enable bit */

#define VCPU            0               /* XXX */

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

#define FETCH_REGS(cpu) \
    if (!regs_valid[cpu]) \
    {                \
	int retval = xc_domain_getfullinfo(xc_handle, domid, cpu, NULL, &ctxt[cpu]); \
	if (retval) \
	    goto error_out; \
	cr3[cpu] = ctxt[cpu].pt_base; /* physical address */ \
	regs_valid[cpu] = 1; \
    } \

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
#define vtopti(va) (((va) >> PAGE_SHIFT) & 0x3ff)

/* XXX application state */


static int                      xc_handle;
static long			nr_pages = 0;
unsigned long			*page_array = NULL;
static int                      regs_valid[MAX_VIRT_CPUS];
static unsigned long            cr3[MAX_VIRT_CPUS];
static vcpu_guest_context_t ctxt[MAX_VIRT_CPUS];

/* --------------------- */

static void *
map_domain_va(unsigned long domid, int cpu, void * guest_va, int perm)
{
    unsigned long pde, page;
    unsigned long va = (unsigned long)guest_va;
    long npgs = xc_get_tot_pages(xc_handle, domid);

    static unsigned long  cr3_phys[MAX_VIRT_CPUS];
    static unsigned long *cr3_virt[MAX_VIRT_CPUS];
    static unsigned long  pde_phys[MAX_VIRT_CPUS];
    static unsigned long *pde_virt[MAX_VIRT_CPUS];
    static unsigned long  page_phys[MAX_VIRT_CPUS];
    static unsigned long *page_virt[MAX_VIRT_CPUS];
    
    static int            prev_perm[MAX_VIRT_CPUS];

    if (nr_pages != npgs) {
	if (nr_pages > 0)
	    free(page_array);
	nr_pages = npgs;
	if ((page_array = malloc(nr_pages * sizeof(unsigned long))) == NULL) {
	    printf("Could not allocate memory\n");
	    goto error_out;
	}

	if (xc_get_pfn_list(xc_handle, domid, page_array, nr_pages) != nr_pages) {
		printf("Could not get the page frame list\n");
		goto error_out;
	}
    }

    FETCH_REGS(cpu);

    if (cr3[cpu] != cr3_phys[cpu]) 
    {
	cr3_phys[cpu] = cr3[cpu];
	if (cr3_virt[cpu])
	    munmap(cr3_virt[cpu], PAGE_SIZE);
	if ((cr3_virt[cpu] = xc_map_foreign_range(xc_handle, domid, PAGE_SIZE,
					     PROT_READ,
					     cr3_phys[cpu] >> PAGE_SHIFT)) == NULL)
	    goto error_out;
    } 
    if ((pde = cr3_virt[cpu][vtopdi(va)]) == 0) /* logical address */
	goto error_out;
    pde = page_array[pde >> PAGE_SHIFT] << PAGE_SHIFT;
    if (pde != pde_phys[cpu]) 
    {
	pde_phys[cpu] = pde;
	if (pde_virt[cpu])
	    munmap(pde_virt[cpu], PAGE_SIZE);
	if ((pde_virt[cpu] = xc_map_foreign_range(xc_handle, domid, PAGE_SIZE,
					     PROT_READ,
					     pde_phys[cpu] >> PAGE_SHIFT)) == NULL)
	    goto error_out;
    }
    if ((page = pde_virt[cpu][vtopti(va)]) == 0) /* logical address */
	goto error_out;
    page = page_array[page >> PAGE_SHIFT] << PAGE_SHIFT;
    if (page != page_phys[cpu] || perm != prev_perm[cpu]) 
    {
	page_phys[cpu] = page;
	if (page_virt[cpu])
	    munmap(page_virt[cpu], PAGE_SIZE);
	if ((page_virt[cpu] = xc_map_foreign_range(xc_handle, domid, PAGE_SIZE,
					      perm,
					      page_phys[cpu] >> PAGE_SHIFT)) == NULL) {
	    printf("cr3 %lx pde %lx page %lx pti %lx\n", cr3[cpu], pde, page, vtopti(va));
	    page_phys[cpu] = 0;
	    goto error_out;
	}
	prev_perm[cpu] = perm;
    }	
    return (void *)(((unsigned long)page_virt[cpu]) | (va & BSD_PAGE_MASK));

 error_out:
    return 0;
}

int 
waitdomain(int domain, int *status, int options)
{
    dom0_op_t op;
    int retval;
    vcpu_guest_context_t ctxt;
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
xc_ptrace(enum __ptrace_request request, pid_t domid, void *addr, void *data)
{
    dom0_op_t       op;
    int             status = 0;
    struct gdb_regs pt;
    long            retval = 0;
    unsigned long  *guest_va;
    int             cpu = VCPU;

    op.interface_version = DOM0_INTERFACE_VERSION;
    
    if (!xc_handle)
	if ((xc_handle = xc_interface_open()) < 0)
	    return -1;
#if 0
    printf("%20s %d, %p, %p \n", ptrace_names[request], domid, addr, data);
#endif
    switch (request) {	
    case PTRACE_PEEKTEXT:
    case PTRACE_PEEKDATA:
	if ((guest_va = (unsigned long *)map_domain_va(domid, cpu, addr, PROT_READ)) == NULL) {
	    status = EFAULT;
	    goto error_out;
	}

	retval = *guest_va;
	break;
    case PTRACE_POKETEXT:
    case PTRACE_POKEDATA:
	if ((guest_va = (unsigned long *)map_domain_va(domid, cpu, addr, PROT_READ|PROT_WRITE)) == NULL) {
	    status = EFAULT;
	    goto error_out;
	}

	*guest_va = (unsigned long)data;
	break;
    case PTRACE_GETREGS:
    case PTRACE_GETFPREGS:
    case PTRACE_GETFPXREGS:
	FETCH_REGS(cpu);

	if (request == PTRACE_GETREGS) {
		SET_PT_REGS(pt, ctxt[cpu].user_regs); 
		memcpy(data, &pt, sizeof(elf_gregset_t));
	} else if (request == PTRACE_GETFPREGS)
	    memcpy(data, &ctxt[cpu].fpu_ctxt, sizeof(ctxt[cpu].fpu_ctxt));
	else /*if (request == PTRACE_GETFPXREGS)*/
	    memcpy(data, &ctxt[cpu].fpu_ctxt, sizeof(ctxt[cpu].fpu_ctxt));
	break;
    case PTRACE_SETREGS:
	op.cmd = DOM0_SETDOMAININFO;
	SET_XC_REGS(((struct gdb_regs *)data), ctxt[VCPU].user_regs);
	op.u.setdomaininfo.domain = domid;
	/* XXX need to understand multiple exec_domains */
	op.u.setdomaininfo.exec_domain = cpu;
	op.u.setdomaininfo.ctxt = &ctxt[cpu];
	retval = do_dom0_op(xc_handle, &op);
	if (retval)
	    goto error_out;

	break;
    case PTRACE_ATTACH:
	op.cmd = DOM0_GETDOMAININFO;
	op.u.getdomaininfo.domain = domid;
	op.u.getdomaininfo.exec_domain = 0;
	op.u.getdomaininfo.ctxt = NULL;
	retval = do_dom0_op(xc_handle, &op);
	if (retval) {
	    perror("dom0 op failed");
	    goto error_out;
	}
	if (op.u.getdomaininfo.flags & DOMFLAGS_PAUSED) {
	    printf("domain currently paused\n");
	    goto error_out;
	}
	printf("domain not currently paused\n");
	op.cmd = DOM0_PAUSEDOMAIN;
	op.u.pausedomain.domain = domid;
	retval = do_dom0_op(xc_handle, &op);
	break;
    case PTRACE_SINGLESTEP:
	ctxt[VCPU].user_regs.eflags |= PSL_T;
	op.cmd = DOM0_SETDOMAININFO;
	op.u.setdomaininfo.domain = domid;
	op.u.setdomaininfo.exec_domain = 0;
	op.u.setdomaininfo.ctxt = &ctxt[cpu];
	retval = do_dom0_op(xc_handle, &op);	
	if (retval) {
	    perror("dom0 op failed");
	    goto error_out;
	}
    	/* FALLTHROUGH */
    case PTRACE_CONT:
    case PTRACE_DETACH:
	if (request != PTRACE_SINGLESTEP) {
	    FETCH_REGS(cpu);
	    /* Clear trace flag */
	    if (ctxt[cpu].user_regs.eflags & PSL_T) {
		ctxt[cpu].user_regs.eflags &= ~PSL_T;
		op.cmd = DOM0_SETDOMAININFO;
		op.u.setdomaininfo.domain = domid;
		op.u.setdomaininfo.exec_domain = cpu;
		op.u.setdomaininfo.ctxt = &ctxt[cpu];
		retval = do_dom0_op(xc_handle, &op);	
		if (retval) {
		    perror("dom0 op failed");
		    goto error_out;
		}
	    }
	}
	regs_valid[cpu] = 0;
	op.cmd = DOM0_UNPAUSEDOMAIN;
	op.u.unpausedomain.domain = domid > 0 ? domid : -domid;
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
 error_out:
    return retval;
}
