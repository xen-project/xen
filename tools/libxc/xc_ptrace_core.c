#include <sys/ptrace.h>
#include <sys/wait.h>
#include "xc_private.h"
#include <time.h>

#define BSD_PAGE_MASK (PAGE_SIZE-1)
#define PDRSHIFT        22
#define VCPU            0               /* XXX */

/*
 * long  
 * ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
 */

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
#define SET_PT_REGS(pt, xc)                     \
{                                               \
    pt.ebx = xc.ebx;                            \
    pt.ecx = xc.ecx;                            \
    pt.edx = xc.edx;                            \
    pt.esi = xc.esi;                            \
    pt.edi = xc.edi;                            \
    pt.ebp = xc.ebp;                            \
    pt.eax = xc.eax;                            \
    pt.eip = xc.eip;                            \
    pt.xcs = xc.cs;                             \
    pt.eflags = xc.eflags;                      \
    pt.esp = xc.esp;                            \
    pt.xss = xc.ss;                             \
    pt.xes = xc.es;                             \
    pt.xds = xc.ds;                             \
    pt.xfs = xc.fs;                             \
    pt.xgs = xc.gs;                             \
}

#define SET_XC_REGS(pt, xc)                     \
{                                               \
    xc.ebx = pt->ebx;                           \
    xc.ecx = pt->ecx;                           \
    xc.edx = pt->edx;                           \
    xc.esi = pt->esi;                           \
    xc.edi = pt->edi;                           \
    xc.ebp = pt->ebp;                           \
    xc.eax = pt->eax;                           \
    xc.eip = pt->eip;                           \
    xc.cs = pt->xcs;                            \
    xc.eflags = pt->eflags;                     \
    xc.esp = pt->esp;                           \
    xc.ss = pt->xss;                            \
    xc.es = pt->xes;                            \
    xc.ds = pt->xds;                            \
    xc.fs = pt->xfs;                            \
    xc.gs = pt->xgs;                            \
}


#define vtopdi(va) ((va) >> PDRSHIFT)
#define vtopti(va) (((va) >> PAGE_SHIFT) & 0x3ff)

/* XXX application state */

static long   nr_pages = 0;
static unsigned long  *p2m_array = NULL;
static unsigned long  *m2p_array = NULL;
static unsigned long            pages_offset;
static unsigned long            cr3[MAX_VIRT_CPUS];
static vcpu_guest_context_t     ctxt[MAX_VIRT_CPUS];

/* --------------------- */

static unsigned long
map_mtop_offset(unsigned long ma)
{
    return pages_offset + (m2p_array[ma >> PAGE_SHIFT] << PAGE_SHIFT);
}


static void *
map_domain_va(unsigned long domfd, int cpu, void * guest_va)
{
    unsigned long pde, page;
    unsigned long va = (unsigned long)guest_va;
    void *v;

    static unsigned long  cr3_phys[MAX_VIRT_CPUS];
    static unsigned long *cr3_virt[MAX_VIRT_CPUS];
    static unsigned long  pde_phys[MAX_VIRT_CPUS];
    static unsigned long *pde_virt[MAX_VIRT_CPUS];
    static unsigned long  page_phys[MAX_VIRT_CPUS];
    static unsigned long *page_virt[MAX_VIRT_CPUS];

    if (cr3[cpu] != cr3_phys[cpu]) 
    {
        cr3_phys[cpu] = cr3[cpu];
        if (cr3_virt[cpu])
            munmap(cr3_virt[cpu], PAGE_SIZE);
        v = mmap(
            NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, domfd,
            map_mtop_offset(cr3_phys[cpu]));
        if (v == MAP_FAILED)
        {
            perror("mmap failed");
            goto error_out;
        }
        cr3_virt[cpu] = v;
    } 
    if ((pde = cr3_virt[cpu][vtopdi(va)]) == 0) /* logical address */
        goto error_out;
    if (ctxt[cpu].flags & VGCF_HVM_GUEST)
        pde = p2m_array[pde >> PAGE_SHIFT] << PAGE_SHIFT;
    if (pde != pde_phys[cpu]) 
    {
        pde_phys[cpu] = pde;
        if (pde_virt[cpu])
            munmap(pde_virt[cpu], PAGE_SIZE);
        v = mmap(
            NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, domfd,
            map_mtop_offset(pde_phys[cpu]));
        if (v == MAP_FAILED)
            goto error_out;
        pde_virt[cpu] = v;
    }
    if ((page = pde_virt[cpu][vtopti(va)]) == 0) /* logical address */
        goto error_out;
    if (ctxt[cpu].flags & VGCF_HVM_GUEST)
        page = p2m_array[page >> PAGE_SHIFT] << PAGE_SHIFT;
    if (page != page_phys[cpu]) 
    {
        page_phys[cpu] = page;
        if (page_virt[cpu])
            munmap(page_virt[cpu], PAGE_SIZE);
        v = mmap(
            NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, domfd,
            map_mtop_offset(page_phys[cpu]));
        if (v == MAP_FAILED) {
            printf("cr3 %lx pde %lx page %lx pti %lx\n", cr3[cpu], pde, page, vtopti(va));
            page_phys[cpu] = 0;
            goto error_out;
        }
        page_virt[cpu] = v;
    } 
    return (void *)(((unsigned long)page_virt[cpu]) | (va & BSD_PAGE_MASK));

 error_out:
    return 0;
}

int 
xc_waitdomain_core(
    int xc_handle,
    int domfd,
    int *status,
    int options)
{
    int retval = -1;
    int nr_vcpus;
    int i;
    xc_core_header_t header;

    if (nr_pages == 0) {

        if (read(domfd, &header, sizeof(header)) != sizeof(header))
            return -1;

        nr_pages = header.xch_nr_pages;
        nr_vcpus = header.xch_nr_vcpus;
        pages_offset = header.xch_pages_offset;

        if (read(domfd, ctxt, sizeof(vcpu_guest_context_t)*nr_vcpus) != 
            sizeof(vcpu_guest_context_t)*nr_vcpus)
            return -1;

        for (i = 0; i < nr_vcpus; i++) {
            cr3[i] = ctxt[i].ctrlreg[3];
        }
        if ((p2m_array = malloc(nr_pages * sizeof(unsigned long))) == NULL) {
            printf("Could not allocate p2m_array\n");
            goto error_out;
        }
        if (read(domfd, p2m_array, sizeof(unsigned long)*nr_pages) != 
            sizeof(unsigned long)*nr_pages)
            return -1;

        if ((m2p_array = malloc((1<<20) * sizeof(unsigned long))) == NULL) {
            printf("Could not allocate m2p array\n");
            goto error_out;
        }
        bzero(m2p_array, sizeof(unsigned long)* 1 << 20);

        for (i = 0; i < nr_pages; i++) {
            m2p_array[p2m_array[i]] = i;
        }

    }
    retval = 0;
 error_out:
    return retval;

}

long
xc_ptrace_core(
    int xc_handle,
    enum __ptrace_request request,
    uint32_t domfd,
    long eaddr,
    long edata)
{
    int             status = 0;
    struct gdb_regs pt;
    long            retval = 0;
    unsigned long  *guest_va;
    int             cpu = VCPU;
    void           *addr = (char *)eaddr;
    void           *data = (char *)edata;

#if 0
    printf("%20s %d, %p, %p \n", ptrace_names[request], domid, addr, data);
#endif
    switch (request) { 
    case PTRACE_PEEKTEXT:
    case PTRACE_PEEKDATA:
        if ((guest_va = (unsigned long *)map_domain_va(domfd, cpu, addr)) == NULL) {
            status = EFAULT;
            goto error_out;
        }

        retval = *guest_va;
        break;
    case PTRACE_POKETEXT:
    case PTRACE_POKEDATA:
        if ((guest_va = (unsigned long *)map_domain_va(domfd, cpu, addr)) == NULL) {
            status = EFAULT;
            goto error_out;
        }
        *guest_va = (unsigned long)data;
        break;
    case PTRACE_GETREGS:
    case PTRACE_GETFPREGS:
    case PTRACE_GETFPXREGS:
        if (request == PTRACE_GETREGS) {
            SET_PT_REGS(pt, ctxt[cpu].user_regs); 
            memcpy(data, &pt, sizeof(struct gdb_regs));
        } else if (request == PTRACE_GETFPREGS)
            memcpy(data, &ctxt[cpu].fpu_ctxt, sizeof(ctxt[cpu].fpu_ctxt));
        else /*if (request == PTRACE_GETFPXREGS)*/
            memcpy(data, &ctxt[cpu].fpu_ctxt, sizeof(ctxt[cpu].fpu_ctxt));
        break;
    case PTRACE_ATTACH:
        retval = 0;
        break;
    case PTRACE_SETREGS:
    case PTRACE_SINGLESTEP:
    case PTRACE_CONT:
    case PTRACE_DETACH:
    case PTRACE_SETFPREGS:
    case PTRACE_SETFPXREGS:
    case PTRACE_PEEKUSER:
    case PTRACE_POKEUSER:
    case PTRACE_SYSCALL:
    case PTRACE_KILL:
#ifdef DEBUG
        printf("unsupported xc_ptrace request %s\n", ptrace_names[request]);
#endif
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
