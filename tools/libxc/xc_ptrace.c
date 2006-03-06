#define XC_PTRACE_PRIVATE

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>

#include "xc_private.h"
#include "xg_private.h"
#include "xc_ptrace.h"

#ifdef DEBUG
const char const * ptrace_names[] = {
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
#endif

/* XXX application state */
static long                     nr_pages = 0;
static unsigned long           *page_array = NULL;
static int                      current_domid = -1;
static int                      current_isfile;

static cpumap_t                 online_cpumap;
static cpumap_t                 regs_valid;
static vcpu_guest_context_t     ctxt[MAX_VIRT_CPUS];

extern int ffsll(long long int);
#define FOREACH_CPU(cpumap, i)  for ( cpumap = online_cpumap; (i = ffsll(cpumap)); cpumap &= ~(1 << (index - 1)) ) 


static int
fetch_regs(int xc_handle, int cpu, int *online)
{
    xc_vcpuinfo_t info;
    int retval = 0;

    if (online)
        *online = 0;
    if ( !(regs_valid & (1 << cpu)) )
    { 
        retval = xc_vcpu_getcontext(xc_handle, current_domid, 
						cpu, &ctxt[cpu]);
        if ( retval ) 
            goto done;
	regs_valid |= (1 << cpu);

    }
	if ( online == NULL )
	    goto done;

	retval = xc_vcpu_getinfo(xc_handle, current_domid, cpu, &info);
	*online = info.online;
    
 done:
    return retval;    
}

static struct thr_ev_handlers {
    thr_ev_handler_t td_create;
    thr_ev_handler_t td_death;
} handlers;

void 
xc_register_event_handler(thr_ev_handler_t h, 
                          td_event_e e)
{
    switch (e) {
    case TD_CREATE:
        handlers.td_create = h;
        break;
    case TD_DEATH:
        handlers.td_death = h;
        break;
    default:
        abort(); /* XXX */
    }
}

static inline int 
paging_enabled(vcpu_guest_context_t *v)
{
    unsigned long cr0 = v->ctrlreg[0];
    return (cr0 & X86_CR0_PE) && (cr0 & X86_CR0_PG);
}

/*
 * Fetch registers for all online cpus and set the cpumap
 * to indicate which cpus are online
 *
 */

static int
get_online_cpumap(int xc_handle, dom0_getdomaininfo_t *d, cpumap_t *cpumap)
{
    int i, online, retval;
    
    *cpumap = 0;
    for (i = 0; i <= d->max_vcpu_id; i++) {
        if ((retval = fetch_regs(xc_handle, i, &online)))
            return retval;
        if (online)
            *cpumap |= (1 << i);            
    }
    
    return 0;
}

/* 
 * Notify GDB of any vcpus that have come online or gone offline
 * update online_cpumap
 *
 */

static void
online_vcpus_changed(cpumap_t cpumap)
{
    cpumap_t changed_cpumap = cpumap ^ online_cpumap;
    int index;
    
    while ( (index = ffsll(changed_cpumap)) ) {
        if ( cpumap & (1 << (index - 1)) )
        {
            if (handlers.td_create) handlers.td_create(index - 1);
        } else {
            printf("thread death: %d\n", index - 1);
            if (handlers.td_death) handlers.td_death(index - 1);
        }
        changed_cpumap &= ~(1 << (index - 1));
    }
    online_cpumap = cpumap;
    
}

/* --------------------- */

static void *
map_domain_va_pae(
    int xc_handle,
    int cpu,
    void *guest_va,
    int perm)
{
    unsigned long l2p, l1p, p, va = (unsigned long)guest_va;
    uint64_t *l3, *l2, *l1;
    static void *v;

    if (fetch_regs(xc_handle, cpu, NULL))
        return NULL;

    l3 = xc_map_foreign_range(
        xc_handle, current_domid, PAGE_SIZE, PROT_READ, ctxt[cpu].ctrlreg[3] >> PAGE_SHIFT);
    if ( l3 == NULL )
        return NULL;

    l2p = l3[l3_table_offset_pae(va)] >> PAGE_SHIFT;
    l2 = xc_map_foreign_range(xc_handle, current_domid, PAGE_SIZE, PROT_READ, l2p);
    if ( l2 == NULL )
        return NULL;

    l1p = l2[l2_table_offset_pae(va)] >> PAGE_SHIFT;
    l1 = xc_map_foreign_range(xc_handle, current_domid, PAGE_SIZE, perm, l1p);
    if ( l1 == NULL )
        return NULL;

    p = l1[l1_table_offset_pae(va)] >> PAGE_SHIFT;
    if ( v != NULL )
        munmap(v, PAGE_SIZE);
    v = xc_map_foreign_range(xc_handle, current_domid, PAGE_SIZE, perm, p);
    if ( v == NULL )
        return NULL;

    return (void *)((unsigned long)v | (va & (PAGE_SIZE - 1)));
}

static void *
map_domain_va(
    int xc_handle,
    int cpu,
    void *guest_va,
    int perm)
{

    unsigned long pde, page;
    unsigned long va = (unsigned long)guest_va;
    long npgs = xc_get_tot_pages(xc_handle, current_domid);


    static uint32_t  cr3_phys[MAX_VIRT_CPUS];
    static unsigned long *cr3_virt[MAX_VIRT_CPUS];
    static unsigned long  pde_phys[MAX_VIRT_CPUS];
    static unsigned long *pde_virt[MAX_VIRT_CPUS];
    static unsigned long  page_phys[MAX_VIRT_CPUS];
    static unsigned long *page_virt[MAX_VIRT_CPUS];    
    static int            prev_perm[MAX_VIRT_CPUS];
    static enum { MODE_UNKNOWN, MODE_32, MODE_PAE } mode;

    if ( mode == MODE_UNKNOWN )
    {
        xen_capabilities_info_t caps;
        (void)xc_version(xc_handle, XENVER_capabilities, caps);
        mode = MODE_32;
        if ( strstr(caps, "_x86_32p") )
            mode = MODE_PAE;
    }

    if ( mode == MODE_PAE )
        return map_domain_va_pae(xc_handle, cpu, guest_va, perm);

    if ( nr_pages != npgs )
    {
        if ( nr_pages > 0 )
            free(page_array);
        nr_pages = npgs;
        if ( (page_array = malloc(nr_pages * sizeof(unsigned long))) == NULL )
        {
            printf("Could not allocate memory\n");
            return NULL;
        }
        if ( xc_get_pfn_list(xc_handle, current_domid,
                             page_array, nr_pages) != nr_pages )
        {
            printf("Could not get the page frame list\n");
            return NULL;
        }
    }

    if (fetch_regs(xc_handle, cpu, NULL))
        return NULL;

    if ( ctxt[cpu].ctrlreg[3] != cr3_phys[cpu] )
    {
        cr3_phys[cpu] = ctxt[cpu].ctrlreg[3];
        if ( cr3_virt[cpu] )
            munmap(cr3_virt[cpu], PAGE_SIZE);
        cr3_virt[cpu] = xc_map_foreign_range(
            xc_handle, current_domid, PAGE_SIZE, PROT_READ,
            cr3_phys[cpu] >> PAGE_SHIFT);
        if ( cr3_virt[cpu] == NULL )
            return NULL;
    }
    if ( (pde = cr3_virt[cpu][vtopdi(va)]) == 0 )
        return NULL;
    if ( (ctxt[cpu].flags & VGCF_HVM_GUEST) && paging_enabled(&ctxt[cpu]) )
        pde = page_array[pde >> PAGE_SHIFT] << PAGE_SHIFT;
    if ( pde != pde_phys[cpu] )
    {
        pde_phys[cpu] = pde;
        if ( pde_virt[cpu] )
            munmap(pde_virt[cpu], PAGE_SIZE);
        pde_virt[cpu] = xc_map_foreign_range(
            xc_handle, current_domid, PAGE_SIZE, PROT_READ,
            pde_phys[cpu] >> PAGE_SHIFT);
        if ( pde_virt[cpu] == NULL )
            return NULL;
    }
    if ( (page = pde_virt[cpu][vtopti(va)]) == 0 )
        return NULL;
    if ( (ctxt[cpu].flags & VGCF_HVM_GUEST) && paging_enabled(&ctxt[cpu]) )
        page = page_array[page >> PAGE_SHIFT] << PAGE_SHIFT;
    if ( (page != page_phys[cpu]) || (perm != prev_perm[cpu]) )
    {
        page_phys[cpu] = page;
        if ( page_virt[cpu] )
            munmap(page_virt[cpu], PAGE_SIZE);
        page_virt[cpu] = xc_map_foreign_range(
            xc_handle, current_domid, PAGE_SIZE, perm,
            page_phys[cpu] >> PAGE_SHIFT);
        if ( page_virt[cpu] == NULL )
        {
            page_phys[cpu] = 0;
            return NULL;
        }
        prev_perm[cpu] = perm;
    } 

    return (void *)(((unsigned long)page_virt[cpu]) | (va & BSD_PAGE_MASK));
}

static int 
__xc_waitdomain(
    int xc_handle,
    int domain,
    int *status,
    int options)
{
    DECLARE_DOM0_OP;
    int retval;
    struct timespec ts;
    cpumap_t cpumap;

    ts.tv_sec = 0;
    ts.tv_nsec = 10*1000*1000;

    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = domain;
    
    
 retry:
    retval = do_dom0_op(xc_handle, &op);
    if ( retval || (op.u.getdomaininfo.domain != domain) )
    {
        printf("getdomaininfo failed\n");
        goto done;
    }
    *status = op.u.getdomaininfo.flags;
    
    if ( options & WNOHANG )
        goto done;

    if ( !(op.u.getdomaininfo.flags & DOMFLAGS_PAUSED) )
    {
        nanosleep(&ts,NULL);
        goto retry;
    }
    /* XXX check for ^C here */
 done:
    if (get_online_cpumap(xc_handle, &op.u.getdomaininfo, &cpumap))
        printf("get_online_cpumap failed\n");
    if (online_cpumap != cpumap)
        online_vcpus_changed(cpumap);
    return retval;

}


long
xc_ptrace(
    int xc_handle,
    enum __ptrace_request request,
    uint32_t domid_tid,
    long eaddr,
    long edata)
{
    DECLARE_DOM0_OP;
    struct gdb_regs pt;
    long            retval = 0;
    unsigned long  *guest_va;
    cpumap_t        cpumap;
    int             cpu, index;
    void           *addr = (char *)eaddr;
    void           *data = (char *)edata;

    cpu = (request != PTRACE_ATTACH) ? domid_tid : 0;
    
    switch ( request )
    { 
    case PTRACE_PEEKTEXT:
    case PTRACE_PEEKDATA:
        if (current_isfile)
            guest_va = (unsigned long *)map_domain_va_core(current_domid, 
                                cpu, addr, ctxt);
        else
            guest_va = (unsigned long *)map_domain_va(xc_handle, 
                                cpu, addr, PROT_READ);
        if ( guest_va == NULL )
            goto out_error;
        retval = *guest_va;
        break;

    case PTRACE_POKETEXT:
    case PTRACE_POKEDATA:
        /* XXX assume that all CPUs have the same address space */
        if (current_isfile)
            guest_va = (unsigned long *)map_domain_va_core(current_domid, 
                                cpu, addr, ctxt);
        else
            guest_va = (unsigned long *)map_domain_va(xc_handle, 
                                cpu, addr, PROT_READ|PROT_WRITE);
        if ( guest_va == NULL ) 
            goto out_error;
        *guest_va = (unsigned long)data;
        break;

    case PTRACE_GETREGS:
        if (!current_isfile && fetch_regs(xc_handle, cpu, NULL)) 
            goto out_error;
        SET_PT_REGS(pt, ctxt[cpu].user_regs); 
        memcpy(data, &pt, sizeof(struct gdb_regs));
        break;

    case PTRACE_GETFPREGS:
    case PTRACE_GETFPXREGS:
        if (!current_isfile && fetch_regs(xc_handle, cpu, NULL)) 
                goto out_error;
        memcpy(data, &ctxt[cpu].fpu_ctxt, sizeof(ctxt[cpu].fpu_ctxt));
        break;

    case PTRACE_SETREGS:
        if (!current_isfile)
                goto out_unspported; /* XXX not yet supported */
        SET_XC_REGS(((struct gdb_regs *)data), ctxt[cpu].user_regs);
        if ((retval = xc_vcpu_setcontext(xc_handle, current_domid, cpu, 
                                &ctxt[cpu])))
            goto out_error_dom0;
        break;

    case PTRACE_SINGLESTEP:
        if (!current_isfile)
              goto out_unspported; /* XXX not yet supported */
        /*  XXX we can still have problems if the user switches threads
         *  during single-stepping - but that just seems retarded
         */
        ctxt[cpu].user_regs.eflags |= PSL_T; 
        if ((retval = xc_vcpu_setcontext(xc_handle, current_domid, cpu, 
                                &ctxt[cpu])))
            goto out_error_dom0;
        /* FALLTHROUGH */

    case PTRACE_CONT:
    case PTRACE_DETACH:
        if (!current_isfile)
            goto out_unspported; /* XXX not yet supported */
        if ( request != PTRACE_SINGLESTEP )
        {
            FOREACH_CPU(cpumap, index) {
                cpu = index - 1;
                if (fetch_regs(xc_handle, cpu, NULL)) 
                    goto out_error;
                /* Clear trace flag */
                if ( ctxt[cpu].user_regs.eflags & PSL_T ) 
                {
                    ctxt[cpu].user_regs.eflags &= ~PSL_T;
                    if ((retval = xc_vcpu_setcontext(xc_handle, current_domid, 
                                                cpu, &ctxt[cpu])))
                        goto out_error_dom0;
                }
            }
        }
        if ( request == PTRACE_DETACH )
        {
            op.cmd = DOM0_SETDEBUGGING;
            op.u.setdebugging.domain = current_domid;
            op.u.setdebugging.enable = 0;
            if ((retval = do_dom0_op(xc_handle, &op)))
                goto out_error_dom0;
        }
        regs_valid = 0;
        if ((retval = xc_domain_unpause(xc_handle, current_domid > 0 ? 
                                current_domid : -current_domid)))
            goto out_error_dom0;
        break;

    case PTRACE_ATTACH:
        current_domid = domid_tid;
        current_isfile = (int)edata;
        if (current_isfile)
            break;
        op.cmd = DOM0_GETDOMAININFO;
        op.u.getdomaininfo.domain = current_domid;
        retval = do_dom0_op(xc_handle, &op);
        if ( retval || (op.u.getdomaininfo.domain != current_domid) )
            goto out_error_dom0;
        if ( op.u.getdomaininfo.flags & DOMFLAGS_PAUSED )
            printf("domain currently paused\n");
        else if ((retval = xc_domain_pause(xc_handle, current_domid)))
            goto out_error_dom0;
        op.cmd = DOM0_SETDEBUGGING;
        op.u.setdebugging.domain = current_domid;
        op.u.setdebugging.enable = 1;
        if ((retval = do_dom0_op(xc_handle, &op)))
            goto out_error_dom0;

        if (get_online_cpumap(xc_handle, &op.u.getdomaininfo, &cpumap))
            printf("get_online_cpumap failed\n");
        if (online_cpumap != cpumap)
            online_vcpus_changed(cpumap);
        break;

    case PTRACE_SETFPREGS:
    case PTRACE_SETFPXREGS:
    case PTRACE_PEEKUSER:
    case PTRACE_POKEUSER:
    case PTRACE_SYSCALL:
    case PTRACE_KILL:
        goto out_unspported; /* XXX not yet supported */

    case PTRACE_TRACEME:
        printf("PTRACE_TRACEME is an invalid request under Xen\n");
        goto out_error;
    }

    return retval;

 out_error_dom0:
    perror("dom0 op failed");
 out_error:
    errno = EINVAL;
    return retval;

 out_unspported:
#ifdef DEBUG
    printf("unsupported xc_ptrace request %s\n", ptrace_names[request]);
#endif
    errno = ENOSYS;
    return -1;

}

int 
xc_waitdomain(
    int xc_handle,
    int domain,
    int *status,
    int options)
{
    if (current_isfile)
        return xc_waitdomain_core(xc_handle, domain, status, options, ctxt);
    return __xc_waitdomain(xc_handle, domain, status, options);
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
