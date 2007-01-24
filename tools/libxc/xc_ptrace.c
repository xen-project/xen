#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>

#include "xc_private.h"
#include "xg_private.h"
#include "xc_ptrace.h"

#ifdef DEBUG
static char *ptrace_names[] = {
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

static int current_domid = -1;
static int current_isfile;
static int current_is_hvm;

static uint64_t                 online_cpumap;
static uint64_t                 regs_valid;
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
get_online_cpumap(int xc_handle, struct xen_domctl_getdomaininfo *d,
                  uint64_t *cpumap)
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
online_vcpus_changed(uint64_t cpumap)
{
    uint64_t changed_cpumap = cpumap ^ online_cpumap;
    int index;

    while ( (index = ffsll(changed_cpumap)) ) {
        if ( cpumap & (1 << (index - 1)) )
        {
            if (handlers.td_create) handlers.td_create(index - 1);
        } else {
            IPRINTF("thread death: %d\n", index - 1);
            if (handlers.td_death) handlers.td_death(index - 1);
        }
        changed_cpumap &= ~(1 << (index - 1));
    }
    online_cpumap = cpumap;

}

/* --------------------- */
/* XXX application state */
static long      nr_pages = 0;
static uint64_t *page_array = NULL;


/*
 * Translates physical addresses to machine addresses for HVM
 * guests. For paravirtual domains the function will just return the
 * given address.
 *
 * This function should be used when reading page directories/page
 * tables.
 *
 */
static uint64_t
to_ma(int cpu, uint64_t maddr)
{
    if ( current_is_hvm && paging_enabled(&ctxt[cpu]) )
        maddr = page_array[maddr >> PAGE_SHIFT] << PAGE_SHIFT;
    return maddr;
}

static void *
map_domain_va_32(
    int xc_handle,
    int cpu,
    void *guest_va,
    int perm)
{
    unsigned long l2e, l1e, l1p, p, va = (unsigned long)guest_va;
    uint32_t *l2, *l1;
    static void *v[MAX_VIRT_CPUS];

    l2 = xc_map_foreign_range(
         xc_handle, current_domid, PAGE_SIZE, PROT_READ,
         xen_cr3_to_pfn(ctxt[cpu].ctrlreg[3]));
    if ( l2 == NULL )
        return NULL;

    l2e = l2[l2_table_offset_i386(va)];
    munmap(l2, PAGE_SIZE);
    if ( !(l2e & _PAGE_PRESENT) )
        return NULL;
    l1p = to_ma(cpu, l2e);
    l1 = xc_map_foreign_range(xc_handle, current_domid, PAGE_SIZE, PROT_READ, l1p >> PAGE_SHIFT);
    if ( l1 == NULL )
        return NULL;

    l1e = l1[l1_table_offset_i386(va)];
    munmap(l1, PAGE_SIZE);
    if ( !(l1e & _PAGE_PRESENT) )
        return NULL;
    p = to_ma(cpu, l1e);
    if ( v[cpu] != NULL )
        munmap(v[cpu], PAGE_SIZE);
    v[cpu] = xc_map_foreign_range(xc_handle, current_domid, PAGE_SIZE, perm, p >> PAGE_SHIFT);
    if ( v[cpu] == NULL )
        return NULL;

    return (void *)((unsigned long)v[cpu] | (va & (PAGE_SIZE - 1)));
}


static void *
map_domain_va_pae(
    int xc_handle,
    int cpu,
    void *guest_va,
    int perm)
{
    uint64_t l3e, l2e, l1e, l2p, l1p, p;
    unsigned long va = (unsigned long)guest_va;
    uint64_t *l3, *l2, *l1;
    static void *v[MAX_VIRT_CPUS];

    l3 = xc_map_foreign_range(
        xc_handle, current_domid, PAGE_SIZE, PROT_READ,
        xen_cr3_to_pfn(ctxt[cpu].ctrlreg[3]));
    if ( l3 == NULL )
        return NULL;

    l3e = l3[l3_table_offset_pae(va)];
    munmap(l3, PAGE_SIZE);
    if ( !(l3e & _PAGE_PRESENT) )
        return NULL;
    l2p = to_ma(cpu, l3e);
    l2 = xc_map_foreign_range(xc_handle, current_domid, PAGE_SIZE, PROT_READ, l2p >> PAGE_SHIFT);
    if ( l2 == NULL )
        return NULL;

    l2e = l2[l2_table_offset_pae(va)];
    munmap(l2, PAGE_SIZE);
    if ( !(l2e & _PAGE_PRESENT) )
        return NULL;
    l1p = to_ma(cpu, l2e);
    l1 = xc_map_foreign_range(xc_handle, current_domid, PAGE_SIZE, PROT_READ, l1p >> PAGE_SHIFT);
    if ( l1 == NULL )
        return NULL;

    l1e = l1[l1_table_offset_pae(va)];
    munmap(l1, PAGE_SIZE);
    if ( !(l1e & _PAGE_PRESENT) )
        return NULL;
    p = to_ma(cpu, l1e);
    if ( v[cpu] != NULL )
        munmap(v[cpu], PAGE_SIZE);
    v[cpu] = xc_map_foreign_range(xc_handle, current_domid, PAGE_SIZE, perm, p >> PAGE_SHIFT);
    if ( v[cpu] == NULL )
        return NULL;

    return (void *)((unsigned long)v[cpu] | (va & (PAGE_SIZE - 1)));
}

#ifdef __x86_64__
static void *
map_domain_va_64(
    int xc_handle,
    int cpu,
    void *guest_va,
    int perm)
{
    unsigned long l4e, l3e, l2e, l1e, l3p, l2p, l1p, p, va = (unsigned long)guest_va;
    uint64_t *l4, *l3, *l2, *l1;
    static void *v[MAX_VIRT_CPUS];

    if ((ctxt[cpu].ctrlreg[4] & 0x20) == 0 ) /* legacy ia32 mode */
        return map_domain_va_32(xc_handle, cpu, guest_va, perm);

    l4 = xc_map_foreign_range(
        xc_handle, current_domid, PAGE_SIZE, PROT_READ,
        xen_cr3_to_pfn(ctxt[cpu].ctrlreg[3]));
    if ( l4 == NULL )
        return NULL;

    l4e = l4[l4_table_offset(va)];
    munmap(l4, PAGE_SIZE);
    if ( !(l4e & _PAGE_PRESENT) )
        return NULL;
    l3p = to_ma(cpu, l4e);
    l3 = xc_map_foreign_range(xc_handle, current_domid, PAGE_SIZE, PROT_READ, l3p >> PAGE_SHIFT);
    if ( l3 == NULL )
        return NULL;

    l3e = l3[l3_table_offset(va)];
    munmap(l3, PAGE_SIZE);
    if ( !(l3e & _PAGE_PRESENT) )
        return NULL;
    l2p = to_ma(cpu, l3e);
    l2 = xc_map_foreign_range(xc_handle, current_domid, PAGE_SIZE, PROT_READ, l2p >> PAGE_SHIFT);
    if ( l2 == NULL )
        return NULL;

    l2e = l2[l2_table_offset(va)];
    munmap(l2, PAGE_SIZE);
    if ( !(l2e & _PAGE_PRESENT) )
        return NULL;
    l1p = to_ma(cpu, l2e);
    if (l2e & 0x80)  { /* 2M pages */
        p = to_ma(cpu, (l1p + l1_table_offset(va)) << PAGE_SHIFT);
    } else { /* 4K pages */
        l1 = xc_map_foreign_range(xc_handle, current_domid, PAGE_SIZE, PROT_READ, l1p >> PAGE_SHIFT);
        if ( l1 == NULL )
            return NULL;

        l1e = l1[l1_table_offset(va)];
        munmap(l1, PAGE_SIZE);
        if ( !(l1e & _PAGE_PRESENT) )
            return NULL;
        p = to_ma(cpu, l1e);
    }
    if ( v[cpu] != NULL )
        munmap(v[cpu], PAGE_SIZE);
    v[cpu] = xc_map_foreign_range(xc_handle, current_domid, PAGE_SIZE, perm, p >> PAGE_SHIFT);
    if ( v[cpu] == NULL )
        return NULL;

    return (void *)((unsigned long)v[cpu] | (va & (PAGE_SIZE - 1)));
}
#endif

static void *
map_domain_va(
    int xc_handle,
    int cpu,
    void *guest_va,
    int perm)
{
    unsigned long va = (unsigned long) guest_va;
    long npgs = xc_get_tot_pages(xc_handle, current_domid);
    static enum { MODE_UNKNOWN, MODE_64, MODE_32, MODE_PAE } mode;

    if ( mode == MODE_UNKNOWN )
    {
        xen_capabilities_info_t caps;
        (void)xc_version(xc_handle, XENVER_capabilities, caps);
        if ( strstr(caps, "-x86_64") )
            mode = MODE_64;
        else if ( strstr(caps, "-x86_32p") )
            mode = MODE_PAE;
        else if ( strstr(caps, "-x86_32") )
            mode = MODE_32;
    }

    if ( nr_pages != npgs )
    {
        if ( nr_pages > 0 )
            free(page_array);
        nr_pages = npgs;
        if ( (page_array = malloc(nr_pages * sizeof(*page_array))) == NULL )
        {
            IPRINTF("Could not allocate memory\n");
            return NULL;
        }
        if ( xc_get_pfn_list(xc_handle, current_domid,
                             page_array, nr_pages) != nr_pages )
        {
            IPRINTF("Could not get the page frame list\n");
            return NULL;
        }
    }

    if (fetch_regs(xc_handle, cpu, NULL))
        return NULL;

    if (!paging_enabled(&ctxt[cpu])) {
        static void * v;
        uint64_t page;

        if ( v != NULL )
            munmap(v, PAGE_SIZE);

        page = to_ma(cpu, va);

        v = xc_map_foreign_range( xc_handle, current_domid, PAGE_SIZE,
                perm, page >> PAGE_SHIFT);

        if ( v == NULL )
            return NULL;

        return (void *)(((unsigned long)v) | (va & BSD_PAGE_MASK));
    }
#ifdef __x86_64__
    if ( mode == MODE_64 )
        return map_domain_va_64(xc_handle, cpu, guest_va, perm);
#endif
    if ( mode == MODE_PAE )
        return map_domain_va_pae(xc_handle, cpu, guest_va, perm);
    /* else ( mode == MODE_32 ) */
    return map_domain_va_32(xc_handle, cpu, guest_va, perm);
}

int control_c_pressed_flag = 0;

static int
__xc_waitdomain(
    int xc_handle,
    int domain,
    int *status,
    int options)
{
    DECLARE_DOMCTL;
    int retval;
    struct timespec ts;
    uint64_t cpumap;

    ts.tv_sec = 0;
    ts.tv_nsec = 10*1000*1000;

    domctl.cmd = XEN_DOMCTL_getdomaininfo;
    domctl.domain = domain;

 retry:
    retval = do_domctl(xc_handle, &domctl);
    if ( retval || (domctl.domain != domain) )
    {
        IPRINTF("getdomaininfo failed\n");
        goto done;
    }
    *status = domctl.u.getdomaininfo.flags;

    if ( options & WNOHANG )
        goto done;

    if (control_c_pressed_flag) {
        xc_domain_pause(xc_handle, domain);
        control_c_pressed_flag = 0;
        goto done;
    }

    if ( !(domctl.u.getdomaininfo.flags & XEN_DOMINF_paused) )
    {
        nanosleep(&ts,NULL);
        goto retry;
    }
 done:
    if (get_online_cpumap(xc_handle, &domctl.u.getdomaininfo, &cpumap))
        IPRINTF("get_online_cpumap failed\n");
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
    DECLARE_DOMCTL;
    struct gdb_regs pt;
    long            retval = 0;
    unsigned long  *guest_va;
    uint64_t        cpumap;
    int             cpu, index;
    void           *addr = (char *)eaddr;
    void           *data = (char *)edata;

    cpu = (request != PTRACE_ATTACH) ? domid_tid : 0;

    switch ( request )
    {
    case PTRACE_PEEKTEXT:
    case PTRACE_PEEKDATA:
        if (current_isfile)
            guest_va = (unsigned long *)map_domain_va_core(
                current_domid, cpu, addr, ctxt);
        else
            guest_va = (unsigned long *)map_domain_va(
                xc_handle, cpu, addr, PROT_READ);
        if ( guest_va == NULL )
            goto out_error;
        retval = *guest_va;
        break;

    case PTRACE_POKETEXT:
    case PTRACE_POKEDATA:
        /* XXX assume that all CPUs have the same address space */
        if (current_isfile)
            guest_va = (unsigned long *)map_domain_va_core(
                current_domid, cpu, addr, ctxt);
        else
            guest_va = (unsigned long *)map_domain_va(
                xc_handle, cpu, addr, PROT_READ|PROT_WRITE);
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
        if (!current_isfile && fetch_regs(xc_handle, cpu, NULL)) 
                goto out_error;
        memcpy(data, &ctxt[cpu].fpu_ctxt, sizeof (elf_fpregset_t));
        break;

    case PTRACE_GETFPXREGS:
        if (!current_isfile && fetch_regs(xc_handle, cpu, NULL))
                goto out_error;
        memcpy(data, &ctxt[cpu].fpu_ctxt, sizeof(ctxt[cpu].fpu_ctxt));
        break;

    case PTRACE_SETREGS:
        if (current_isfile)
                goto out_unsupported; /* XXX not yet supported */
        SET_XC_REGS(((struct gdb_regs *)data), ctxt[cpu].user_regs);
        if ((retval = xc_vcpu_setcontext(xc_handle, current_domid, cpu,
                                &ctxt[cpu])))
            goto out_error_domctl;
        break;

    case PTRACE_SINGLESTEP:
        if (current_isfile)
              goto out_unsupported; /* XXX not yet supported */
        /*  XXX we can still have problems if the user switches threads
         *  during single-stepping - but that just seems retarded
         */
        ctxt[cpu].user_regs.eflags |= PSL_T;
        if ((retval = xc_vcpu_setcontext(xc_handle, current_domid, cpu,
                                &ctxt[cpu])))
            goto out_error_domctl;
        /* FALLTHROUGH */

    case PTRACE_CONT:
    case PTRACE_DETACH:
        if (current_isfile)
            goto out_unsupported; /* XXX not yet supported */
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
                        goto out_error_domctl;
                }
            }
        }
        if ( request == PTRACE_DETACH )
        {
            domctl.cmd = XEN_DOMCTL_setdebugging;
            domctl.domain = current_domid;
            domctl.u.setdebugging.enable = 0;
            if ((retval = do_domctl(xc_handle, &domctl)))
                goto out_error_domctl;
        }
        regs_valid = 0;
        if ((retval = xc_domain_unpause(xc_handle, current_domid > 0 ?
                                current_domid : -current_domid)))
            goto out_error_domctl;
        break;

    case PTRACE_ATTACH:
        current_domid = domid_tid;
        current_isfile = (int)edata;
        if (current_isfile)
            break;
        domctl.cmd = XEN_DOMCTL_getdomaininfo;
        domctl.domain = current_domid;
        retval = do_domctl(xc_handle, &domctl);
        if ( retval || (domctl.domain != current_domid) )
            goto out_error_domctl;
        if ( domctl.u.getdomaininfo.flags & XEN_DOMINF_paused )
            IPRINTF("domain currently paused\n");
        else if ((retval = xc_domain_pause(xc_handle, current_domid)))
            goto out_error_domctl;
        current_is_hvm = !!(domctl.u.getdomaininfo.flags&XEN_DOMINF_hvm_guest);
        domctl.cmd = XEN_DOMCTL_setdebugging;
        domctl.domain = current_domid;
        domctl.u.setdebugging.enable = 1;
        if ((retval = do_domctl(xc_handle, &domctl)))
            goto out_error_domctl;

        if (get_online_cpumap(xc_handle, &domctl.u.getdomaininfo, &cpumap))
            IPRINTF("get_online_cpumap failed\n");
        if (online_cpumap != cpumap)
            online_vcpus_changed(cpumap);
        break;

    case PTRACE_TRACEME:
        IPRINTF("PTRACE_TRACEME is an invalid request under Xen\n");
        goto out_error;

    default:
        goto out_unsupported; /* XXX not yet supported */
    }

    return retval;

 out_error_domctl:
    perror("domctl failed");
 out_error:
    errno = EINVAL;
    return retval;

 out_unsupported:
#ifdef DEBUG
    IPRINTF("unsupported xc_ptrace request %s\n", ptrace_names[request]);
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
