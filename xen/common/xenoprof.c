/*
 * Copyright (C) 2005 Hewlett-Packard Co.
 * written by Aravind Menon & Jose Renato Santos
 *            (email: xenoprof@groups.hp.com)
 *
 * arch generic xenoprof and IA64 support.
 * dynamic map/unmap xenoprof buffer support.
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 */

#ifndef COMPAT
#include <xen/guest_access.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/xenoprof.h>
#include <public/xenoprof.h>
#include <xen/paging.h>
#include <xsm/xsm.h>
#include <xen/hypercall.h>

/* Limit amount of pages used for shared buffer (per domain) */
#define MAX_OPROF_SHARED_PAGES 32

/* Lock protecting the following global state */
static DEFINE_SPINLOCK(xenoprof_lock);

static DEFINE_SPINLOCK(pmu_owner_lock);
int pmu_owner = 0;
int pmu_hvm_refcount = 0;

static struct domain *active_domains[MAX_OPROF_DOMAINS];
static int active_ready[MAX_OPROF_DOMAINS];
static unsigned int adomains;

static struct domain *passive_domains[MAX_OPROF_DOMAINS];
static unsigned int pdomains;

static unsigned int activated;
static struct domain *xenoprof_primary_profiler;
static int xenoprof_state = XENOPROF_IDLE;
static unsigned long backtrace_depth;

static u64 total_samples;
static u64 invalid_buffer_samples;
static u64 corrupted_buffer_samples;
static u64 lost_samples;
static u64 active_samples;
static u64 passive_samples;
static u64 idle_samples;
static u64 others_samples;

int acquire_pmu_ownership(int pmu_ownship)
{
    spin_lock(&pmu_owner_lock);
    if ( pmu_owner == PMU_OWNER_NONE )
    {
        pmu_owner = pmu_ownship;
        goto out;
    }

    if ( pmu_owner == pmu_ownship )
        goto out;

    spin_unlock(&pmu_owner_lock);
    return 0;
 out:
    if ( pmu_owner == PMU_OWNER_HVM )
        pmu_hvm_refcount++;
    spin_unlock(&pmu_owner_lock);
    return 1;
}

void release_pmu_ownship(int pmu_ownship)
{
    spin_lock(&pmu_owner_lock);
    if ( pmu_ownship == PMU_OWNER_HVM )
        pmu_hvm_refcount--;
    if ( !pmu_hvm_refcount )
        pmu_owner = PMU_OWNER_NONE;
    spin_unlock(&pmu_owner_lock);
}

int is_active(struct domain *d)
{
    struct xenoprof *x = d->xenoprof;
    return ((x != NULL) && (x->domain_type == XENOPROF_DOMAIN_ACTIVE));
}

int is_passive(struct domain *d)
{
    struct xenoprof *x = d->xenoprof;
    return ((x != NULL) && (x->domain_type == XENOPROF_DOMAIN_PASSIVE));
}

static int is_profiled(struct domain *d)
{
    return (is_active(d) || is_passive(d));
}

static void xenoprof_reset_stat(void)
{
    total_samples = 0;
    invalid_buffer_samples = 0;
    corrupted_buffer_samples = 0;
    lost_samples = 0;
    active_samples = 0;
    passive_samples = 0;
    idle_samples = 0;
    others_samples = 0;
}

static void xenoprof_reset_buf(struct domain *d)
{
    int j;
    xenoprof_buf_t *buf;

    if ( d->xenoprof == NULL )
    {
        printk("xenoprof_reset_buf: ERROR - Unexpected "
               "Xenoprof NULL pointer \n");
        return;
    }

    for ( j = 0; j < d->max_vcpus; j++ )
    {
        buf = d->xenoprof->vcpu[j].buffer;
        if ( buf != NULL )
        {
            xenoprof_buf(d, buf, event_head) = 0;
            xenoprof_buf(d, buf, event_tail) = 0;
        }
    }
}

static int
share_xenoprof_page_with_guest(struct domain *d, unsigned long mfn, int npages)
{
    int i;

    /* Check if previous page owner has released the page. */
    for ( i = 0; i < npages; i++ )
    {
        struct page_info *page = mfn_to_page(mfn + i);
        if ( (page->count_info & (PGC_allocated|PGC_count_mask)) != 0 )
        {
            printk(XENLOG_G_INFO "dom%d mfn %#lx page->count_info %#lx\n",
                   d->domain_id, mfn + i, page->count_info);
            return -EBUSY;
        }
        page_set_owner(page, NULL);
    }

    for ( i = 0; i < npages; i++ )
        share_xen_page_with_guest(mfn_to_page(mfn + i), d, XENSHARE_writable);

    return 0;
}

static void
unshare_xenoprof_page_with_guest(struct xenoprof *x)
{
    int i, npages = x->npages;
    unsigned long mfn = virt_to_mfn(x->rawbuf);

    for ( i = 0; i < npages; i++ )
    {
        struct page_info *page = mfn_to_page(mfn + i);
        BUG_ON(page_get_owner(page) != current->domain);
        if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
            put_page(page);
    }
}

static void
xenoprof_shared_gmfn_with_guest(
    struct domain *d, unsigned long maddr, unsigned long gmaddr, int npages)
{
    int i;
    
    for ( i = 0; i < npages; i++, maddr += PAGE_SIZE, gmaddr += PAGE_SIZE )
    {
        BUG_ON(page_get_owner(maddr_to_page(maddr)) != d);
        xenoprof_shared_gmfn(d, gmaddr, maddr);
    }
}

static int alloc_xenoprof_struct(
    struct domain *d, int max_samples, int is_passive)
{
    struct vcpu *v;
    int nvcpu, npages, bufsize, max_bufsize;
    unsigned max_max_samples;
    int i;

    nvcpu = 0;
    for_each_vcpu ( d, v )
        nvcpu++;

    if ( !nvcpu )
        return -EINVAL;

    d->xenoprof = xzalloc(struct xenoprof);
    if ( d->xenoprof == NULL )
    {
        printk("alloc_xenoprof_struct(): memory allocation failed\n");
        return -ENOMEM;
    }

    d->xenoprof->vcpu = xzalloc_array(struct xenoprof_vcpu, d->max_vcpus);
    if ( d->xenoprof->vcpu == NULL )
    {
        xfree(d->xenoprof);
        d->xenoprof = NULL;
        printk("alloc_xenoprof_struct(): vcpu array allocation failed\n");
        return -ENOMEM;
    }

    bufsize = sizeof(struct xenoprof_buf);
    i = sizeof(struct event_log);
#ifdef CONFIG_COMPAT
    d->xenoprof->is_compat = is_pv_32bit_domain(is_passive ? hardware_domain : d);
    if ( XENOPROF_COMPAT(d->xenoprof) )
    {
        bufsize = sizeof(struct compat_oprof_buf);
        i = sizeof(struct compat_event_log);
    }
#endif

    /* reduce max_samples if necessary to limit pages allocated */
    max_bufsize = (MAX_OPROF_SHARED_PAGES * PAGE_SIZE) / nvcpu;
    max_max_samples = ( (max_bufsize - bufsize) / i ) + 1;
    if ( (unsigned)max_samples > max_max_samples )
        max_samples = max_max_samples;

    bufsize += (max_samples - 1) * i;
    npages = (nvcpu * bufsize - 1) / PAGE_SIZE + 1;

    d->xenoprof->rawbuf = alloc_xenheap_pages(get_order_from_pages(npages), 0);
    if ( d->xenoprof->rawbuf == NULL )
    {
        xfree(d->xenoprof->vcpu);
        xfree(d->xenoprof);
        d->xenoprof = NULL;
        return -ENOMEM;
    }

    d->xenoprof->npages = npages;
    d->xenoprof->nbuf = nvcpu;
    d->xenoprof->bufsize = bufsize;
    d->xenoprof->domain_ready = 0;
    d->xenoprof->domain_type = XENOPROF_DOMAIN_IGNORED;

    /* Update buffer pointers for active vcpus */
    i = 0;
    for_each_vcpu ( d, v )
    {
        xenoprof_buf_t *buf = (xenoprof_buf_t *)
            &d->xenoprof->rawbuf[i * bufsize];

        d->xenoprof->vcpu[v->vcpu_id].event_size = max_samples;
        d->xenoprof->vcpu[v->vcpu_id].buffer = buf;
        xenoprof_buf(d, buf, event_size) = max_samples;
        xenoprof_buf(d, buf, vcpu_id) = v->vcpu_id;

        i++;
        /* in the unlikely case that the number of active vcpus changes */
        if ( i >= nvcpu )
            break;
    }
    
    return 0;
}

void free_xenoprof_pages(struct domain *d)
{
    struct xenoprof *x;
    int order;

    x = d->xenoprof;
    if ( x == NULL )
        return;

    if ( x->rawbuf != NULL )
    {
        order = get_order_from_pages(x->npages);
        free_xenheap_pages(x->rawbuf, order);
    }

    xfree(x->vcpu);
    xfree(x);
    d->xenoprof = NULL;
}

static int active_index(struct domain *d)
{
    int i;

    for ( i = 0; i < adomains; i++ )
        if ( active_domains[i] == d )
            return i;

    return -1;
}

static int set_active(struct domain *d)
{
    int ind;
    struct xenoprof *x;

    ind = active_index(d);
    if ( ind < 0 )
        return -EPERM;

    x = d->xenoprof;
    if ( x == NULL )
        return -EPERM;

    x->domain_ready = 1;
    x->domain_type = XENOPROF_DOMAIN_ACTIVE;
    active_ready[ind] = 1;
    activated++;

    return 0;
}

static int reset_active(struct domain *d)
{
    int ind;
    struct xenoprof *x;

    ind = active_index(d);
    if ( ind < 0 )
        return -EPERM;

    x = d->xenoprof;
    if ( x == NULL )
        return -EPERM;

    x->domain_ready = 0;
    x->domain_type = XENOPROF_DOMAIN_IGNORED;
    active_ready[ind] = 0;
    active_domains[ind] = NULL;
    activated--;
    put_domain(d);

    if ( activated <= 0 )
        adomains = 0;

    return 0;
}

static void reset_passive(struct domain *d)
{
    struct xenoprof *x;

    if ( d == NULL )
        return;

    x = d->xenoprof;
    if ( x == NULL )
        return;

    unshare_xenoprof_page_with_guest(x);
    x->domain_type = XENOPROF_DOMAIN_IGNORED;
}

static void reset_active_list(void)
{
    int i;

    for ( i = 0; i < adomains; i++ )
        if ( active_ready[i] )
            reset_active(active_domains[i]);

    adomains = 0;
    activated = 0;
}

static void reset_passive_list(void)
{
    int i;

    for ( i = 0; i < pdomains; i++ )
    {
        reset_passive(passive_domains[i]);
        put_domain(passive_domains[i]);
        passive_domains[i] = NULL;
    }

    pdomains = 0;
}

static int add_active_list(domid_t domid)
{
    struct domain *d;

    if ( adomains >= MAX_OPROF_DOMAINS )
        return -E2BIG;

    d = get_domain_by_id(domid);
    if ( d == NULL )
        return -EINVAL;

    active_domains[adomains] = d;
    active_ready[adomains] = 0;
    adomains++;

    return 0;
}

static int add_passive_list(XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct xenoprof_passive passive;
    struct domain *d;
    int ret = 0;

    if ( pdomains >= MAX_OPROF_DOMAINS )
        return -E2BIG;

    if ( copy_from_guest(&passive, arg, 1) )
        return -EFAULT;

    d = get_domain_by_id(passive.domain_id);
    if ( d == NULL )
        return -EINVAL;

    if ( d->xenoprof == NULL )
    {
        ret = alloc_xenoprof_struct(d, passive.max_samples, 1);
        if ( ret < 0 )
        {
            put_domain(d);
            return -ENOMEM;
        }
    }

    ret = share_xenoprof_page_with_guest(
        current->domain, virt_to_mfn(d->xenoprof->rawbuf),
        d->xenoprof->npages);
    if ( ret < 0 )
    {
        put_domain(d);
        return ret;
    }

    d->xenoprof->domain_type = XENOPROF_DOMAIN_PASSIVE;
    passive.nbuf = d->xenoprof->nbuf;
    passive.bufsize = d->xenoprof->bufsize;
    if ( !paging_mode_translate(current->domain) )
        passive.buf_gmaddr = __pa(d->xenoprof->rawbuf);
    else
        xenoprof_shared_gmfn_with_guest(
            current->domain, __pa(d->xenoprof->rawbuf),
            passive.buf_gmaddr, d->xenoprof->npages);

    if ( __copy_to_guest(arg, &passive, 1) )
    {
        put_domain(d);
        return -EFAULT;
    }
    
    passive_domains[pdomains] = d;
    pdomains++;

    return ret;
}


/* Get space in the buffer */
static int xenoprof_buf_space(struct domain *d, xenoprof_buf_t * buf, int size)
{
    int head, tail;

    head = xenoprof_buf(d, buf, event_head);
    tail = xenoprof_buf(d, buf, event_tail);

    return ((tail > head) ? 0 : size) + tail - head - 1;
}

/* Check for space and add a sample. Return 1 if successful, 0 otherwise. */
static int xenoprof_add_sample(struct domain *d, xenoprof_buf_t *buf,
                               uint64_t eip, int mode, int event)
{
    int head, tail, size;

    head = xenoprof_buf(d, buf, event_head);
    tail = xenoprof_buf(d, buf, event_tail);
    size = xenoprof_buf(d, buf, event_size);
    
    /* make sure indexes in shared buffer are sane */
    if ( (head < 0) || (head >= size) || (tail < 0) || (tail >= size) )
    {
        corrupted_buffer_samples++;
        return 0;
    }

    if ( xenoprof_buf_space(d, buf, size) > 0 )
    {
        xenoprof_buf(d, buf, event_log[head].eip) = eip;
        xenoprof_buf(d, buf, event_log[head].mode) = mode;
        xenoprof_buf(d, buf, event_log[head].event) = event;
        head++;
        if ( head >= size )
            head = 0;
        
        xenoprof_buf(d, buf, event_head) = head;
    }
    else
    {
        xenoprof_buf(d, buf, lost_samples)++;
        lost_samples++;
        return 0;
    }

    return 1;
}

int xenoprof_add_trace(struct vcpu *vcpu, uint64_t pc, int mode)
{
    struct domain *d = vcpu->domain;
    xenoprof_buf_t *buf = d->xenoprof->vcpu[vcpu->vcpu_id].buffer;

    /* Do not accidentally write an escape code due to a broken frame. */
    if ( pc == XENOPROF_ESCAPE_CODE )
    {
        invalid_buffer_samples++;
        return 0;
    }

    return xenoprof_add_sample(d, buf, pc, mode, 0);
}

void xenoprof_log_event(struct vcpu *vcpu, const struct cpu_user_regs *regs,
                        uint64_t pc, int mode, int event)
{
    struct domain *d = vcpu->domain;
    struct xenoprof_vcpu *v;
    xenoprof_buf_t *buf;

    total_samples++;

    /* Ignore samples of un-monitored domains. */
    if ( !is_profiled(d) )
    {
        others_samples++;
        return;
    }

    v = &d->xenoprof->vcpu[vcpu->vcpu_id];
    if ( v->buffer == NULL )
    {
        invalid_buffer_samples++;
        return;
    }
    
    buf = v->buffer;

    /* Provide backtrace if requested. */
    if ( backtrace_depth > 0 )
    {
        if ( (xenoprof_buf_space(d, buf, v->event_size) < 2) ||
             !xenoprof_add_sample(d, buf, XENOPROF_ESCAPE_CODE, mode, 
                                  XENOPROF_TRACE_BEGIN) )
        {
            xenoprof_buf(d, buf, lost_samples)++;
            lost_samples++;
            return;
        }
    }

    if ( xenoprof_add_sample(d, buf, pc, mode, event) )
    {
        if ( is_active(vcpu->domain) )
            active_samples++;
        else
            passive_samples++;
        if ( mode == 0 )
            xenoprof_buf(d, buf, user_samples)++;
        else if ( mode == 1 )
            xenoprof_buf(d, buf, kernel_samples)++;
        else
            xenoprof_buf(d, buf, xen_samples)++;
    
    }

    if ( backtrace_depth > 0 )
        xenoprof_backtrace(vcpu, regs, backtrace_depth, mode);
}



static int xenoprof_op_init(XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct domain *d = current->domain;
    struct xenoprof_init xenoprof_init;
    int ret;

    if ( copy_from_guest(&xenoprof_init, arg, 1) )
        return -EFAULT;

    if ( (ret = xenoprof_arch_init(&xenoprof_init.num_events,
                                   xenoprof_init.cpu_type)) )
        return ret;

    /* Only the hardware domain may become the primary profiler here because
     * there is currently no cleanup of xenoprof_primary_profiler or associated
     * profiling state when the primary profiling domain is shut down or
     * crashes.  Once a better cleanup method is present, it will be possible to
     * allow another domain to be the primary profiler.
     */
    xenoprof_init.is_primary = 
        ((xenoprof_primary_profiler == d) ||
         ((xenoprof_primary_profiler == NULL) && is_hardware_domain(d)));
    if ( xenoprof_init.is_primary )
        xenoprof_primary_profiler = current->domain;

    return __copy_to_guest(arg, &xenoprof_init, 1) ? -EFAULT : 0;
}

#define ret_t long

#endif /* !COMPAT */

static int xenoprof_op_get_buffer(XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct xenoprof_get_buffer xenoprof_get_buffer;
    struct domain *d = current->domain;
    int ret;

    if ( copy_from_guest(&xenoprof_get_buffer, arg, 1) )
        return -EFAULT;

    /*
     * We allocate xenoprof struct and buffers only at first time
     * get_buffer is called. Memory is then kept until domain is destroyed.
     */
    if ( d->xenoprof == NULL )
    {
        ret = alloc_xenoprof_struct(d, xenoprof_get_buffer.max_samples, 0);
        if ( ret < 0 )
            return ret;
    }

    ret = share_xenoprof_page_with_guest(
        d, virt_to_mfn(d->xenoprof->rawbuf), d->xenoprof->npages);
    if ( ret < 0 )
        return ret;

    xenoprof_reset_buf(d);

    d->xenoprof->domain_type  = XENOPROF_DOMAIN_IGNORED;
    d->xenoprof->domain_ready = 0;
    d->xenoprof->is_primary   = (xenoprof_primary_profiler == current->domain);
        
    xenoprof_get_buffer.nbuf = d->xenoprof->nbuf;
    xenoprof_get_buffer.bufsize = d->xenoprof->bufsize;
    if ( !paging_mode_translate(d) )
        xenoprof_get_buffer.buf_gmaddr = __pa(d->xenoprof->rawbuf);
    else
        xenoprof_shared_gmfn_with_guest(
            d, __pa(d->xenoprof->rawbuf), xenoprof_get_buffer.buf_gmaddr,
            d->xenoprof->npages);

    return __copy_to_guest(arg, &xenoprof_get_buffer, 1) ? -EFAULT : 0;
}

#define NONPRIV_OP(op) ( (op == XENOPROF_init)          \
                      || (op == XENOPROF_enable_virq)   \
                      || (op == XENOPROF_disable_virq)  \
                      || (op == XENOPROF_get_buffer))
 
ret_t do_xenoprof_op(int op, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    int ret = 0;
    
    if ( (op < 0) || (op > XENOPROF_last_op) )
    {
        gdprintk(XENLOG_DEBUG, "invalid operation %d\n", op);
        return -EINVAL;
    }

    if ( !NONPRIV_OP(op) && (current->domain != xenoprof_primary_profiler) )
    {
        gdprintk(XENLOG_DEBUG, "denied privileged operation %d\n", op);
        return -EPERM;
    }

    ret = xsm_profile(XSM_HOOK, current->domain, op);
    if ( ret )
        return ret;

    spin_lock(&xenoprof_lock);
    
    switch ( op )
    {
    case XENOPROF_init:
        ret = xenoprof_op_init(arg);
        if ( (ret == 0) &&
             (current->domain == xenoprof_primary_profiler) )
            xenoprof_state = XENOPROF_INITIALIZED;
        break;

    case XENOPROF_get_buffer:
        if ( !acquire_pmu_ownership(PMU_OWNER_XENOPROF) )
        {
            ret = -EBUSY;
            break;
        }
        ret = xenoprof_op_get_buffer(arg);
        break;

    case XENOPROF_reset_active_list:
        reset_active_list();
        ret = 0;
        break;

    case XENOPROF_reset_passive_list:
        reset_passive_list();
        ret = 0;
        break;

    case XENOPROF_set_active:
    {
        domid_t domid;
        if ( xenoprof_state != XENOPROF_INITIALIZED )
        {
            ret = -EPERM;
            break;
        }
        if ( copy_from_guest(&domid, arg, 1) )
        {
            ret = -EFAULT;
            break;
        }
        ret = add_active_list(domid);
        break;
    }

    case XENOPROF_set_passive:
        if ( xenoprof_state != XENOPROF_INITIALIZED )
        {
            ret = -EPERM;
            break;
        }
        ret = add_passive_list(arg);
        break;

    case XENOPROF_reserve_counters:
        if ( xenoprof_state != XENOPROF_INITIALIZED )
        {
            ret = -EPERM;
            break;
        }
        ret = xenoprof_arch_reserve_counters();
        if ( !ret )
            xenoprof_state = XENOPROF_COUNTERS_RESERVED;
        break;

    case XENOPROF_counter:
        if ( (xenoprof_state != XENOPROF_COUNTERS_RESERVED) ||
             (adomains == 0) )
        {
            ret = -EPERM;
            break;
        }
        ret = xenoprof_arch_counter(arg);
        break;

    case XENOPROF_setup_events:
        if ( xenoprof_state != XENOPROF_COUNTERS_RESERVED )
        {
            ret = -EPERM;
            break;
        }
        ret = xenoprof_arch_setup_events();
        if ( !ret )
            xenoprof_state = XENOPROF_READY;
        break;

    case XENOPROF_enable_virq:
    {
        int i;

        if ( current->domain == xenoprof_primary_profiler )
        {
            if ( xenoprof_state != XENOPROF_READY )
            {
                ret = -EPERM;
                break;
            }
            xenoprof_arch_enable_virq();
            xenoprof_reset_stat();
            for ( i = 0; i < pdomains; i++ )
                xenoprof_reset_buf(passive_domains[i]);
        }
        xenoprof_reset_buf(current->domain);
        ret = set_active(current->domain);
        break;
    }

    case XENOPROF_start:
        ret = -EPERM;
        if ( (xenoprof_state == XENOPROF_READY) &&
             (activated == adomains) )
            ret = xenoprof_arch_start();
        if ( ret == 0 )
            xenoprof_state = XENOPROF_PROFILING;
        break;

    case XENOPROF_stop:
    {
        struct domain *d;
        struct vcpu *v;
        int i;

        if ( xenoprof_state != XENOPROF_PROFILING )
        {
            ret = -EPERM;
            break;
        }
        xenoprof_arch_stop();

        /* Flush remaining samples. */
        for ( i = 0; i < adomains; i++ )
        {
            if ( !active_ready[i] )
                continue;
            d = active_domains[i];
            for_each_vcpu(d, v)
                send_guest_vcpu_virq(v, VIRQ_XENOPROF);
        }
        xenoprof_state = XENOPROF_READY;
        break;
    }

    case XENOPROF_disable_virq:
    {
        struct xenoprof *x;
        if ( (xenoprof_state == XENOPROF_PROFILING) && 
             (is_active(current->domain)) )
        {
            ret = -EPERM;
            break;
        }
        if ( (ret = reset_active(current->domain)) != 0 )
            break;
        x = current->domain->xenoprof;
        unshare_xenoprof_page_with_guest(x);
        release_pmu_ownship(PMU_OWNER_XENOPROF);
        break;
    }

    case XENOPROF_release_counters:
        ret = -EPERM;
        if ( (xenoprof_state == XENOPROF_COUNTERS_RESERVED) ||
             (xenoprof_state == XENOPROF_READY) )
        {
            xenoprof_state = XENOPROF_INITIALIZED;
            xenoprof_arch_release_counters();
            xenoprof_arch_disable_virq();
            reset_passive_list();
            ret = 0;
        }
        break;

    case XENOPROF_shutdown:
        ret = -EPERM;
        if ( xenoprof_state == XENOPROF_INITIALIZED )
        {
            activated = 0;
            adomains=0;
            xenoprof_primary_profiler = NULL;
            backtrace_depth=0;
            ret = 0;
        }
        break;
                
    case XENOPROF_set_backtrace:
        ret = 0;
        if ( !xenoprof_backtrace_supported() )
            ret = -EINVAL;
        else if ( copy_from_guest(&backtrace_depth, arg, 1) )
            ret = -EFAULT;
        break;

    case XENOPROF_ibs_counter:
        if ( (xenoprof_state != XENOPROF_COUNTERS_RESERVED) ||
             (adomains == 0) )
        {
            ret = -EPERM;
            break;
        }
        ret = xenoprof_arch_ibs_counter(arg);
        break;

    case XENOPROF_get_ibs_caps:
        ret = ibs_caps;
        break;

    default:
        ret = -ENOSYS;
    }

    spin_unlock(&xenoprof_lock);

    if ( ret < 0 )
        gdprintk(XENLOG_DEBUG, "operation %d failed: %d\n", op, ret);

    return ret;
}

#if defined(CONFIG_COMPAT) && !defined(COMPAT)
#undef ret_t
#include "compat/xenoprof.c"
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
