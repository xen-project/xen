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

#include <xen/guest_access.h>
#include <xen/sched.h>
#include <public/xenoprof.h>
#include <asm/shadow.h>

/* Limit amount of pages used for shared buffer (per domain) */
#define MAX_OPROF_SHARED_PAGES 32

/* Lock protecting the following global state */
static DEFINE_SPINLOCK(xenoprof_lock);

struct domain *active_domains[MAX_OPROF_DOMAINS];
int active_ready[MAX_OPROF_DOMAINS];
unsigned int adomains;

struct domain *passive_domains[MAX_OPROF_DOMAINS];
unsigned int pdomains;

unsigned int activated;
struct domain *xenoprof_primary_profiler;
int xenoprof_state = XENOPROF_IDLE;

u64 total_samples;
u64 invalid_buffer_samples;
u64 corrupted_buffer_samples;
u64 lost_samples;
u64 active_samples;
u64 passive_samples;
u64 idle_samples;
u64 others_samples;

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

int is_profiled(struct domain *d)
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
    struct xenoprof_buf *buf;

    if ( d->xenoprof == NULL )
    {
        printk("xenoprof_reset_buf: ERROR - Unexpected "
               "Xenoprof NULL pointer \n");
        return;
    }

    for ( j = 0; j < MAX_VIRT_CPUS; j++ )
    {
        buf = d->xenoprof->vcpu[j].buffer;
        if ( buf != NULL )
        {
            buf->event_head = 0;
            buf->event_tail = 0;
        }
    }
}

static void
share_xenoprof_page_with_guest(struct domain* d, unsigned long mfn, int npages)
{
    int i;
    
    for ( i = 0; i < npages; i++ )
        share_xen_page_with_guest(mfn_to_page(mfn + i), d, XENSHARE_writable);
}

static void
unshare_xenoprof_page_with_guest(unsigned long mfn, int npages)
{
    int i;

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
    struct domain* d, unsigned long maddr, unsigned long gmaddr, int npages)
{
    int i;
    
    for ( i = 0; i < npages; i++, maddr += PAGE_SIZE, gmaddr += PAGE_SIZE )
    {
        BUG_ON(page_get_owner(maddr_to_page(maddr)) != d);
        xenoprof_shared_gmfn(d, gmaddr, maddr);
    }
}

static char *alloc_xenoprof_buf(struct domain *d, int npages)
{
    char *rawbuf;
    int order;

    /* allocate pages to store sample buffer shared with domain */
    order  = get_order_from_pages(npages);
    rawbuf = alloc_xenheap_pages(order);
    if ( rawbuf == NULL )
    {
        printk("alloc_xenoprof_buf(): memory allocation failed\n");
        return 0;
    }

    return rawbuf;
}

static int alloc_xenoprof_struct(
    struct domain *d, int max_samples, int is_passive)
{
    struct vcpu *v;
    int nvcpu, npages, bufsize, max_bufsize;
    unsigned max_max_samples;
    int i;

    d->xenoprof = xmalloc(struct xenoprof);

    if ( d->xenoprof == NULL )
    {
        printk ("alloc_xenoprof_struct(): memory "
                "allocation (xmalloc) failed\n");
        return -ENOMEM;
    }

    memset(d->xenoprof, 0, sizeof(*d->xenoprof));

    nvcpu = 0;
    for_each_vcpu ( d, v )
        nvcpu++;

    /* reduce max_samples if necessary to limit pages allocated */
    max_bufsize = (MAX_OPROF_SHARED_PAGES * PAGE_SIZE) / nvcpu;
    max_max_samples = ( (max_bufsize - sizeof(struct xenoprof_buf)) /
                        sizeof(struct event_log) ) + 1;
    if ( (unsigned)max_samples > max_max_samples )
        max_samples = max_max_samples;

    bufsize = sizeof(struct xenoprof_buf) +
        (max_samples - 1) * sizeof(struct event_log);
    npages = (nvcpu * bufsize - 1) / PAGE_SIZE + 1;
    
    d->xenoprof->rawbuf = alloc_xenoprof_buf(is_passive ? dom0 : d, npages);

    if ( d->xenoprof->rawbuf == NULL )
    {
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
        d->xenoprof->vcpu[v->vcpu_id].event_size = max_samples;
        d->xenoprof->vcpu[v->vcpu_id].buffer =
            (struct xenoprof_buf *)&d->xenoprof->rawbuf[i * bufsize];
        d->xenoprof->vcpu[v->vcpu_id].buffer->event_size = max_samples;
        d->xenoprof->vcpu[v->vcpu_id].buffer->vcpu_id = v->vcpu_id;

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

    if ( d == 0 )
        return;

    x = d->xenoprof;
    if ( x == NULL )
        return;

    unshare_xenoprof_page_with_guest(virt_to_mfn(x->rawbuf), x->npages);
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

    d = find_domain_by_id(domid);
    if ( d == NULL )
        return -EINVAL;

    active_domains[adomains] = d;
    active_ready[adomains] = 0;
    adomains++;

    return 0;
}

static int add_passive_list(XEN_GUEST_HANDLE(void) arg)
{
    struct xenoprof_passive passive;
    struct domain *d;
    int ret = 0;

    if ( pdomains >= MAX_OPROF_DOMAINS )
        return -E2BIG;

    if ( copy_from_guest(&passive, arg, 1) )
        return -EFAULT;

    d = find_domain_by_id(passive.domain_id);
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

    share_xenoprof_page_with_guest(
        current->domain, virt_to_mfn(d->xenoprof->rawbuf),
        d->xenoprof->npages);

    d->xenoprof->domain_type = XENOPROF_DOMAIN_PASSIVE;
    passive.nbuf = d->xenoprof->nbuf;
    passive.bufsize = d->xenoprof->bufsize;
    if ( !shadow_mode_translate(d) )
        passive.buf_gmaddr = __pa(d->xenoprof->rawbuf);
    else
        xenoprof_shared_gmfn_with_guest(
            current->domain, __pa(d->xenoprof->rawbuf),
            passive.buf_gmaddr, d->xenoprof->npages);

    if ( copy_to_guest(arg, &passive, 1) )
    {
        put_domain(d);
        return -EFAULT;
    }
    
    passive_domains[pdomains] = d;
    pdomains++;

    return ret;
}

void xenoprof_log_event(
    struct vcpu *vcpu, unsigned long eip, int mode, int event)
{
    struct xenoprof_vcpu *v;
    struct xenoprof_buf *buf;
    int head;
    int tail;
    int size;


    total_samples++;

    /* ignore samples of un-monitored domains */
    /* Count samples in idle separate from other unmonitored domains */
    if ( !is_profiled(vcpu->domain) )
    {
        others_samples++;
        return;
    }

    v = &vcpu->domain->xenoprof->vcpu[vcpu->vcpu_id];

    /* Sanity check. Should never happen */ 
    if ( v->buffer == NULL )
    {
        invalid_buffer_samples++;
        return;
    }

    buf = vcpu->domain->xenoprof->vcpu[vcpu->vcpu_id].buffer;

    head = buf->event_head;
    tail = buf->event_tail;
    size = v->event_size;

    /* make sure indexes in shared buffer are sane */
    if ( (head < 0) || (head >= size) || (tail < 0) || (tail >= size) )
    {
        corrupted_buffer_samples++;
        return;
    }

    if ( (head == tail - 1) || (head == size - 1 && tail == 0) )
    {
        buf->lost_samples++;
        lost_samples++;
    }
    else
    {
        buf->event_log[head].eip = eip;
        buf->event_log[head].mode = mode;
        buf->event_log[head].event = event;
        head++;
        if ( head >= size )
            head = 0;
        buf->event_head = head;
        if ( is_active(vcpu->domain) )
            active_samples++;
        else
            passive_samples++;
        if ( mode == 0 )
            buf->user_samples++;
        else if ( mode == 1 )
            buf->kernel_samples++;
        else
            buf->xen_samples++;
    }
}

static int xenoprof_op_init(XEN_GUEST_HANDLE(void) arg)
{
    struct xenoprof_init xenoprof_init;
    int ret;

    if ( copy_from_guest(&xenoprof_init, arg, 1) )
        return -EFAULT;

    if ( (ret = xenoprof_arch_init(&xenoprof_init.num_events, 
                                   &xenoprof_init.is_primary, 
                                   xenoprof_init.cpu_type)) )
        return ret;

    if ( copy_to_guest(arg, &xenoprof_init, 1) )
        return -EFAULT;

    if ( xenoprof_init.is_primary )
        xenoprof_primary_profiler = current->domain;

    return 0;
}

static int xenoprof_op_get_buffer(XEN_GUEST_HANDLE(void) arg)
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

    share_xenoprof_page_with_guest(
        d, virt_to_mfn(d->xenoprof->rawbuf), d->xenoprof->npages);

    xenoprof_reset_buf(d);

    d->xenoprof->domain_type  = XENOPROF_DOMAIN_IGNORED;
    d->xenoprof->domain_ready = 0;
    d->xenoprof->is_primary   = (xenoprof_primary_profiler == current->domain);
        
    xenoprof_get_buffer.nbuf = d->xenoprof->nbuf;
    xenoprof_get_buffer.bufsize = d->xenoprof->bufsize;
    if ( !shadow_mode_translate(d) )
        xenoprof_get_buffer.buf_gmaddr = __pa(d->xenoprof->rawbuf);
    else
        xenoprof_shared_gmfn_with_guest(
            d, __pa(d->xenoprof->rawbuf), xenoprof_get_buffer.buf_gmaddr,
            d->xenoprof->npages);

    if ( copy_to_guest(arg, &xenoprof_get_buffer, 1) )
        return -EFAULT;

    return 0;
}

#define NONPRIV_OP(op) ( (op == XENOPROF_init)          \
                      || (op == XENOPROF_enable_virq)   \
                      || (op == XENOPROF_disable_virq)  \
                      || (op == XENOPROF_get_buffer))
 
int do_xenoprof_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    int ret = 0;
    
    if ( (op < 0) || (op > XENOPROF_last_op) )
    {
        printk("xenoprof: invalid operation %d for domain %d\n",
               op, current->domain->domain_id);
        return -EINVAL;
    }

    if ( !NONPRIV_OP(op) && (current->domain != xenoprof_primary_profiler) )
    {
        printk("xenoprof: dom %d denied privileged operation %d\n",
               current->domain->domain_id, op);
        return -EPERM;
    }

    spin_lock(&xenoprof_lock);
    
    switch ( op )
    {
    case XENOPROF_init:
        ret = xenoprof_op_init(arg);
        break;

    case XENOPROF_get_buffer:
        ret = xenoprof_op_get_buffer(arg);
        break;

    case XENOPROF_reset_active_list:
    {
        reset_active_list();
        ret = 0;
        break;
    }
    case XENOPROF_reset_passive_list:
    {
        reset_passive_list();
        ret = 0;
        break;
    }
    case XENOPROF_set_active:
    {
        domid_t domid;
        if ( xenoprof_state != XENOPROF_IDLE )
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
    {
        if ( xenoprof_state != XENOPROF_IDLE )
        {
            ret = -EPERM;
            break;
        }
        ret = add_passive_list(arg);
        break;
    }
    case XENOPROF_reserve_counters:
        if ( xenoprof_state != XENOPROF_IDLE )
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
        if ( xenoprof_state != XENOPROF_PROFILING ) {
            ret = -EPERM;
            break;
        }
        xenoprof_arch_stop();
        xenoprof_state = XENOPROF_READY;
        break;

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
        unshare_xenoprof_page_with_guest(virt_to_mfn(x->rawbuf), x->npages);
        break;
    }

    case XENOPROF_release_counters:
        ret = -EPERM;
        if ( (xenoprof_state == XENOPROF_COUNTERS_RESERVED) ||
             (xenoprof_state == XENOPROF_READY) )
        {
            xenoprof_state = XENOPROF_IDLE;
            xenoprof_arch_release_counters();
            xenoprof_arch_disable_virq();
            reset_passive_list();
            ret = 0;
        }
        break;

    case XENOPROF_shutdown:
        ret = -EPERM;
        if ( xenoprof_state == XENOPROF_IDLE )
        {
            activated = 0;
            adomains=0;
            xenoprof_primary_profiler = NULL;
            ret = 0;
        }
        break;

    default:
        ret = -ENOSYS;
    }

    spin_unlock(&xenoprof_lock);

    if ( ret < 0 )
        printk("xenoprof: operation %d failed for dom %d (status : %d)\n",
               op, current->domain->domain_id, ret);

    return ret;
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
