/*
 * Copyright (C) 2005 Hewlett-Packard Co.
 * written by Aravind Menon & Jose Renato Santos
 *            (email: xenoprof@groups.hp.com)
 */

#include <xen/guest_access.h>
#include <xen/sched.h>
#include <public/xenoprof.h>

#include "op_counter.h"

/* Limit amount of pages used for shared buffer (per domain) */
#define MAX_OPROF_SHARED_PAGES 32

domid_t active_domains[MAX_OPROF_DOMAINS];
int active_ready[MAX_OPROF_DOMAINS];
unsigned int adomains;
unsigned int activated;
struct domain *primary_profiler;
int xenoprof_state = XENOPROF_IDLE;

u64 total_samples;
u64 invalid_buffer_samples;
u64 corrupted_buffer_samples;
u64 lost_samples;
u64 active_samples;
u64 idle_samples;
u64 others_samples;


extern int nmi_init(int *num_events, int *is_primary, char *cpu_type);
extern int nmi_reserve_counters(void);
extern int nmi_setup_events(void);
extern int nmi_enable_virq(void);
extern int nmi_start(void);
extern void nmi_stop(void);
extern void nmi_disable_virq(void);
extern void nmi_release_counters(void);

int is_active(struct domain *d)
{
    struct xenoprof *x = d->xenoprof;
    return ((x != NULL) && (x->domain_type == XENOPROF_DOMAIN_ACTIVE));
}

int is_profiled(struct domain *d)
{
    return is_active(d);
}

static void xenoprof_reset_stat(void)
{
    total_samples = 0;
    invalid_buffer_samples = 0;
    corrupted_buffer_samples = 0;
    lost_samples = 0;
    active_samples = 0;
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

int active_index(struct domain *d)
{
    int i;
    domid_t id = d->domain_id;

    for ( i = 0; i < adomains; i++ )
        if ( active_domains[i] == id )
            return i;

    return -1;
}

int set_active(struct domain *d)
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

int reset_active(struct domain *d)
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
    activated--;
    if ( activated <= 0 )
        adomains = 0;

    return 0;
}

int reset_active_list(void)
{
    int i;
    struct domain *d;

    for ( i = 0; i < adomains; i++ )
    {
        if ( active_ready[i] )
        {
            d = find_domain_by_id(active_domains[i]);
            if ( d != NULL )
            {
                reset_active(d);
                put_domain(d);
            }
        }
    }

    adomains = 0;
    activated = 0;

    return 0;
}

int add_active_list (domid_t domid)
{
    if ( adomains >= MAX_OPROF_DOMAINS )
        return -E2BIG;

    active_domains[adomains] = domid;
    active_ready[adomains] = 0;
    adomains++;

    return 0;
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
        active_samples++;
        if ( mode == 0 )
            buf->user_samples++;
        else if ( mode == 1 )
            buf->kernel_samples++;
        else
            buf->xen_samples++;
    }
}

char *alloc_xenoprof_buf(struct domain *d, int npages)
{
    char *rawbuf;
    int i, order;

    /* allocate pages to store sample buffer shared with domain */
    order  = get_order_from_pages(npages);
    rawbuf = alloc_xenheap_pages(order);
    if ( rawbuf == NULL )
    {
        printk("alloc_xenoprof_buf(): memory allocation failed\n");
        return 0;
    }

    /* Share pages so that kernel can map it */
    for ( i = 0; i < npages; i++ )
        share_xen_page_with_guest(
            virt_to_page(rawbuf + i * PAGE_SIZE), 
            d, XENSHARE_writable);

    return rawbuf;
}

int alloc_xenoprof_struct(struct domain *d, int max_samples)
{
    struct vcpu *v;
    int nvcpu, npages, bufsize, max_bufsize;
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

    /* reduce buffer size if necessary to limit pages allocated */
    bufsize = sizeof(struct xenoprof_buf) +
        (max_samples - 1) * sizeof(struct event_log);
    max_bufsize = (MAX_OPROF_SHARED_PAGES * PAGE_SIZE) / nvcpu;
    if ( bufsize > max_bufsize )
    {
        bufsize = max_bufsize;
        max_samples = ( (max_bufsize - sizeof(struct xenoprof_buf)) /
                        sizeof(struct event_log) ) + 1;
    }

    npages = (nvcpu * bufsize - 1) / PAGE_SIZE + 1;
    d->xenoprof->rawbuf = alloc_xenoprof_buf(d, npages);
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

int xenoprof_op_init(XEN_GUEST_HANDLE(void) arg)
{
    struct xenoprof_init xenoprof_init;
    int is_primary, num_events;
    struct domain *d = current->domain;
    int ret;

    if ( copy_from_guest(&xenoprof_init, arg, 1) )
        return -EFAULT;

    ret = nmi_init(&num_events, 
                   &is_primary, 
                   xenoprof_init.cpu_type);
    if ( ret < 0 )
        goto err;

    if ( is_primary )
        primary_profiler = current->domain;

    /*
     * We allocate xenoprof struct and buffers only at first time xenoprof_init
     * is called. Memory is then kept until domain is destroyed.
     */
    if ( (d->xenoprof == NULL) &&
         ((ret = alloc_xenoprof_struct(d, xenoprof_init.max_samples)) < 0) )
        goto err;

    xenoprof_reset_buf(d);

    d->xenoprof->domain_type  = XENOPROF_DOMAIN_IGNORED;
    d->xenoprof->domain_ready = 0;
    d->xenoprof->is_primary = is_primary;

    xenoprof_init.is_primary = is_primary;
    xenoprof_init.num_events = num_events;
    xenoprof_init.nbuf = d->xenoprof->nbuf;
    xenoprof_init.bufsize = d->xenoprof->bufsize;
    xenoprof_init.buf_maddr = __pa(d->xenoprof->rawbuf);

    if ( copy_to_guest(arg, &xenoprof_init, 1) )
    {
        ret = -EFAULT;
        goto err;
    }

    return ret;

 err:
    if ( primary_profiler == current->domain )
        primary_profiler = NULL;
    return ret;
}

#define PRIV_OP(op) ( (op == XENOPROF_set_active)       \
                   || (op == XENOPROF_reserve_counters) \
                   || (op == XENOPROF_setup_events)     \
                   || (op == XENOPROF_start)            \
                   || (op == XENOPROF_stop)             \
                   || (op == XENOPROF_release_counters) \
                   || (op == XENOPROF_shutdown))

int do_xenoprof_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    int ret = 0;

    if ( PRIV_OP(op) && (current->domain != primary_profiler) )
    {
        printk("xenoprof: dom %d denied privileged operation %d\n",
               current->domain->domain_id, op);
        return -EPERM;
    }

    switch ( op )
    {
    case XENOPROF_init:
        ret = xenoprof_op_init(arg);
        break;

    case XENOPROF_reset_active_list:
    {
        ret = reset_active_list();
        break;
    }
    case XENOPROF_set_active:
    {
        domid_t domid;
        if ( xenoprof_state != XENOPROF_IDLE )
            return -EPERM;
        if ( copy_from_guest(&domid, arg, 1) )
            return -EFAULT;
        ret = add_active_list(domid);
        break;
    }
    case XENOPROF_reserve_counters:
        if ( xenoprof_state != XENOPROF_IDLE )
            return -EPERM;
        ret = nmi_reserve_counters();
        if ( !ret )
            xenoprof_state = XENOPROF_COUNTERS_RESERVED;
        break;

    case XENOPROF_counter:
    {
        struct xenoprof_counter counter;
        if ( xenoprof_state != XENOPROF_COUNTERS_RESERVED )
            return -EPERM;
        if ( adomains == 0 )
            return -EPERM;

        if ( copy_from_guest(&counter, arg, 1) )
            return -EFAULT;

        if ( counter.ind > OP_MAX_COUNTER )
            return -E2BIG;

        counter_config[counter.ind].count     = (unsigned long) counter.count;
        counter_config[counter.ind].enabled   = (unsigned long) counter.enabled;
        counter_config[counter.ind].event     = (unsigned long) counter.event;
        counter_config[counter.ind].kernel    = (unsigned long) counter.kernel;
        counter_config[counter.ind].user      = (unsigned long) counter.user;
        counter_config[counter.ind].unit_mask = (unsigned long) counter.unit_mask;

        ret = 0;
        break;
    }

    case XENOPROF_setup_events:
        if ( xenoprof_state != XENOPROF_COUNTERS_RESERVED )
            return -EPERM;
        ret = nmi_setup_events();
        if ( !ret )
            xenoprof_state = XENOPROF_READY;
        break;

    case XENOPROF_enable_virq:
        if ( current->domain == primary_profiler )
        {
            nmi_enable_virq();
            xenoprof_reset_stat();
        }
        xenoprof_reset_buf(current->domain);
        ret = set_active(current->domain);
        break;

    case XENOPROF_start:
        ret = -EPERM;
        if ( (xenoprof_state == XENOPROF_READY) &&
             (activated == adomains) )
            ret = nmi_start();

        if ( ret == 0 )
            xenoprof_state = XENOPROF_PROFILING;
        break;

    case XENOPROF_stop:
        if ( xenoprof_state != XENOPROF_PROFILING )
            return -EPERM;
        nmi_stop();
        xenoprof_state = XENOPROF_READY;
        break;

    case XENOPROF_disable_virq:
        if ( (xenoprof_state == XENOPROF_PROFILING) && 
             (is_active(current->domain)) )
            return -EPERM;
        ret = reset_active(current->domain);
        break;

    case XENOPROF_release_counters:
        ret = -EPERM;
        if ( (xenoprof_state == XENOPROF_COUNTERS_RESERVED) ||
             (xenoprof_state == XENOPROF_READY) )
        {
            xenoprof_state = XENOPROF_IDLE;
            nmi_release_counters();
            nmi_disable_virq();
            ret = 0;
        }
        break;

    case XENOPROF_shutdown:
        ret = -EPERM;
        if ( xenoprof_state == XENOPROF_IDLE )
        {
            activated = 0;
            adomains=0;
            primary_profiler = NULL;
            ret = 0;
        }
        break;

    default:
        ret = -EINVAL;
    }

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
