/*
 * ioreq.c: hardware virtual machine I/O emulation
 *
 * Copyright (c) 2016 Citrix Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/domain.h>
#include <xen/domain_page.h>
#include <xen/event.h>
#include <xen/init.h>
#include <xen/ioreq.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/paging.h>
#include <xen/sched.h>
#include <xen/trace.h>

#include <asm/guest_atomics.h>
#include <asm/ioreq.h>

#include <public/hvm/ioreq.h>
#include <public/hvm/params.h>

void ioreq_request_mapcache_invalidate(const struct domain *d)
{
    struct vcpu *v = current;

    if ( d == v->domain )
        v->mapcache_invalidate = true;
    else if ( d->creation_finished )
        for_each_vcpu ( d, v )
            v->mapcache_invalidate = true;
}

/* Ask ioemu mapcache to invalidate mappings. */
void ioreq_signal_mapcache_invalidate(void)
{
    ioreq_t p = {
        .type = IOREQ_TYPE_INVALIDATE,
        .size = 4,
        .dir = IOREQ_WRITE,
        .data = ~0UL, /* flush all */
    };

    if ( ioreq_broadcast(&p, false) != 0 )
        gprintk(XENLOG_ERR, "Unsuccessful map-cache invalidate\n");
}

static void set_ioreq_server(struct domain *d, unsigned int id,
                             struct ioreq_server *s)
{
    ASSERT(id < MAX_NR_IOREQ_SERVERS);
    ASSERT(!s || !d->ioreq_server.server[id]);

    d->ioreq_server.server[id] = s;
}

#define GET_IOREQ_SERVER(d, id) \
    (d)->ioreq_server.server[id]

static struct ioreq_server *get_ioreq_server(const struct domain *d,
                                             unsigned int id)
{
    if ( id >= MAX_NR_IOREQ_SERVERS )
        return NULL;

    return GET_IOREQ_SERVER(d, id);
}

/*
 * Iterate over all possible ioreq servers.
 *
 * NOTE: The iteration is backwards such that more recently created
 *       ioreq servers are favoured in ioreq_server_select().
 *       This is a semantic that previously existed when ioreq servers
 *       were held in a linked list.
 */
#define FOR_EACH_IOREQ_SERVER(d, id, s) \
    for ( (id) = MAX_NR_IOREQ_SERVERS; (id) != 0; ) \
        if ( !(s = GET_IOREQ_SERVER(d, --(id))) ) \
            continue; \
        else

static ioreq_t *get_ioreq(struct ioreq_server *s, struct vcpu *v)
{
    shared_iopage_t *p = s->ioreq.va;

    ASSERT((v == current) || !vcpu_runnable(v));
    ASSERT(p != NULL);

    return &p->vcpu_ioreq[v->vcpu_id];
}

/*
 * This should only be used when d == current->domain or when they're
 * distinct and d is paused. Otherwise the result is stale before
 * the caller can inspect it.
 */
bool domain_has_ioreq_server(const struct domain *d)
{
    const struct ioreq_server *s;
    unsigned int id;

    FOR_EACH_IOREQ_SERVER(d, id, s)
        return true;

    return false;
}

static struct ioreq_vcpu *get_pending_vcpu(const struct vcpu *v,
                                           struct ioreq_server **srvp)
{
    struct domain *d = v->domain;
    struct ioreq_server *s;
    unsigned int id;

    FOR_EACH_IOREQ_SERVER(d, id, s)
    {
        struct ioreq_vcpu *sv;

        list_for_each_entry ( sv,
                              &s->ioreq_vcpu_list,
                              list_entry )
        {
            if ( sv->vcpu == v && sv->pending )
            {
                if ( srvp )
                    *srvp = s;
                return sv;
            }
        }
    }

    return NULL;
}

bool vcpu_ioreq_pending(struct vcpu *v)
{
    return get_pending_vcpu(v, NULL);
}

static bool wait_for_io(struct ioreq_vcpu *sv, ioreq_t *p)
{
    unsigned int prev_state = STATE_IOREQ_NONE;
    unsigned int state = p->state;
    uint64_t data = ~0;

    smp_rmb();

    /*
     * The only reason we should see this condition be false is when an
     * emulator dying races with I/O being requested.
     */
    while ( likely(state != STATE_IOREQ_NONE) )
    {
        if ( unlikely(state < prev_state) )
        {
            gdprintk(XENLOG_ERR, "Weird HVM ioreq state transition %u -> %u\n",
                     prev_state, state);
            sv->pending = false;
            domain_crash(sv->vcpu->domain);
            return false; /* bail */
        }

        switch ( prev_state = state )
        {
        case STATE_IORESP_READY: /* IORESP_READY -> NONE */
            p->state = STATE_IOREQ_NONE;
            data = p->data;
            break;

        case STATE_IOREQ_READY:  /* IOREQ_{READY,INPROCESS} -> IORESP_READY */
        case STATE_IOREQ_INPROCESS:
            wait_on_xen_event_channel(sv->ioreq_evtchn,
                                      ({ state = p->state;
                                         smp_rmb();
                                         state != prev_state; }));
            continue;

        default:
            gdprintk(XENLOG_ERR, "Weird HVM iorequest state %u\n", state);
            sv->pending = false;
            domain_crash(sv->vcpu->domain);
            return false; /* bail */
        }

        break;
    }

    p = &sv->vcpu->io.req;
    if ( ioreq_needs_completion(p) )
        p->data = data;

    sv->pending = false;

    return true;
}

bool vcpu_ioreq_handle_completion(struct vcpu *v)
{
    struct vcpu_io *vio = &v->io;
    struct ioreq_server *s;
    struct ioreq_vcpu *sv;
    enum vio_completion completion;
    bool res = true;

    while ( (sv = get_pending_vcpu(v, &s)) != NULL )
        if ( !wait_for_io(sv, get_ioreq(s, v)) )
            return false;

    vio->req.state = ioreq_needs_completion(&vio->req) ?
        STATE_IORESP_READY : STATE_IOREQ_NONE;

    msix_write_completion(v);
    vcpu_end_shutdown_deferral(v);

    completion = vio->completion;
    vio->completion = VIO_no_completion;

    switch ( completion )
    {
    case VIO_no_completion:
        break;

    case VIO_mmio_completion:
        res = arch_ioreq_complete_mmio();
        break;

    case VIO_pio_completion:
        res = handle_pio(vio->req.addr, vio->req.size,
                         vio->req.dir);
        break;

    default:
        res = arch_vcpu_ioreq_completion(completion);
        break;
    }

    if ( res && unlikely(v->mapcache_invalidate) )
    {
        v->mapcache_invalidate = false;
        ioreq_signal_mapcache_invalidate();
        res = false;
    }

    return res;
}

static int ioreq_server_alloc_mfn(struct ioreq_server *s, bool buf)
{
    struct ioreq_page *iorp = buf ? &s->bufioreq : &s->ioreq;
    struct page_info *page;

    if ( iorp->page )
    {
        /*
         * If a guest frame has already been mapped (which may happen
         * on demand if ioreq_server_get_info() is called), then
         * allocating a page is not permitted.
         */
        if ( !gfn_eq(iorp->gfn, INVALID_GFN) )
            return -EPERM;

        return 0;
    }

    page = alloc_domheap_page(s->target, MEMF_no_refcount);

    if ( !page )
        return -ENOMEM;

    if ( !get_page_and_type(page, s->target, PGT_writable_page) )
    {
        /*
         * The domain can't possibly know about this page yet, so failure
         * here is a clear indication of something fishy going on.
         */
        domain_crash(s->emulator);
        return -ENODATA;
    }

    iorp->va = __map_domain_page_global(page);
    if ( !iorp->va )
        goto fail;

    iorp->page = page;
    clear_page(iorp->va);
    return 0;

 fail:
    put_page_alloc_ref(page);
    put_page_and_type(page);

    return -ENOMEM;
}

static void ioreq_server_free_mfn(struct ioreq_server *s, bool buf)
{
    struct ioreq_page *iorp = buf ? &s->bufioreq : &s->ioreq;
    struct page_info *page = iorp->page;

    if ( !page )
        return;

    iorp->page = NULL;

    unmap_domain_page_global(iorp->va);
    iorp->va = NULL;

    put_page_alloc_ref(page);
    put_page_and_type(page);
}

bool is_ioreq_server_page(struct domain *d, const struct page_info *page)
{
    const struct ioreq_server *s;
    unsigned int id;
    bool found = false;

    rspin_lock(&d->ioreq_server.lock);

    FOR_EACH_IOREQ_SERVER(d, id, s)
    {
        if ( (s->ioreq.page == page) || (s->bufioreq.page == page) )
        {
            found = true;
            break;
        }
    }

    rspin_unlock(&d->ioreq_server.lock);

    return found;
}

static void ioreq_server_update_evtchn(struct ioreq_server *s,
                                       struct ioreq_vcpu *sv)
{
    ASSERT(spin_is_locked(&s->lock));

    if ( s->ioreq.va != NULL )
    {
        ioreq_t *p = get_ioreq(s, sv->vcpu);

        p->vp_eport = sv->ioreq_evtchn;
    }
}

static int ioreq_server_add_vcpu(struct ioreq_server *s,
                                 struct vcpu *v)
{
    struct ioreq_vcpu *sv;
    int rc;

    sv = xzalloc(struct ioreq_vcpu);

    rc = -ENOMEM;
    if ( !sv )
        goto fail1;

    spin_lock(&s->lock);

    rc = alloc_unbound_xen_event_channel(v->domain, v->vcpu_id,
                                         s->emulator->domain_id, NULL);
    if ( rc < 0 )
        goto fail2;

    sv->ioreq_evtchn = rc;

    if ( v->vcpu_id == 0 && HANDLE_BUFIOREQ(s) )
    {
        rc = alloc_unbound_xen_event_channel(v->domain, 0,
                                             s->emulator->domain_id, NULL);
        if ( rc < 0 )
            goto fail3;

        s->bufioreq_evtchn = rc;
    }

    sv->vcpu = v;

    list_add(&sv->list_entry, &s->ioreq_vcpu_list);

    if ( s->enabled )
        ioreq_server_update_evtchn(s, sv);

    spin_unlock(&s->lock);
    return 0;

 fail3:
    free_xen_event_channel(v->domain, sv->ioreq_evtchn);

 fail2:
    spin_unlock(&s->lock);
    xfree(sv);

 fail1:
    return rc;
}

static void ioreq_server_remove_vcpu(struct ioreq_server *s,
                                     struct vcpu *v)
{
    struct ioreq_vcpu *sv;

    spin_lock(&s->lock);

    list_for_each_entry ( sv,
                          &s->ioreq_vcpu_list,
                          list_entry )
    {
        if ( sv->vcpu != v )
            continue;

        list_del(&sv->list_entry);

        if ( v->vcpu_id == 0 && HANDLE_BUFIOREQ(s) )
            free_xen_event_channel(v->domain, s->bufioreq_evtchn);

        free_xen_event_channel(v->domain, sv->ioreq_evtchn);

        xfree(sv);
        break;
    }

    spin_unlock(&s->lock);
}

static void ioreq_server_remove_all_vcpus(struct ioreq_server *s)
{
    struct ioreq_vcpu *sv, *next;

    spin_lock(&s->lock);

    list_for_each_entry_safe ( sv,
                               next,
                               &s->ioreq_vcpu_list,
                               list_entry )
    {
        struct vcpu *v = sv->vcpu;

        list_del(&sv->list_entry);

        if ( v->vcpu_id == 0 && HANDLE_BUFIOREQ(s) )
            free_xen_event_channel(v->domain, s->bufioreq_evtchn);

        free_xen_event_channel(v->domain, sv->ioreq_evtchn);

        xfree(sv);
    }

    spin_unlock(&s->lock);
}

static int ioreq_server_alloc_pages(struct ioreq_server *s)
{
    int rc;

    rc = ioreq_server_alloc_mfn(s, false);

    if ( !rc && (s->bufioreq_handling != HVM_IOREQSRV_BUFIOREQ_OFF) )
        rc = ioreq_server_alloc_mfn(s, true);

    if ( rc )
        ioreq_server_free_mfn(s, false);

    return rc;
}

static void ioreq_server_free_pages(struct ioreq_server *s)
{
    ioreq_server_free_mfn(s, true);
    ioreq_server_free_mfn(s, false);
}

static void ioreq_server_free_rangesets(struct ioreq_server *s)
{
    unsigned int i;

    for ( i = 0; i < NR_IO_RANGE_TYPES; i++ )
        rangeset_destroy(s->range[i]);
}

static int ioreq_server_alloc_rangesets(struct ioreq_server *s,
                                        ioservid_t id)
{
    unsigned int i;
    int rc;

    for ( i = 0; i < NR_IO_RANGE_TYPES; i++ )
    {
        const char *type;
        char *name;

        switch ( i )
        {
        case XEN_DMOP_IO_RANGE_PORT:   type = " port";   break;
        case XEN_DMOP_IO_RANGE_MEMORY: type = " memory"; break;
        case XEN_DMOP_IO_RANGE_PCI:    type = " pci";    break;
        default:                       type = "";        break;
        }

        rc = xasprintf(&name, "ioreq_server %d%s", id, type);
        if ( rc )
            goto fail;

        s->range[i] = rangeset_new(s->target, name,
                                   RANGESETF_prettyprint_hex);

        xfree(name);

        rc = -ENOMEM;
        if ( !s->range[i] )
            goto fail;

        rangeset_limit(s->range[i], MAX_NR_IO_RANGES);
    }

    return 0;

 fail:
    ioreq_server_free_rangesets(s);

    return rc;
}

static void ioreq_server_enable(struct ioreq_server *s)
{
    struct ioreq_vcpu *sv;

    spin_lock(&s->lock);

    if ( s->enabled )
        goto done;

    arch_ioreq_server_enable(s);

    s->enabled = true;

    list_for_each_entry ( sv,
                          &s->ioreq_vcpu_list,
                          list_entry )
        ioreq_server_update_evtchn(s, sv);

  done:
    spin_unlock(&s->lock);
}

static void ioreq_server_disable(struct ioreq_server *s)
{
    spin_lock(&s->lock);

    if ( !s->enabled )
        goto done;

    arch_ioreq_server_disable(s);

    s->enabled = false;

 done:
    spin_unlock(&s->lock);
}

static int ioreq_server_init(struct ioreq_server *s,
                             struct domain *d, int bufioreq_handling,
                             ioservid_t id)
{
    struct domain *currd = current->domain;
    struct vcpu *v;
    int rc;

    s->target = d;

    get_knownalive_domain(currd);
    s->emulator = currd;

    spin_lock_init(&s->lock);
    INIT_LIST_HEAD(&s->ioreq_vcpu_list);
    spin_lock_init(&s->bufioreq_lock);

    s->ioreq.gfn = INVALID_GFN;
    s->bufioreq.gfn = INVALID_GFN;

    rc = ioreq_server_alloc_rangesets(s, id);
    if ( rc )
        return rc;

    s->bufioreq_handling = bufioreq_handling;

    for_each_vcpu ( d, v )
    {
        rc = ioreq_server_add_vcpu(s, v);
        if ( rc )
            goto fail_add;
    }

    return 0;

 fail_add:
    ioreq_server_remove_all_vcpus(s);
    arch_ioreq_server_unmap_pages(s);

    ioreq_server_free_rangesets(s);

    put_domain(s->emulator);
    return rc;
}

static void ioreq_server_deinit(struct ioreq_server *s)
{
    ASSERT(!s->enabled);
    ioreq_server_remove_all_vcpus(s);

    /*
     * NOTE: It is safe to call both arch_ioreq_server_unmap_pages() and
     *       ioreq_server_free_pages() in that order.
     *       This is because the former will do nothing if the pages
     *       are not mapped, leaving the page to be freed by the latter.
     *       However if the pages are mapped then the former will set
     *       the page_info pointer to NULL, meaning the latter will do
     *       nothing.
     */
    arch_ioreq_server_unmap_pages(s);
    ioreq_server_free_pages(s);

    ioreq_server_free_rangesets(s);

    put_domain(s->emulator);
}

static int ioreq_server_create(struct domain *d, int bufioreq_handling,
                               ioservid_t *id)
{
    struct ioreq_server *s;
    unsigned int i;
    int rc;

    if ( !IS_ENABLED(CONFIG_X86) && bufioreq_handling )
        return -EINVAL;

    if ( bufioreq_handling > HVM_IOREQSRV_BUFIOREQ_ATOMIC )
        return -EINVAL;

    s = xzalloc(struct ioreq_server);
    if ( !s )
        return -ENOMEM;

    domain_pause(d);
    rspin_lock(&d->ioreq_server.lock);

    for ( i = 0; i < MAX_NR_IOREQ_SERVERS; i++ )
    {
        if ( !GET_IOREQ_SERVER(d, i) )
            break;
    }

    rc = -ENOSPC;
    if ( i >= MAX_NR_IOREQ_SERVERS )
        goto fail;

    /*
     * It is safe to call set_ioreq_server() prior to
     * ioreq_server_init() since the target domain is paused.
     */
    set_ioreq_server(d, i, s);

    rc = ioreq_server_init(s, d, bufioreq_handling, i);
    if ( rc )
    {
        set_ioreq_server(d, i, NULL);
        goto fail;
    }

    if ( id )
        *id = i;

    rspin_unlock(&d->ioreq_server.lock);
    domain_unpause(d);

    return 0;

 fail:
    rspin_unlock(&d->ioreq_server.lock);
    domain_unpause(d);

    xfree(s);
    return rc;
}

static int ioreq_server_destroy(struct domain *d, ioservid_t id)
{
    struct ioreq_server *s;
    int rc;

    rspin_lock(&d->ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    domain_pause(d);

    arch_ioreq_server_destroy(s);

    ioreq_server_disable(s);

    /*
     * It is safe to call ioreq_server_deinit() prior to
     * set_ioreq_server() since the target domain is paused.
     */
    ioreq_server_deinit(s);
    set_ioreq_server(d, id, NULL);

    domain_unpause(d);

    xfree(s);

    rc = 0;

 out:
    rspin_unlock(&d->ioreq_server.lock);

    return rc;
}

static int ioreq_server_get_info(struct domain *d, ioservid_t id,
                                 unsigned long *ioreq_gfn,
                                 unsigned long *bufioreq_gfn,
                                 evtchn_port_t *bufioreq_port)
{
    struct ioreq_server *s;
    int rc;

    rspin_lock(&d->ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    if ( ioreq_gfn || bufioreq_gfn )
    {
        rc = arch_ioreq_server_map_pages(s);
        if ( rc )
            goto out;
    }

    if ( ioreq_gfn )
        *ioreq_gfn = gfn_x(s->ioreq.gfn);

    if ( HANDLE_BUFIOREQ(s) )
    {
        if ( bufioreq_gfn )
            *bufioreq_gfn = gfn_x(s->bufioreq.gfn);

        if ( bufioreq_port )
            *bufioreq_port = s->bufioreq_evtchn;
    }

    rc = 0;

 out:
    rspin_unlock(&d->ioreq_server.lock);

    return rc;
}

int ioreq_server_get_frame(struct domain *d, ioservid_t id,
                           unsigned int idx, mfn_t *mfn)
{
    struct ioreq_server *s;
    int rc;

    ASSERT(is_hvm_domain(d));

    rspin_lock(&d->ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    rc = ioreq_server_alloc_pages(s);
    if ( rc )
        goto out;

    switch ( idx )
    {
    case XENMEM_resource_ioreq_server_frame_bufioreq:
        rc = -ENOENT;
        if ( !HANDLE_BUFIOREQ(s) )
            goto out;

        *mfn = page_to_mfn(s->bufioreq.page);
        rc = 0;
        break;

    case XENMEM_resource_ioreq_server_frame_ioreq(0):
        *mfn = page_to_mfn(s->ioreq.page);
        rc = 0;
        break;

    default:
        rc = -EINVAL;
        break;
    }

 out:
    rspin_unlock(&d->ioreq_server.lock);

    return rc;
}

static int ioreq_server_map_io_range(struct domain *d, ioservid_t id,
                                     uint32_t type, uint64_t start,
                                     uint64_t end)
{
    struct ioreq_server *s;
    struct rangeset *r;
    int rc;

    if ( start > end )
        return -EINVAL;

    rspin_lock(&d->ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    switch ( type )
    {
    case XEN_DMOP_IO_RANGE_PORT:
    case XEN_DMOP_IO_RANGE_MEMORY:
    case XEN_DMOP_IO_RANGE_PCI:
        r = s->range[type];
        break;

    default:
        r = NULL;
        break;
    }

    rc = -EINVAL;
    if ( !r )
        goto out;

    rc = -EEXIST;
    if ( rangeset_overlaps_range(r, start, end) )
        goto out;

    rc = rangeset_add_range(r, start, end);

 out:
    rspin_unlock(&d->ioreq_server.lock);

    return rc;
}

static int ioreq_server_unmap_io_range(struct domain *d, ioservid_t id,
                                       uint32_t type, uint64_t start,
                                       uint64_t end)
{
    struct ioreq_server *s;
    struct rangeset *r;
    int rc;

    if ( start > end )
        return -EINVAL;

    rspin_lock(&d->ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    switch ( type )
    {
    case XEN_DMOP_IO_RANGE_PORT:
    case XEN_DMOP_IO_RANGE_MEMORY:
    case XEN_DMOP_IO_RANGE_PCI:
        r = s->range[type];
        break;

    default:
        r = NULL;
        break;
    }

    rc = -EINVAL;
    if ( !r )
        goto out;

    rc = -ENOENT;
    if ( !rangeset_contains_range(r, start, end) )
        goto out;

    rc = rangeset_remove_range(r, start, end);

 out:
    rspin_unlock(&d->ioreq_server.lock);

    return rc;
}

/*
 * Map or unmap an ioreq server to specific memory type. For now, only
 * HVMMEM_ioreq_server is supported, and in the future new types can be
 * introduced, e.g. HVMMEM_ioreq_serverX mapped to ioreq server X. And
 * currently, only write operations are to be forwarded to an ioreq server.
 * Support for the emulation of read operations can be added when an ioreq
 * server has such requirement in the future.
 */
int ioreq_server_map_mem_type(struct domain *d, ioservid_t id,
                              uint32_t type, uint32_t flags)
{
    struct ioreq_server *s;
    int rc;

    if ( type != HVMMEM_ioreq_server )
        return -EINVAL;

    if ( flags & ~XEN_DMOP_IOREQ_MEM_ACCESS_WRITE )
        return -EINVAL;

    rspin_lock(&d->ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    rc = arch_ioreq_server_map_mem_type(d, s, flags);

 out:
    rspin_unlock(&d->ioreq_server.lock);

    if ( rc == 0 )
        arch_ioreq_server_map_mem_type_completed(d, s, flags);

    return rc;
}

static int ioreq_server_set_state(struct domain *d, ioservid_t id,
                                  bool enabled)
{
    struct ioreq_server *s;
    int rc;

    rspin_lock(&d->ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    domain_pause(d);

    if ( enabled )
        ioreq_server_enable(s);
    else
        ioreq_server_disable(s);

    domain_unpause(d);

    rc = 0;

 out:
    rspin_unlock(&d->ioreq_server.lock);
    return rc;
}

int ioreq_server_add_vcpu_all(struct domain *d, struct vcpu *v)
{
    struct ioreq_server *s;
    unsigned int id;
    int rc;

    rspin_lock(&d->ioreq_server.lock);

    FOR_EACH_IOREQ_SERVER(d, id, s)
    {
        rc = ioreq_server_add_vcpu(s, v);
        if ( rc )
            goto fail;
    }

    rspin_unlock(&d->ioreq_server.lock);

    return 0;

 fail:
    while ( ++id != MAX_NR_IOREQ_SERVERS )
    {
        s = GET_IOREQ_SERVER(d, id);

        if ( !s )
            continue;

        ioreq_server_remove_vcpu(s, v);
    }

    rspin_unlock(&d->ioreq_server.lock);

    return rc;
}

void ioreq_server_remove_vcpu_all(struct domain *d, struct vcpu *v)
{
    struct ioreq_server *s;
    unsigned int id;

    rspin_lock(&d->ioreq_server.lock);

    FOR_EACH_IOREQ_SERVER(d, id, s)
        ioreq_server_remove_vcpu(s, v);

    rspin_unlock(&d->ioreq_server.lock);
}

void ioreq_server_destroy_all(struct domain *d)
{
    struct ioreq_server *s;
    unsigned int id;

    if ( !arch_ioreq_server_destroy_all(d) )
        return;

    rspin_lock(&d->ioreq_server.lock);

    /* No need to domain_pause() as the domain is being torn down */

    FOR_EACH_IOREQ_SERVER(d, id, s)
    {
        ioreq_server_disable(s);

        /*
         * It is safe to call ioreq_server_deinit() prior to
         * set_ioreq_server() since the target domain is being destroyed.
         */
        ioreq_server_deinit(s);
        set_ioreq_server(d, id, NULL);

        xfree(s);
    }

    rspin_unlock(&d->ioreq_server.lock);
}

struct ioreq_server *ioreq_server_select(struct domain *d,
                                         ioreq_t *p)
{
    struct ioreq_server *s;
    uint8_t type;
    uint64_t addr;
    unsigned int id;

    if ( !arch_ioreq_server_get_type_addr(d, p, &type, &addr) )
        return NULL;

    FOR_EACH_IOREQ_SERVER(d, id, s)
    {
        struct rangeset *r;

        if ( !s->enabled )
            continue;

        r = s->range[type];

        switch ( type )
        {
            unsigned long start, end;

        case XEN_DMOP_IO_RANGE_PORT:
            start = addr;
            end = start + p->size - 1;
            if ( rangeset_contains_range(r, start, end) )
                return s;

            break;

        case XEN_DMOP_IO_RANGE_MEMORY:
            start = ioreq_mmio_first_byte(p);
            end = ioreq_mmio_last_byte(p);

            if ( rangeset_contains_range(r, start, end) )
                return s;

            break;

        case XEN_DMOP_IO_RANGE_PCI:
            if ( rangeset_contains_singleton(r, addr >> 32) )
            {
                p->type = IOREQ_TYPE_PCI_CONFIG;
                p->addr = addr;
                return s;
            }

            break;
        }
    }

    return NULL;
}

static int ioreq_send_buffered(struct ioreq_server *s, ioreq_t *p)
{
    struct domain *d = current->domain;
    struct ioreq_page *iorp;
    buffered_iopage_t *pg;
    buf_ioreq_t bp = { .data = p->data,
                       .addr = p->addr,
                       .type = p->type,
                       .dir = p->dir };
    /* Timeoffset sends 64b data, but no address. Use two consecutive slots. */
    int qw = 0;

    /* Ensure buffered_iopage fits in a page */
    BUILD_BUG_ON(sizeof(buffered_iopage_t) > PAGE_SIZE);

    iorp = &s->bufioreq;
    pg = iorp->va;

    if ( !pg )
        return IOREQ_STATUS_UNHANDLED;

    /*
     * Return UNHANDLED for the cases we can't deal with:
     *  - 'addr' is only a 20-bit field, so we cannot address beyond 1MB
     *  - we cannot buffer accesses to guest memory buffers, as the guest
     *    may expect the memory buffer to be synchronously accessed
     *  - the count field is usually used with data_is_ptr and since we don't
     *    support data_is_ptr we do not waste space for the count field either
     */
    if ( (p->addr > 0xfffffUL) || p->data_is_ptr || (p->count != 1) )
        return IOREQ_STATUS_UNHANDLED;

    switch ( p->size )
    {
    case 1:
        bp.size = 0;
        break;
    case 2:
        bp.size = 1;
        break;
    case 4:
        bp.size = 2;
        break;
    case 8:
        bp.size = 3;
        qw = 1;
        break;
    default:
        gdprintk(XENLOG_WARNING, "unexpected ioreq size: %u\n", p->size);
        return IOREQ_STATUS_UNHANDLED;
    }

    spin_lock(&s->bufioreq_lock);

    if ( (pg->ptrs.write_pointer - pg->ptrs.read_pointer) >=
         (IOREQ_BUFFER_SLOT_NUM - qw) )
    {
        /* The queue is full: send the iopacket through the normal path. */
        spin_unlock(&s->bufioreq_lock);
        return IOREQ_STATUS_UNHANDLED;
    }

    pg->buf_ioreq[pg->ptrs.write_pointer % IOREQ_BUFFER_SLOT_NUM] = bp;

    if ( qw )
    {
        bp.data = p->data >> 32;
        pg->buf_ioreq[(pg->ptrs.write_pointer+1) % IOREQ_BUFFER_SLOT_NUM] = bp;
    }

    /* Make the ioreq_t visible /before/ write_pointer. */
    smp_wmb();
    pg->ptrs.write_pointer += qw ? 2 : 1;

    /* Canonicalize read/write pointers to prevent their overflow. */
    while ( (s->bufioreq_handling == HVM_IOREQSRV_BUFIOREQ_ATOMIC) &&
            qw++ < IOREQ_BUFFER_SLOT_NUM &&
            pg->ptrs.read_pointer >= IOREQ_BUFFER_SLOT_NUM )
    {
        union bufioreq_pointers old = pg->ptrs, new;
        unsigned int n = old.read_pointer / IOREQ_BUFFER_SLOT_NUM;

        new.read_pointer = old.read_pointer - n * IOREQ_BUFFER_SLOT_NUM;
        new.write_pointer = old.write_pointer - n * IOREQ_BUFFER_SLOT_NUM;
        guest_cmpxchg64(s->emulator, &pg->ptrs.full, old.full, new.full);
    }

    notify_via_xen_event_channel(d, s->bufioreq_evtchn);
    spin_unlock(&s->bufioreq_lock);

    return IOREQ_STATUS_HANDLED;
}

int ioreq_send(struct ioreq_server *s, ioreq_t *proto_p,
               bool buffered)
{
    struct vcpu *curr = current;
    struct domain *d = curr->domain;
    struct ioreq_vcpu *sv;
    struct vcpu_io *vio = &curr->io;

    ASSERT(s);

    if ( buffered )
        return ioreq_send_buffered(s, proto_p);

    if ( unlikely(!vcpu_start_shutdown_deferral(curr)) )
    {
        vio->suspended = true;
        return IOREQ_STATUS_RETRY;
    }

    list_for_each_entry ( sv,
                          &s->ioreq_vcpu_list,
                          list_entry )
    {
        if ( sv->vcpu == curr )
        {
            evtchn_port_t port = sv->ioreq_evtchn;
            ioreq_t *p = get_ioreq(s, curr);

            if ( unlikely(p->state != STATE_IOREQ_NONE) )
            {
                gprintk(XENLOG_ERR, "device model set bad IO state %d\n",
                        p->state);
                break;
            }

            if ( unlikely(p->vp_eport != port) )
            {
                gprintk(XENLOG_ERR, "device model set bad event channel %d\n",
                        p->vp_eport);
                break;
            }

            proto_p->state = STATE_IOREQ_NONE;
            proto_p->vp_eport = port;
            *p = *proto_p;

            prepare_wait_on_xen_event_channel(port);

            /*
             * Following happens /after/ blocking and setting up ioreq
             * contents. prepare_wait_on_xen_event_channel() is an implicit
             * barrier.
             */
            p->state = STATE_IOREQ_READY;
            notify_via_xen_event_channel(d, port);

            sv->pending = true;
            return IOREQ_STATUS_RETRY;
        }
    }

    return IOREQ_STATUS_UNHANDLED;
}

unsigned int ioreq_broadcast(ioreq_t *p, bool buffered)
{
    struct domain *d = current->domain;
    struct ioreq_server *s;
    unsigned int id, failed = 0;

    FOR_EACH_IOREQ_SERVER(d, id, s)
    {
        if ( !s->enabled ||
             (buffered && s->bufioreq_handling == HVM_IOREQSRV_BUFIOREQ_OFF) )
            continue;

        if ( ioreq_send(s, p, buffered) == IOREQ_STATUS_UNHANDLED )
            failed++;
    }

    return failed;
}

void ioreq_domain_init(struct domain *d)
{
    rspin_lock_init(&d->ioreq_server.lock);

    arch_ioreq_domain_init(d);
}

int ioreq_server_dm_op(struct xen_dm_op *op, struct domain *d, bool *const_op)
{
    long rc;

    switch ( op->op )
    {
    case XEN_DMOP_create_ioreq_server:
    {
        struct xen_dm_op_create_ioreq_server *data =
            &op->u.create_ioreq_server;

        *const_op = false;

        rc = -EINVAL;
        if ( data->pad[0] || data->pad[1] || data->pad[2] )
            break;

        rc = ioreq_server_create(d, data->handle_bufioreq,
                                 &data->id);
        break;
    }

    case XEN_DMOP_get_ioreq_server_info:
    {
        struct xen_dm_op_get_ioreq_server_info *data =
            &op->u.get_ioreq_server_info;
        const uint16_t valid_flags = XEN_DMOP_no_gfns;

        *const_op = false;

        rc = -EINVAL;
        if ( data->flags & ~valid_flags )
            break;

        rc = ioreq_server_get_info(d, data->id,
                                   (data->flags & XEN_DMOP_no_gfns) ?
                                   NULL : (unsigned long *)&data->ioreq_gfn,
                                   (data->flags & XEN_DMOP_no_gfns) ?
                                   NULL : (unsigned long *)&data->bufioreq_gfn,
                                   &data->bufioreq_port);
        break;
    }

    case XEN_DMOP_map_io_range_to_ioreq_server:
    {
        const struct xen_dm_op_ioreq_server_range *data =
            &op->u.map_io_range_to_ioreq_server;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = ioreq_server_map_io_range(d, data->id, data->type,
                                       data->start, data->end);
        break;
    }

    case XEN_DMOP_unmap_io_range_from_ioreq_server:
    {
        const struct xen_dm_op_ioreq_server_range *data =
            &op->u.unmap_io_range_from_ioreq_server;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = ioreq_server_unmap_io_range(d, data->id, data->type,
                                         data->start, data->end);
        break;
    }

    case XEN_DMOP_set_ioreq_server_state:
    {
        const struct xen_dm_op_set_ioreq_server_state *data =
            &op->u.set_ioreq_server_state;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = ioreq_server_set_state(d, data->id, !!data->enabled);
        break;
    }

    case XEN_DMOP_destroy_ioreq_server:
    {
        const struct xen_dm_op_destroy_ioreq_server *data =
            &op->u.destroy_ioreq_server;

        rc = -EINVAL;
        if ( data->pad )
            break;

        rc = ioreq_server_destroy(d, data->id);
        break;
    }

    default:
        rc = -EOPNOTSUPP;
        break;
    }

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
