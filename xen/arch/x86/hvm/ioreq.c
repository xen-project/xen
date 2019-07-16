/*
 * hvm/io.c: hardware virtual machine I/O emulation
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

#include <xen/ctype.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/paging.h>
#include <xen/vpci.h>

#include <asm/hvm/hvm.h>
#include <asm/hvm/ioreq.h>
#include <asm/hvm/vmx/vmx.h>

#include <public/hvm/ioreq.h>

static void set_ioreq_server(struct domain *d, unsigned int id,
                             struct hvm_ioreq_server *s)
{
    ASSERT(id < MAX_NR_IOREQ_SERVERS);
    ASSERT(!s || !d->arch.hvm.ioreq_server.server[id]);

    d->arch.hvm.ioreq_server.server[id] = s;
}

#define GET_IOREQ_SERVER(d, id) \
    (d)->arch.hvm.ioreq_server.server[id]

static struct hvm_ioreq_server *get_ioreq_server(const struct domain *d,
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
 *       ioreq servers are favoured in hvm_select_ioreq_server().
 *       This is a semantic that previously existed when ioreq servers
 *       were held in a linked list.
 */
#define FOR_EACH_IOREQ_SERVER(d, id, s) \
    for ( (id) = MAX_NR_IOREQ_SERVERS; (id) != 0; ) \
        if ( !(s = GET_IOREQ_SERVER(d, --(id))) ) \
            continue; \
        else

static ioreq_t *get_ioreq(struct hvm_ioreq_server *s, struct vcpu *v)
{
    shared_iopage_t *p = s->ioreq.va;

    ASSERT((v == current) || !vcpu_runnable(v));
    ASSERT(p != NULL);

    return &p->vcpu_ioreq[v->vcpu_id];
}

bool hvm_io_pending(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct hvm_ioreq_server *s;
    unsigned int id;

    FOR_EACH_IOREQ_SERVER(d, id, s)
    {
        struct hvm_ioreq_vcpu *sv;

        list_for_each_entry ( sv,
                              &s->ioreq_vcpu_list,
                              list_entry )
        {
            if ( sv->vcpu == v && sv->pending )
                return true;
        }
    }

    return false;
}

static void hvm_io_assist(struct hvm_ioreq_vcpu *sv, uint64_t data)
{
    struct vcpu *v = sv->vcpu;
    ioreq_t *ioreq = &v->arch.hvm.hvm_io.io_req;

    if ( hvm_ioreq_needs_completion(ioreq) )
    {
        ioreq->state = STATE_IORESP_READY;
        ioreq->data = data;
    }
    else
        ioreq->state = STATE_IOREQ_NONE;

    msix_write_completion(v);
    vcpu_end_shutdown_deferral(v);

    sv->pending = false;
}

static bool hvm_wait_for_io(struct hvm_ioreq_vcpu *sv, ioreq_t *p)
{
    unsigned int prev_state = STATE_IOREQ_NONE;

    while ( sv->pending )
    {
        unsigned int state = p->state;

        smp_rmb();

    recheck:
        if ( unlikely(state == STATE_IOREQ_NONE) )
        {
            /*
             * The only reason we should see this case is when an
             * emulator is dying and it races with an I/O being
             * requested.
             */
            hvm_io_assist(sv, ~0ul);
            break;
        }

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
            hvm_io_assist(sv, p->data);
            break;
        case STATE_IOREQ_READY:  /* IOREQ_{READY,INPROCESS} -> IORESP_READY */
        case STATE_IOREQ_INPROCESS:
            wait_on_xen_event_channel(sv->ioreq_evtchn,
                                      ({ state = p->state;
                                         smp_rmb();
                                         state != prev_state; }));
            goto recheck;
        default:
            gdprintk(XENLOG_ERR, "Weird HVM iorequest state %u\n", state);
            sv->pending = false;
            domain_crash(sv->vcpu->domain);
            return false; /* bail */
        }
    }

    return true;
}

bool handle_hvm_io_completion(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct hvm_vcpu_io *vio = &v->arch.hvm.hvm_io;
    struct hvm_ioreq_server *s;
    enum hvm_io_completion io_completion;
    unsigned int id;

    if ( has_vpci(d) && vpci_process_pending(v) )
    {
        raise_softirq(SCHEDULE_SOFTIRQ);
        return false;
    }

    FOR_EACH_IOREQ_SERVER(d, id, s)
    {
        struct hvm_ioreq_vcpu *sv;

        list_for_each_entry ( sv,
                              &s->ioreq_vcpu_list,
                              list_entry )
        {
            if ( sv->vcpu == v && sv->pending )
            {
                if ( !hvm_wait_for_io(sv, get_ioreq(s, v)) )
                    return false;

                break;
            }
        }
    }

    io_completion = vio->io_completion;
    vio->io_completion = HVMIO_no_completion;

    switch ( io_completion )
    {
    case HVMIO_no_completion:
        break;

    case HVMIO_mmio_completion:
        return handle_mmio();

    case HVMIO_pio_completion:
        return handle_pio(vio->io_req.addr, vio->io_req.size,
                          vio->io_req.dir);

    case HVMIO_realmode_completion:
    {
        struct hvm_emulate_ctxt ctxt;

        hvm_emulate_init_once(&ctxt, NULL, guest_cpu_user_regs());
        vmx_realmode_emulate_one(&ctxt);
        hvm_emulate_writeback(&ctxt);

        break;
    }
    default:
        ASSERT_UNREACHABLE();
        break;
    }

    return true;
}

static gfn_t hvm_alloc_legacy_ioreq_gfn(struct hvm_ioreq_server *s)
{
    struct domain *d = s->target;
    unsigned int i;

    BUILD_BUG_ON(HVM_PARAM_BUFIOREQ_PFN != HVM_PARAM_IOREQ_PFN + 1);

    for ( i = HVM_PARAM_IOREQ_PFN; i <= HVM_PARAM_BUFIOREQ_PFN; i++ )
    {
        if ( !test_and_clear_bit(i, &d->arch.hvm.ioreq_gfn.legacy_mask) )
            return _gfn(d->arch.hvm.params[i]);
    }

    return INVALID_GFN;
}

static gfn_t hvm_alloc_ioreq_gfn(struct hvm_ioreq_server *s)
{
    struct domain *d = s->target;
    unsigned int i;

    for ( i = 0; i < sizeof(d->arch.hvm.ioreq_gfn.mask) * 8; i++ )
    {
        if ( test_and_clear_bit(i, &d->arch.hvm.ioreq_gfn.mask) )
            return _gfn(d->arch.hvm.ioreq_gfn.base + i);
    }

    /*
     * If we are out of 'normal' GFNs then we may still have a 'legacy'
     * GFN available.
     */
    return hvm_alloc_legacy_ioreq_gfn(s);
}

static bool hvm_free_legacy_ioreq_gfn(struct hvm_ioreq_server *s,
                                      gfn_t gfn)
{
    struct domain *d = s->target;
    unsigned int i;

    for ( i = HVM_PARAM_IOREQ_PFN; i <= HVM_PARAM_BUFIOREQ_PFN; i++ )
    {
        if ( gfn_eq(gfn, _gfn(d->arch.hvm.params[i])) )
             break;
    }
    if ( i > HVM_PARAM_BUFIOREQ_PFN )
        return false;

    set_bit(i, &d->arch.hvm.ioreq_gfn.legacy_mask);
    return true;
}

static void hvm_free_ioreq_gfn(struct hvm_ioreq_server *s, gfn_t gfn)
{
    struct domain *d = s->target;
    unsigned int i = gfn_x(gfn) - d->arch.hvm.ioreq_gfn.base;

    ASSERT(!gfn_eq(gfn, INVALID_GFN));

    if ( !hvm_free_legacy_ioreq_gfn(s, gfn) )
    {
        ASSERT(i < sizeof(d->arch.hvm.ioreq_gfn.mask) * 8);
        set_bit(i, &d->arch.hvm.ioreq_gfn.mask);
    }
}

static void hvm_unmap_ioreq_gfn(struct hvm_ioreq_server *s, bool buf)
{
    struct hvm_ioreq_page *iorp = buf ? &s->bufioreq : &s->ioreq;

    if ( gfn_eq(iorp->gfn, INVALID_GFN) )
        return;

    destroy_ring_for_helper(&iorp->va, iorp->page);
    iorp->page = NULL;

    hvm_free_ioreq_gfn(s, iorp->gfn);
    iorp->gfn = INVALID_GFN;
}

static int hvm_map_ioreq_gfn(struct hvm_ioreq_server *s, bool buf)
{
    struct domain *d = s->target;
    struct hvm_ioreq_page *iorp = buf ? &s->bufioreq : &s->ioreq;
    int rc;

    if ( iorp->page )
    {
        /*
         * If a page has already been allocated (which will happen on
         * demand if hvm_get_ioreq_server_frame() is called), then
         * mapping a guest frame is not permitted.
         */
        if ( gfn_eq(iorp->gfn, INVALID_GFN) )
            return -EPERM;

        return 0;
    }

    if ( d->is_dying )
        return -EINVAL;

    iorp->gfn = hvm_alloc_ioreq_gfn(s);

    if ( gfn_eq(iorp->gfn, INVALID_GFN) )
        return -ENOMEM;

    rc = prepare_ring_for_helper(d, gfn_x(iorp->gfn), &iorp->page,
                                 &iorp->va);

    if ( rc )
        hvm_unmap_ioreq_gfn(s, buf);

    return rc;
}

static int hvm_alloc_ioreq_mfn(struct hvm_ioreq_server *s, bool buf)
{
    struct hvm_ioreq_page *iorp = buf ? &s->bufioreq : &s->ioreq;
    struct page_info *page;

    if ( iorp->page )
    {
        /*
         * If a guest frame has already been mapped (which may happen
         * on demand if hvm_get_ioreq_server_info() is called), then
         * allocating a page is not permitted.
         */
        if ( !gfn_eq(iorp->gfn, INVALID_GFN) )
            return -EPERM;

        return 0;
    }

    page = alloc_domheap_page(s->target, 0);

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

static void hvm_free_ioreq_mfn(struct hvm_ioreq_server *s, bool buf)
{
    struct hvm_ioreq_page *iorp = buf ? &s->bufioreq : &s->ioreq;
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
    const struct hvm_ioreq_server *s;
    unsigned int id;
    bool found = false;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    FOR_EACH_IOREQ_SERVER(d, id, s)
    {
        if ( (s->ioreq.page == page) || (s->bufioreq.page == page) )
        {
            found = true;
            break;
        }
    }

    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    return found;
}

static void hvm_remove_ioreq_gfn(struct hvm_ioreq_server *s, bool buf)

{
    struct domain *d = s->target;
    struct hvm_ioreq_page *iorp = buf ? &s->bufioreq : &s->ioreq;

    if ( gfn_eq(iorp->gfn, INVALID_GFN) )
        return;

    if ( guest_physmap_remove_page(d, iorp->gfn,
                                   page_to_mfn(iorp->page), 0) )
        domain_crash(d);
    clear_page(iorp->va);
}

static int hvm_add_ioreq_gfn(struct hvm_ioreq_server *s, bool buf)
{
    struct domain *d = s->target;
    struct hvm_ioreq_page *iorp = buf ? &s->bufioreq : &s->ioreq;
    int rc;

    if ( gfn_eq(iorp->gfn, INVALID_GFN) )
        return 0;

    clear_page(iorp->va);

    rc = guest_physmap_add_page(d, iorp->gfn,
                                page_to_mfn(iorp->page), 0);
    if ( rc == 0 )
        paging_mark_pfn_dirty(d, _pfn(gfn_x(iorp->gfn)));

    return rc;
}

static void hvm_update_ioreq_evtchn(struct hvm_ioreq_server *s,
                                    struct hvm_ioreq_vcpu *sv)
{
    ASSERT(spin_is_locked(&s->lock));

    if ( s->ioreq.va != NULL )
    {
        ioreq_t *p = get_ioreq(s, sv->vcpu);

        p->vp_eport = sv->ioreq_evtchn;
    }
}

#define HANDLE_BUFIOREQ(s) \
    ((s)->bufioreq_handling != HVM_IOREQSRV_BUFIOREQ_OFF)

static int hvm_ioreq_server_add_vcpu(struct hvm_ioreq_server *s,
                                     struct vcpu *v)
{
    struct hvm_ioreq_vcpu *sv;
    int rc;

    sv = xzalloc(struct hvm_ioreq_vcpu);

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
        hvm_update_ioreq_evtchn(s, sv);

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

static void hvm_ioreq_server_remove_vcpu(struct hvm_ioreq_server *s,
                                         struct vcpu *v)
{
    struct hvm_ioreq_vcpu *sv;

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

static void hvm_ioreq_server_remove_all_vcpus(struct hvm_ioreq_server *s)
{
    struct hvm_ioreq_vcpu *sv, *next;

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

static int hvm_ioreq_server_map_pages(struct hvm_ioreq_server *s)
{
    int rc;

    rc = hvm_map_ioreq_gfn(s, false);

    if ( !rc && HANDLE_BUFIOREQ(s) )
        rc = hvm_map_ioreq_gfn(s, true);

    if ( rc )
        hvm_unmap_ioreq_gfn(s, false);

    return rc;
}

static void hvm_ioreq_server_unmap_pages(struct hvm_ioreq_server *s)
{
    hvm_unmap_ioreq_gfn(s, true);
    hvm_unmap_ioreq_gfn(s, false);
}

static int hvm_ioreq_server_alloc_pages(struct hvm_ioreq_server *s)
{
    int rc;

    rc = hvm_alloc_ioreq_mfn(s, false);

    if ( !rc && (s->bufioreq_handling != HVM_IOREQSRV_BUFIOREQ_OFF) )
        rc = hvm_alloc_ioreq_mfn(s, true);

    if ( rc )
        hvm_free_ioreq_mfn(s, false);

    return rc;
}

static void hvm_ioreq_server_free_pages(struct hvm_ioreq_server *s)
{
    hvm_free_ioreq_mfn(s, true);
    hvm_free_ioreq_mfn(s, false);
}

static void hvm_ioreq_server_free_rangesets(struct hvm_ioreq_server *s)
{
    unsigned int i;

    for ( i = 0; i < NR_IO_RANGE_TYPES; i++ )
        rangeset_destroy(s->range[i]);
}

static int hvm_ioreq_server_alloc_rangesets(struct hvm_ioreq_server *s,
                                            ioservid_t id)
{
    unsigned int i;
    int rc;

    for ( i = 0; i < NR_IO_RANGE_TYPES; i++ )
    {
        char *name;

        rc = asprintf(&name, "ioreq_server %d %s", id,
                      (i == XEN_DMOP_IO_RANGE_PORT) ? "port" :
                      (i == XEN_DMOP_IO_RANGE_MEMORY) ? "memory" :
                      (i == XEN_DMOP_IO_RANGE_PCI) ? "pci" :
                      "");
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
    hvm_ioreq_server_free_rangesets(s);

    return rc;
}

static void hvm_ioreq_server_enable(struct hvm_ioreq_server *s)
{
    struct hvm_ioreq_vcpu *sv;

    spin_lock(&s->lock);

    if ( s->enabled )
        goto done;

    hvm_remove_ioreq_gfn(s, false);
    hvm_remove_ioreq_gfn(s, true);

    s->enabled = true;

    list_for_each_entry ( sv,
                          &s->ioreq_vcpu_list,
                          list_entry )
        hvm_update_ioreq_evtchn(s, sv);

  done:
    spin_unlock(&s->lock);
}

static void hvm_ioreq_server_disable(struct hvm_ioreq_server *s)
{
    spin_lock(&s->lock);

    if ( !s->enabled )
        goto done;

    hvm_add_ioreq_gfn(s, true);
    hvm_add_ioreq_gfn(s, false);

    s->enabled = false;

 done:
    spin_unlock(&s->lock);
}

static int hvm_ioreq_server_init(struct hvm_ioreq_server *s,
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

    rc = hvm_ioreq_server_alloc_rangesets(s, id);
    if ( rc )
        return rc;

    s->bufioreq_handling = bufioreq_handling;

    for_each_vcpu ( d, v )
    {
        rc = hvm_ioreq_server_add_vcpu(s, v);
        if ( rc )
            goto fail_add;
    }

    return 0;

 fail_add:
    hvm_ioreq_server_remove_all_vcpus(s);
    hvm_ioreq_server_unmap_pages(s);

    hvm_ioreq_server_free_rangesets(s);

    put_domain(s->emulator);
    return rc;
}

static void hvm_ioreq_server_deinit(struct hvm_ioreq_server *s)
{
    ASSERT(!s->enabled);
    hvm_ioreq_server_remove_all_vcpus(s);

    /*
     * NOTE: It is safe to call both hvm_ioreq_server_unmap_pages() and
     *       hvm_ioreq_server_free_pages() in that order.
     *       This is because the former will do nothing if the pages
     *       are not mapped, leaving the page to be freed by the latter.
     *       However if the pages are mapped then the former will set
     *       the page_info pointer to NULL, meaning the latter will do
     *       nothing.
     */
    hvm_ioreq_server_unmap_pages(s);
    hvm_ioreq_server_free_pages(s);

    hvm_ioreq_server_free_rangesets(s);

    put_domain(s->emulator);
}

int hvm_create_ioreq_server(struct domain *d, int bufioreq_handling,
                            ioservid_t *id)
{
    struct hvm_ioreq_server *s;
    unsigned int i;
    int rc;

    if ( bufioreq_handling > HVM_IOREQSRV_BUFIOREQ_ATOMIC )
        return -EINVAL;

    s = xzalloc(struct hvm_ioreq_server);
    if ( !s )
        return -ENOMEM;

    domain_pause(d);
    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

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
     * hvm_ioreq_server_init() since the target domain is paused.
     */
    set_ioreq_server(d, i, s);

    rc = hvm_ioreq_server_init(s, d, bufioreq_handling, i);
    if ( rc )
    {
        set_ioreq_server(d, i, NULL);
        goto fail;
    }

    if ( id )
        *id = i;

    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);
    domain_unpause(d);

    return 0;

 fail:
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);
    domain_unpause(d);

    xfree(s);
    return rc;
}

int hvm_destroy_ioreq_server(struct domain *d, ioservid_t id)
{
    struct hvm_ioreq_server *s;
    int rc;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    domain_pause(d);

    p2m_set_ioreq_server(d, 0, s);

    hvm_ioreq_server_disable(s);

    /*
     * It is safe to call hvm_ioreq_server_deinit() prior to
     * set_ioreq_server() since the target domain is paused.
     */
    hvm_ioreq_server_deinit(s);
    set_ioreq_server(d, id, NULL);

    domain_unpause(d);

    xfree(s);

    rc = 0;

 out:
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    return rc;
}

int hvm_get_ioreq_server_info(struct domain *d, ioservid_t id,
                              unsigned long *ioreq_gfn,
                              unsigned long *bufioreq_gfn,
                              evtchn_port_t *bufioreq_port)
{
    struct hvm_ioreq_server *s;
    int rc;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    if ( ioreq_gfn || bufioreq_gfn )
    {
        rc = hvm_ioreq_server_map_pages(s);
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
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    return rc;
}

int hvm_get_ioreq_server_frame(struct domain *d, ioservid_t id,
                               unsigned long idx, mfn_t *mfn)
{
    struct hvm_ioreq_server *s;
    int rc;

    ASSERT(is_hvm_domain(d));

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    rc = hvm_ioreq_server_alloc_pages(s);
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
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    return rc;
}

int hvm_map_io_range_to_ioreq_server(struct domain *d, ioservid_t id,
                                     uint32_t type, uint64_t start,
                                     uint64_t end)
{
    struct hvm_ioreq_server *s;
    struct rangeset *r;
    int rc;

    if ( start > end )
        return -EINVAL;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

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
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    return rc;
}

int hvm_unmap_io_range_from_ioreq_server(struct domain *d, ioservid_t id,
                                         uint32_t type, uint64_t start,
                                         uint64_t end)
{
    struct hvm_ioreq_server *s;
    struct rangeset *r;
    int rc;

    if ( start > end )
        return -EINVAL;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

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
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

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
int hvm_map_mem_type_to_ioreq_server(struct domain *d, ioservid_t id,
                                     uint32_t type, uint32_t flags)
{
    struct hvm_ioreq_server *s;
    int rc;

    if ( type != HVMMEM_ioreq_server )
        return -EINVAL;

    if ( flags & ~XEN_DMOP_IOREQ_MEM_ACCESS_WRITE )
        return -EINVAL;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    rc = p2m_set_ioreq_server(d, flags, s);

 out:
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    if ( rc == 0 && flags == 0 )
    {
        struct p2m_domain *p2m = p2m_get_hostp2m(d);

        if ( read_atomic(&p2m->ioreq.entry_count) )
            p2m_change_entry_type_global(d, p2m_ioreq_server, p2m_ram_rw);
    }

    return rc;
}

int hvm_set_ioreq_server_state(struct domain *d, ioservid_t id,
                               bool enabled)
{
    struct hvm_ioreq_server *s;
    int rc;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    s = get_ioreq_server(d, id);

    rc = -ENOENT;
    if ( !s )
        goto out;

    rc = -EPERM;
    if ( s->emulator != current->domain )
        goto out;

    domain_pause(d);

    if ( enabled )
        hvm_ioreq_server_enable(s);
    else
        hvm_ioreq_server_disable(s);

    domain_unpause(d);

    rc = 0;

 out:
    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);
    return rc;
}

int hvm_all_ioreq_servers_add_vcpu(struct domain *d, struct vcpu *v)
{
    struct hvm_ioreq_server *s;
    unsigned int id;
    int rc;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    FOR_EACH_IOREQ_SERVER(d, id, s)
    {
        rc = hvm_ioreq_server_add_vcpu(s, v);
        if ( rc )
            goto fail;
    }

    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    return 0;

 fail:
    while ( id-- != 0 )
    {
        s = GET_IOREQ_SERVER(d, id);

        if ( !s )
            continue;

        hvm_ioreq_server_remove_vcpu(s, v);
    }

    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);

    return rc;
}

void hvm_all_ioreq_servers_remove_vcpu(struct domain *d, struct vcpu *v)
{
    struct hvm_ioreq_server *s;
    unsigned int id;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    FOR_EACH_IOREQ_SERVER(d, id, s)
        hvm_ioreq_server_remove_vcpu(s, v);

    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);
}

void hvm_destroy_all_ioreq_servers(struct domain *d)
{
    struct hvm_ioreq_server *s;
    unsigned int id;

    spin_lock_recursive(&d->arch.hvm.ioreq_server.lock);

    /* No need to domain_pause() as the domain is being torn down */

    FOR_EACH_IOREQ_SERVER(d, id, s)
    {
        hvm_ioreq_server_disable(s);

        /*
         * It is safe to call hvm_ioreq_server_deinit() prior to
         * set_ioreq_server() since the target domain is being destroyed.
         */
        hvm_ioreq_server_deinit(s);
        set_ioreq_server(d, id, NULL);

        xfree(s);
    }

    spin_unlock_recursive(&d->arch.hvm.ioreq_server.lock);
}

struct hvm_ioreq_server *hvm_select_ioreq_server(struct domain *d,
                                                 ioreq_t *p)
{
    struct hvm_ioreq_server *s;
    uint32_t cf8;
    uint8_t type;
    uint64_t addr;
    unsigned int id;

    if ( p->type != IOREQ_TYPE_COPY && p->type != IOREQ_TYPE_PIO )
        return NULL;

    cf8 = d->arch.hvm.pci_cf8;

    if ( p->type == IOREQ_TYPE_PIO &&
         (p->addr & ~3) == 0xcfc &&
         CF8_ENABLED(cf8) )
    {
        uint32_t x86_fam;
        pci_sbdf_t sbdf;
        unsigned int reg;

        reg = hvm_pci_decode_addr(cf8, p->addr, &sbdf);

        /* PCI config data cycle */
        type = XEN_DMOP_IO_RANGE_PCI;
        addr = ((uint64_t)sbdf.sbdf << 32) | reg;
        /* AMD extended configuration space access? */
        if ( CF8_ADDR_HI(cf8) &&
             d->arch.cpuid->x86_vendor == X86_VENDOR_AMD &&
             (x86_fam = get_cpu_family(
                 d->arch.cpuid->basic.raw_fms, NULL, NULL)) > 0x10 &&
             x86_fam < 0x17 )
        {
            uint64_t msr_val;

            if ( !rdmsr_safe(MSR_AMD64_NB_CFG, msr_val) &&
                 (msr_val & (1ULL << AMD64_NB_CFG_CF8_EXT_ENABLE_BIT)) )
                addr |= CF8_ADDR_HI(cf8);
        }
    }
    else
    {
        type = (p->type == IOREQ_TYPE_PIO) ?
                XEN_DMOP_IO_RANGE_PORT : XEN_DMOP_IO_RANGE_MEMORY;
        addr = p->addr;
    }

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
            start = hvm_mmio_first_byte(p);
            end = hvm_mmio_last_byte(p);

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

static int hvm_send_buffered_ioreq(struct hvm_ioreq_server *s, ioreq_t *p)
{
    struct domain *d = current->domain;
    struct hvm_ioreq_page *iorp;
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
        return X86EMUL_UNHANDLEABLE;

    /*
     * Return 0 for the cases we can't deal with:
     *  - 'addr' is only a 20-bit field, so we cannot address beyond 1MB
     *  - we cannot buffer accesses to guest memory buffers, as the guest
     *    may expect the memory buffer to be synchronously accessed
     *  - the count field is usually used with data_is_ptr and since we don't
     *    support data_is_ptr we do not waste space for the count field either
     */
    if ( (p->addr > 0xffffful) || p->data_is_ptr || (p->count != 1) )
        return 0;

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
        return X86EMUL_UNHANDLEABLE;
    }

    spin_lock(&s->bufioreq_lock);

    if ( (pg->ptrs.write_pointer - pg->ptrs.read_pointer) >=
         (IOREQ_BUFFER_SLOT_NUM - qw) )
    {
        /* The queue is full: send the iopacket through the normal path. */
        spin_unlock(&s->bufioreq_lock);
        return X86EMUL_UNHANDLEABLE;
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
        cmpxchg(&pg->ptrs.full, old.full, new.full);
    }

    notify_via_xen_event_channel(d, s->bufioreq_evtchn);
    spin_unlock(&s->bufioreq_lock);

    return X86EMUL_OKAY;
}

int hvm_send_ioreq(struct hvm_ioreq_server *s, ioreq_t *proto_p,
                   bool buffered)
{
    struct vcpu *curr = current;
    struct domain *d = curr->domain;
    struct hvm_ioreq_vcpu *sv;

    ASSERT(s);

    if ( buffered )
        return hvm_send_buffered_ioreq(s, proto_p);

    if ( unlikely(!vcpu_start_shutdown_deferral(curr)) )
        return X86EMUL_RETRY;

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
            return X86EMUL_RETRY;
        }
    }

    return X86EMUL_UNHANDLEABLE;
}

unsigned int hvm_broadcast_ioreq(ioreq_t *p, bool buffered)
{
    struct domain *d = current->domain;
    struct hvm_ioreq_server *s;
    unsigned int id, failed = 0;

    FOR_EACH_IOREQ_SERVER(d, id, s)
    {
        if ( !s->enabled )
            continue;

        if ( hvm_send_ioreq(s, p, buffered) == X86EMUL_UNHANDLEABLE )
            failed++;
    }

    return failed;
}

static int hvm_access_cf8(
    int dir, unsigned int port, unsigned int bytes, uint32_t *val)
{
    struct domain *d = current->domain;

    if ( dir == IOREQ_WRITE && bytes == 4 )
        d->arch.hvm.pci_cf8 = *val;

    /* We always need to fall through to the catch all emulator */
    return X86EMUL_UNHANDLEABLE;
}

void hvm_ioreq_init(struct domain *d)
{
    spin_lock_init(&d->arch.hvm.ioreq_server.lock);

    register_portio_handler(d, 0xcf8, 4, hvm_access_cf8);
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
