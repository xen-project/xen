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

#include <xen/config.h>
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

#include <asm/hvm/hvm.h>
#include <asm/hvm/ioreq.h>
#include <asm/hvm/vmx/vmx.h>

#include <public/hvm/ioreq.h>

static ioreq_t *get_ioreq(struct hvm_ioreq_server *s, struct vcpu *v)
{
    shared_iopage_t *p = s->ioreq.va;

    ASSERT((v == current) || !vcpu_runnable(v));
    ASSERT(p != NULL);

    return &p->vcpu_ioreq[v->vcpu_id];
}

bool_t hvm_io_pending(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct hvm_ioreq_server *s;

    list_for_each_entry ( s,
                          &d->arch.hvm_domain.ioreq_server.list,
                          list_entry )
    {
        struct hvm_ioreq_vcpu *sv;

        list_for_each_entry ( sv,
                              &s->ioreq_vcpu_list,
                              list_entry )
        {
            if ( sv->vcpu == v && sv->pending )
                return 1;
        }
    }

    return 0;
}

static void hvm_io_assist(struct hvm_ioreq_vcpu *sv, uint64_t data)
{
    struct vcpu *v = sv->vcpu;
    struct hvm_vcpu_io *vio = &v->arch.hvm_vcpu.hvm_io;

    if ( hvm_vcpu_io_need_completion(vio) )
    {
        vio->io_req.state = STATE_IORESP_READY;
        vio->io_req.data = data;
    }
    else
        vio->io_req.state = STATE_IOREQ_NONE;

    msix_write_completion(v);
    vcpu_end_shutdown_deferral(v);

    sv->pending = 0;
}

static bool_t hvm_wait_for_io(struct hvm_ioreq_vcpu *sv, ioreq_t *p)
{
    while ( sv->pending )
    {
        unsigned int state = p->state;

        rmb();
        switch ( state )
        {
        case STATE_IOREQ_NONE:
            /*
             * The only reason we should see this case is when an
             * emulator is dying and it races with an I/O being
             * requested.
             */
            hvm_io_assist(sv, ~0ul);
            break;
        case STATE_IORESP_READY: /* IORESP_READY -> NONE */
            p->state = STATE_IOREQ_NONE;
            hvm_io_assist(sv, p->data);
            break;
        case STATE_IOREQ_READY:  /* IOREQ_{READY,INPROCESS} -> IORESP_READY */
        case STATE_IOREQ_INPROCESS:
            wait_on_xen_event_channel(sv->ioreq_evtchn, p->state != state);
            break;
        default:
            gdprintk(XENLOG_ERR, "Weird HVM iorequest state %u\n", state);
            sv->pending = 0;
            domain_crash(sv->vcpu->domain);
            return 0; /* bail */
        }
    }

    return 1;
}

bool_t handle_hvm_io_completion(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct hvm_vcpu_io *vio = &v->arch.hvm_vcpu.hvm_io;
    struct hvm_ioreq_server *s;
    enum hvm_io_completion io_completion;

      list_for_each_entry ( s,
                          &d->arch.hvm_domain.ioreq_server.list,
                          list_entry )
    {
        struct hvm_ioreq_vcpu *sv;

        list_for_each_entry ( sv,
                              &s->ioreq_vcpu_list,
                              list_entry )
        {
            if ( sv->vcpu == v && sv->pending )
            {
                if ( !hvm_wait_for_io(sv, get_ioreq(s, v)) )
                    return 0;

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
        handle_mmio();
        break;
    case HVMIO_pio_completion:
        (void)handle_pio(vio->io_req.addr, vio->io_req.size,
                         vio->io_req.dir);
        break;
    case HVMIO_realmode_completion:
    {
        struct hvm_emulate_ctxt ctxt;

        hvm_emulate_init_once(&ctxt, guest_cpu_user_regs());
        vmx_realmode_emulate_one(&ctxt);
        hvm_emulate_writeback(&ctxt);

        break;
    }
    default:
        ASSERT_UNREACHABLE();
        break;
    }

    return 1;
}

static int hvm_alloc_ioreq_gmfn(struct domain *d, unsigned long *gmfn)
{
    unsigned int i;
    int rc;

    rc = -ENOMEM;
    for ( i = 0; i < sizeof(d->arch.hvm_domain.ioreq_gmfn.mask) * 8; i++ )
    {
        if ( test_and_clear_bit(i, &d->arch.hvm_domain.ioreq_gmfn.mask) )
        {
            *gmfn = d->arch.hvm_domain.ioreq_gmfn.base + i;
            rc = 0;
            break;
        }
    }

    return rc;
}

static void hvm_free_ioreq_gmfn(struct domain *d, unsigned long gmfn)
{
    unsigned int i = gmfn - d->arch.hvm_domain.ioreq_gmfn.base;

    if ( gmfn != gfn_x(INVALID_GFN) )
        set_bit(i, &d->arch.hvm_domain.ioreq_gmfn.mask);
}

static void hvm_unmap_ioreq_page(struct hvm_ioreq_server *s, bool_t buf)
{
    struct hvm_ioreq_page *iorp = buf ? &s->bufioreq : &s->ioreq;

    destroy_ring_for_helper(&iorp->va, iorp->page);
}

static int hvm_map_ioreq_page(
    struct hvm_ioreq_server *s, bool_t buf, unsigned long gmfn)
{
    struct domain *d = s->domain;
    struct hvm_ioreq_page *iorp = buf ? &s->bufioreq : &s->ioreq;
    struct page_info *page;
    void *va;
    int rc;

    if ( (rc = prepare_ring_for_helper(d, gmfn, &page, &va)) )
        return rc;

    if ( (iorp->va != NULL) || d->is_dying )
    {
        destroy_ring_for_helper(&va, page);
        return -EINVAL;
    }

    iorp->va = va;
    iorp->page = page;
    iorp->gmfn = gmfn;

    return 0;
}

bool_t is_ioreq_server_page(struct domain *d, const struct page_info *page)
{
    const struct hvm_ioreq_server *s;
    bool_t found = 0;

    spin_lock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    list_for_each_entry ( s,
                          &d->arch.hvm_domain.ioreq_server.list,
                          list_entry )
    {
        if ( (s->ioreq.va && s->ioreq.page == page) ||
             (s->bufioreq.va && s->bufioreq.page == page) )
        {
            found = 1;
            break;
        }
    }

    spin_unlock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    return found;
}

static void hvm_remove_ioreq_gmfn(
    struct domain *d, struct hvm_ioreq_page *iorp)
{
    guest_physmap_remove_page(d, _gfn(iorp->gmfn),
                              _mfn(page_to_mfn(iorp->page)), 0);
    clear_page(iorp->va);
}

static int hvm_add_ioreq_gmfn(
    struct domain *d, struct hvm_ioreq_page *iorp)
{
    int rc;

    clear_page(iorp->va);

    rc = guest_physmap_add_page(d, _gfn(iorp->gmfn),
                                _mfn(page_to_mfn(iorp->page)), 0);
    if ( rc == 0 )
        paging_mark_dirty(d, page_to_mfn(iorp->page));

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

static int hvm_ioreq_server_add_vcpu(struct hvm_ioreq_server *s,
                                     bool_t is_default, struct vcpu *v)
{
    struct hvm_ioreq_vcpu *sv;
    int rc;

    sv = xzalloc(struct hvm_ioreq_vcpu);

    rc = -ENOMEM;
    if ( !sv )
        goto fail1;

    spin_lock(&s->lock);

    rc = alloc_unbound_xen_event_channel(v->domain, v->vcpu_id, s->domid,
                                         NULL);
    if ( rc < 0 )
        goto fail2;

    sv->ioreq_evtchn = rc;

    if ( v->vcpu_id == 0 && s->bufioreq.va != NULL )
    {
        struct domain *d = s->domain;

        rc = alloc_unbound_xen_event_channel(v->domain, 0, s->domid, NULL);
        if ( rc < 0 )
            goto fail3;

        s->bufioreq_evtchn = rc;
        if ( is_default )
            d->arch.hvm_domain.params[HVM_PARAM_BUFIOREQ_EVTCHN] =
                s->bufioreq_evtchn;
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

        if ( v->vcpu_id == 0 && s->bufioreq.va != NULL )
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

        if ( v->vcpu_id == 0 && s->bufioreq.va != NULL )
            free_xen_event_channel(v->domain, s->bufioreq_evtchn);

        free_xen_event_channel(v->domain, sv->ioreq_evtchn);

        xfree(sv);
    }

    spin_unlock(&s->lock);
}

static int hvm_ioreq_server_map_pages(struct hvm_ioreq_server *s,
                                      unsigned long ioreq_pfn,
                                      unsigned long bufioreq_pfn)
{
    int rc;

    rc = hvm_map_ioreq_page(s, 0, ioreq_pfn);
    if ( rc )
        return rc;

    if ( bufioreq_pfn != gfn_x(INVALID_GFN) )
        rc = hvm_map_ioreq_page(s, 1, bufioreq_pfn);

    if ( rc )
        hvm_unmap_ioreq_page(s, 0);

    return rc;
}

static int hvm_ioreq_server_setup_pages(struct hvm_ioreq_server *s,
                                        bool_t is_default,
                                        bool_t handle_bufioreq)
{
    struct domain *d = s->domain;
    unsigned long ioreq_pfn = gfn_x(INVALID_GFN);
    unsigned long bufioreq_pfn = gfn_x(INVALID_GFN);
    int rc;

    if ( is_default )
    {
        /*
         * The default ioreq server must handle buffered ioreqs, for
         * backwards compatibility.
         */
        ASSERT(handle_bufioreq);
        return hvm_ioreq_server_map_pages(s,
                   d->arch.hvm_domain.params[HVM_PARAM_IOREQ_PFN],
                   d->arch.hvm_domain.params[HVM_PARAM_BUFIOREQ_PFN]);
    }

    rc = hvm_alloc_ioreq_gmfn(d, &ioreq_pfn);

    if ( !rc && handle_bufioreq )
        rc = hvm_alloc_ioreq_gmfn(d, &bufioreq_pfn);

    if ( !rc )
        rc = hvm_ioreq_server_map_pages(s, ioreq_pfn, bufioreq_pfn);

    if ( rc )
    {
        hvm_free_ioreq_gmfn(d, ioreq_pfn);
        hvm_free_ioreq_gmfn(d, bufioreq_pfn);
    }

    return rc;
}

static void hvm_ioreq_server_unmap_pages(struct hvm_ioreq_server *s,
                                         bool_t is_default)
{
    struct domain *d = s->domain;
    bool_t handle_bufioreq = ( s->bufioreq.va != NULL );

    if ( handle_bufioreq )
        hvm_unmap_ioreq_page(s, 1);

    hvm_unmap_ioreq_page(s, 0);

    if ( !is_default )
    {
        if ( handle_bufioreq )
            hvm_free_ioreq_gmfn(d, s->bufioreq.gmfn);

        hvm_free_ioreq_gmfn(d, s->ioreq.gmfn);
    }
}

static void hvm_ioreq_server_free_rangesets(struct hvm_ioreq_server *s,
                                            bool_t is_default)
{
    unsigned int i;

    if ( is_default )
        return;

    for ( i = 0; i < NR_IO_RANGE_TYPES; i++ )
        rangeset_destroy(s->range[i]);
}

static int hvm_ioreq_server_alloc_rangesets(struct hvm_ioreq_server *s,
                                            bool_t is_default)
{
    unsigned int i;
    int rc;

    if ( is_default )
        goto done;

    for ( i = 0; i < NR_IO_RANGE_TYPES; i++ )
    {
        char *name;

        rc = asprintf(&name, "ioreq_server %d %s", s->id,
                      (i == HVMOP_IO_RANGE_PORT) ? "port" :
                      (i == HVMOP_IO_RANGE_MEMORY) ? "memory" :
                      (i == HVMOP_IO_RANGE_PCI) ? "pci" :
                      "");
        if ( rc )
            goto fail;

        s->range[i] = rangeset_new(s->domain, name,
                                   RANGESETF_prettyprint_hex);

        xfree(name);

        rc = -ENOMEM;
        if ( !s->range[i] )
            goto fail;

        rangeset_limit(s->range[i], MAX_NR_IO_RANGES);
    }

 done:
    return 0;

 fail:
    hvm_ioreq_server_free_rangesets(s, 0);

    return rc;
}

static void hvm_ioreq_server_enable(struct hvm_ioreq_server *s,
                                    bool_t is_default)
{
    struct domain *d = s->domain;
    struct hvm_ioreq_vcpu *sv;
    bool_t handle_bufioreq = ( s->bufioreq.va != NULL );

    spin_lock(&s->lock);

    if ( s->enabled )
        goto done;

    if ( !is_default )
    {
        hvm_remove_ioreq_gmfn(d, &s->ioreq);

        if ( handle_bufioreq )
            hvm_remove_ioreq_gmfn(d, &s->bufioreq);
    }

    s->enabled = 1;

    list_for_each_entry ( sv,
                          &s->ioreq_vcpu_list,
                          list_entry )
        hvm_update_ioreq_evtchn(s, sv);

  done:
    spin_unlock(&s->lock);
}

static void hvm_ioreq_server_disable(struct hvm_ioreq_server *s,
                                    bool_t is_default)
{
    struct domain *d = s->domain;
    bool_t handle_bufioreq = ( s->bufioreq.va != NULL );

    spin_lock(&s->lock);

    if ( !s->enabled )
        goto done;

    if ( !is_default )
    {
        if ( handle_bufioreq )
            hvm_add_ioreq_gmfn(d, &s->bufioreq);

        hvm_add_ioreq_gmfn(d, &s->ioreq);
    }

    s->enabled = 0;

 done:
    spin_unlock(&s->lock);
}

static int hvm_ioreq_server_init(struct hvm_ioreq_server *s,
                                 struct domain *d, domid_t domid,
                                 bool_t is_default, int bufioreq_handling,
                                 ioservid_t id)
{
    struct vcpu *v;
    int rc;

    s->id = id;
    s->domain = d;
    s->domid = domid;

    spin_lock_init(&s->lock);
    INIT_LIST_HEAD(&s->ioreq_vcpu_list);
    spin_lock_init(&s->bufioreq_lock);

    rc = hvm_ioreq_server_alloc_rangesets(s, is_default);
    if ( rc )
        return rc;

    if ( bufioreq_handling == HVM_IOREQSRV_BUFIOREQ_ATOMIC )
        s->bufioreq_atomic = 1;

    rc = hvm_ioreq_server_setup_pages(
             s, is_default, bufioreq_handling != HVM_IOREQSRV_BUFIOREQ_OFF);
    if ( rc )
        goto fail_map;

    for_each_vcpu ( d, v )
    {
        rc = hvm_ioreq_server_add_vcpu(s, is_default, v);
        if ( rc )
            goto fail_add;
    }

    return 0;

 fail_add:
    hvm_ioreq_server_remove_all_vcpus(s);
    hvm_ioreq_server_unmap_pages(s, is_default);

 fail_map:
    hvm_ioreq_server_free_rangesets(s, is_default);

    return rc;
}

static void hvm_ioreq_server_deinit(struct hvm_ioreq_server *s,
                                    bool_t is_default)
{
    ASSERT(!s->enabled);
    hvm_ioreq_server_remove_all_vcpus(s);
    hvm_ioreq_server_unmap_pages(s, is_default);
    hvm_ioreq_server_free_rangesets(s, is_default);
}

static ioservid_t next_ioservid(struct domain *d)
{
    struct hvm_ioreq_server *s;
    ioservid_t id;

    ASSERT(spin_is_locked(&d->arch.hvm_domain.ioreq_server.lock));

    id = d->arch.hvm_domain.ioreq_server.id;

 again:
    id++;

    /* Check for uniqueness */
    list_for_each_entry ( s,
                          &d->arch.hvm_domain.ioreq_server.list,
                          list_entry )
    {
        if ( id == s->id )
            goto again;
    }

    d->arch.hvm_domain.ioreq_server.id = id;

    return id;
}

int hvm_create_ioreq_server(struct domain *d, domid_t domid,
                            bool_t is_default, int bufioreq_handling,
                            ioservid_t *id)
{
    struct hvm_ioreq_server *s;
    int rc;

    if ( bufioreq_handling > HVM_IOREQSRV_BUFIOREQ_ATOMIC )
        return -EINVAL;

    rc = -ENOMEM;
    s = xzalloc(struct hvm_ioreq_server);
    if ( !s )
        goto fail1;

    domain_pause(d);
    spin_lock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    rc = -EEXIST;
    if ( is_default && d->arch.hvm_domain.default_ioreq_server != NULL )
        goto fail2;

    rc = hvm_ioreq_server_init(s, d, domid, is_default, bufioreq_handling,
                               next_ioservid(d));
    if ( rc )
        goto fail3;

    list_add(&s->list_entry,
             &d->arch.hvm_domain.ioreq_server.list);

    if ( is_default )
    {
        d->arch.hvm_domain.default_ioreq_server = s;
        hvm_ioreq_server_enable(s, 1);
    }

    if ( id )
        *id = s->id;

    spin_unlock_recursive(&d->arch.hvm_domain.ioreq_server.lock);
    domain_unpause(d);

    return 0;

 fail3:
 fail2:
    spin_unlock_recursive(&d->arch.hvm_domain.ioreq_server.lock);
    domain_unpause(d);

    xfree(s);
 fail1:
    return rc;
}

int hvm_destroy_ioreq_server(struct domain *d, ioservid_t id)
{
    struct hvm_ioreq_server *s;
    int rc;

    spin_lock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    rc = -ENOENT;
    list_for_each_entry ( s,
                          &d->arch.hvm_domain.ioreq_server.list,
                          list_entry )
    {
        if ( s == d->arch.hvm_domain.default_ioreq_server )
            continue;

        if ( s->id != id )
            continue;

        domain_pause(d);

        hvm_ioreq_server_disable(s, 0);

        list_del(&s->list_entry);

        hvm_ioreq_server_deinit(s, 0);

        domain_unpause(d);

        xfree(s);

        rc = 0;
        break;
    }

    spin_unlock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    return rc;
}

int hvm_get_ioreq_server_info(struct domain *d, ioservid_t id,
                              unsigned long *ioreq_pfn,
                              unsigned long *bufioreq_pfn,
                              evtchn_port_t *bufioreq_port)
{
    struct hvm_ioreq_server *s;
    int rc;

    spin_lock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    rc = -ENOENT;
    list_for_each_entry ( s,
                          &d->arch.hvm_domain.ioreq_server.list,
                          list_entry )
    {
        if ( s == d->arch.hvm_domain.default_ioreq_server )
            continue;

        if ( s->id != id )
            continue;

        *ioreq_pfn = s->ioreq.gmfn;

        if ( s->bufioreq.va != NULL )
        {
            *bufioreq_pfn = s->bufioreq.gmfn;
            *bufioreq_port = s->bufioreq_evtchn;
        }

        rc = 0;
        break;
    }

    spin_unlock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    return rc;
}

int hvm_map_io_range_to_ioreq_server(struct domain *d, ioservid_t id,
                                     uint32_t type, uint64_t start,
                                     uint64_t end)
{
    struct hvm_ioreq_server *s;
    int rc;

    spin_lock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    rc = -ENOENT;
    list_for_each_entry ( s,
                          &d->arch.hvm_domain.ioreq_server.list,
                          list_entry )
    {
        if ( s == d->arch.hvm_domain.default_ioreq_server )
            continue;

        if ( s->id == id )
        {
            struct rangeset *r;

            switch ( type )
            {
            case HVMOP_IO_RANGE_PORT:
            case HVMOP_IO_RANGE_MEMORY:
            case HVMOP_IO_RANGE_PCI:
                r = s->range[type];
                break;

            default:
                r = NULL;
                break;
            }

            rc = -EINVAL;
            if ( !r )
                break;

            rc = -EEXIST;
            if ( rangeset_overlaps_range(r, start, end) )
                break;

            rc = rangeset_add_range(r, start, end);
            break;
        }
    }

    spin_unlock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    return rc;
}

int hvm_unmap_io_range_from_ioreq_server(struct domain *d, ioservid_t id,
                                         uint32_t type, uint64_t start,
                                         uint64_t end)
{
    struct hvm_ioreq_server *s;
    int rc;

    spin_lock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    rc = -ENOENT;
    list_for_each_entry ( s,
                          &d->arch.hvm_domain.ioreq_server.list,
                          list_entry )
    {
        if ( s == d->arch.hvm_domain.default_ioreq_server )
            continue;

        if ( s->id == id )
        {
            struct rangeset *r;

            switch ( type )
            {
            case HVMOP_IO_RANGE_PORT:
            case HVMOP_IO_RANGE_MEMORY:
            case HVMOP_IO_RANGE_PCI:
                r = s->range[type];
                break;

            default:
                r = NULL;
                break;
            }

            rc = -EINVAL;
            if ( !r )
                break;

            rc = -ENOENT;
            if ( !rangeset_contains_range(r, start, end) )
                break;

            rc = rangeset_remove_range(r, start, end);
            break;
        }
    }

    spin_unlock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    return rc;
}

int hvm_set_ioreq_server_state(struct domain *d, ioservid_t id,
                               bool_t enabled)
{
    struct list_head *entry;
    int rc;

    spin_lock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    rc = -ENOENT;
    list_for_each ( entry,
                    &d->arch.hvm_domain.ioreq_server.list )
    {
        struct hvm_ioreq_server *s = list_entry(entry,
                                                struct hvm_ioreq_server,
                                                list_entry);

        if ( s == d->arch.hvm_domain.default_ioreq_server )
            continue;

        if ( s->id != id )
            continue;

        domain_pause(d);

        if ( enabled )
            hvm_ioreq_server_enable(s, 0);
        else
            hvm_ioreq_server_disable(s, 0);

        domain_unpause(d);

        rc = 0;
        break;
    }

    spin_unlock_recursive(&d->arch.hvm_domain.ioreq_server.lock);
    return rc;
}

int hvm_all_ioreq_servers_add_vcpu(struct domain *d, struct vcpu *v)
{
    struct hvm_ioreq_server *s;
    int rc;

    spin_lock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    list_for_each_entry ( s,
                          &d->arch.hvm_domain.ioreq_server.list,
                          list_entry )
    {
        bool_t is_default = (s == d->arch.hvm_domain.default_ioreq_server);

        rc = hvm_ioreq_server_add_vcpu(s, is_default, v);
        if ( rc )
            goto fail;
    }

    spin_unlock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    return 0;

 fail:
    list_for_each_entry ( s,
                          &d->arch.hvm_domain.ioreq_server.list,
                          list_entry )
        hvm_ioreq_server_remove_vcpu(s, v);

    spin_unlock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    return rc;
}

void hvm_all_ioreq_servers_remove_vcpu(struct domain *d, struct vcpu *v)
{
    struct hvm_ioreq_server *s;

    spin_lock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    list_for_each_entry ( s,
                          &d->arch.hvm_domain.ioreq_server.list,
                          list_entry )
        hvm_ioreq_server_remove_vcpu(s, v);

    spin_unlock_recursive(&d->arch.hvm_domain.ioreq_server.lock);
}

void hvm_destroy_all_ioreq_servers(struct domain *d)
{
    struct hvm_ioreq_server *s, *next;

    spin_lock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    /* No need to domain_pause() as the domain is being torn down */

    list_for_each_entry_safe ( s,
                               next,
                               &d->arch.hvm_domain.ioreq_server.list,
                               list_entry )
    {
        bool_t is_default = (s == d->arch.hvm_domain.default_ioreq_server);

        hvm_ioreq_server_disable(s, is_default);

        if ( is_default )
            d->arch.hvm_domain.default_ioreq_server = NULL;

        list_del(&s->list_entry);

        hvm_ioreq_server_deinit(s, is_default);

        xfree(s);
    }

    spin_unlock_recursive(&d->arch.hvm_domain.ioreq_server.lock);
}

static int hvm_replace_event_channel(struct vcpu *v, domid_t remote_domid,
                                     evtchn_port_t *p_port)
{
    int old_port, new_port;

    new_port = alloc_unbound_xen_event_channel(v->domain, v->vcpu_id,
                                               remote_domid, NULL);
    if ( new_port < 0 )
        return new_port;

    /* xchg() ensures that only we call free_xen_event_channel(). */
    old_port = xchg(p_port, new_port);
    free_xen_event_channel(v->domain, old_port);
    return 0;
}

int hvm_set_dm_domain(struct domain *d, domid_t domid)
{
    struct hvm_ioreq_server *s;
    int rc = 0;

    spin_lock_recursive(&d->arch.hvm_domain.ioreq_server.lock);

    /*
     * Lack of ioreq server is not a failure. HVM_PARAM_DM_DOMAIN will
     * still be set and thus, when the server is created, it will have
     * the correct domid.
     */
    s = d->arch.hvm_domain.default_ioreq_server;
    if ( !s )
        goto done;

    domain_pause(d);
    spin_lock(&s->lock);

    if ( s->domid != domid )
    {
        struct hvm_ioreq_vcpu *sv;

        list_for_each_entry ( sv,
                              &s->ioreq_vcpu_list,
                              list_entry )
        {
            struct vcpu *v = sv->vcpu;

            if ( v->vcpu_id == 0 )
            {
                rc = hvm_replace_event_channel(v, domid,
                                               &s->bufioreq_evtchn);
                if ( rc )
                    break;

                d->arch.hvm_domain.params[HVM_PARAM_BUFIOREQ_EVTCHN] =
                    s->bufioreq_evtchn;
            }

            rc = hvm_replace_event_channel(v, domid, &sv->ioreq_evtchn);
            if ( rc )
                break;

            hvm_update_ioreq_evtchn(s, sv);
        }

        s->domid = domid;
    }

    spin_unlock(&s->lock);
    domain_unpause(d);

 done:
    spin_unlock_recursive(&d->arch.hvm_domain.ioreq_server.lock);
    return rc;
}

struct hvm_ioreq_server *hvm_select_ioreq_server(struct domain *d,
                                                 ioreq_t *p)
{
    struct hvm_ioreq_server *s;
    uint32_t cf8;
    uint8_t type;
    uint64_t addr;

    if ( list_empty(&d->arch.hvm_domain.ioreq_server.list) )
        return NULL;

    if ( p->type != IOREQ_TYPE_COPY && p->type != IOREQ_TYPE_PIO )
        return d->arch.hvm_domain.default_ioreq_server;

    cf8 = d->arch.hvm_domain.pci_cf8;

    if ( p->type == IOREQ_TYPE_PIO &&
         (p->addr & ~3) == 0xcfc &&
         CF8_ENABLED(cf8) )
    {
        uint32_t sbdf;

        /* PCI config data cycle */

        sbdf = HVMOP_PCI_SBDF(0,
                              PCI_BUS(CF8_BDF(cf8)),
                              PCI_SLOT(CF8_BDF(cf8)),
                              PCI_FUNC(CF8_BDF(cf8)));

        type = HVMOP_IO_RANGE_PCI;
        addr = ((uint64_t)sbdf << 32) |
               CF8_ADDR_LO(cf8) |
               (p->addr & 3);
        /* AMD extended configuration space access? */
        if ( CF8_ADDR_HI(cf8) &&
             d->arch.x86_vendor == X86_VENDOR_AMD &&
             d->arch.x86 >= 0x10 && d->arch.x86 <= 0x17 )
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
                HVMOP_IO_RANGE_PORT : HVMOP_IO_RANGE_MEMORY;
        addr = p->addr;
    }

    list_for_each_entry ( s,
                          &d->arch.hvm_domain.ioreq_server.list,
                          list_entry )
    {
        struct rangeset *r;

        if ( s == d->arch.hvm_domain.default_ioreq_server )
            continue;

        if ( !s->enabled )
            continue;

        r = s->range[type];

        switch ( type )
        {
            unsigned long end;

        case HVMOP_IO_RANGE_PORT:
            end = addr + p->size - 1;
            if ( rangeset_contains_range(r, addr, end) )
                return s;

            break;
        case HVMOP_IO_RANGE_MEMORY:
            end = addr + (p->size * p->count) - 1;
            if ( rangeset_contains_range(r, addr, end) )
                return s;

            break;
        case HVMOP_IO_RANGE_PCI:
            if ( rangeset_contains_singleton(r, addr >> 32) )
            {
                p->type = IOREQ_TYPE_PCI_CONFIG;
                p->addr = addr;
                return s;
            }

            break;
        }
    }

    return d->arch.hvm_domain.default_ioreq_server;
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
    wmb();
    pg->ptrs.write_pointer += qw ? 2 : 1;

    /* Canonicalize read/write pointers to prevent their overflow. */
    while ( s->bufioreq_atomic && qw++ < IOREQ_BUFFER_SLOT_NUM &&
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
                   bool_t buffered)
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

            sv->pending = 1;
            return X86EMUL_RETRY;
        }
    }

    return X86EMUL_UNHANDLEABLE;
}

unsigned int hvm_broadcast_ioreq(ioreq_t *p, bool_t buffered)
{
    struct domain *d = current->domain;
    struct hvm_ioreq_server *s;
    unsigned int failed = 0;

    list_for_each_entry ( s,
                          &d->arch.hvm_domain.ioreq_server.list,
                          list_entry )
        if ( hvm_send_ioreq(s, p, buffered) == X86EMUL_UNHANDLEABLE )
            failed++;

    return failed;
}

static int hvm_access_cf8(
    int dir, unsigned int port, unsigned int bytes, uint32_t *val)
{
    struct domain *d = current->domain;

    if ( dir == IOREQ_WRITE && bytes == 4 )
        d->arch.hvm_domain.pci_cf8 = *val;

    /* We always need to fall through to the catch all emulator */
    return X86EMUL_UNHANDLEABLE;
}

void hvm_ioreq_init(struct domain *d)
{
    spin_lock_init(&d->arch.hvm_domain.ioreq_server.lock);
    INIT_LIST_HEAD(&d->arch.hvm_domain.ioreq_server.list);

    if ( !is_pvh_domain(d) )
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
