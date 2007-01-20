/*
 * intercept.c: Handle performance critical I/O packets in hypervisor space
 *
 * Copyright (c) 2004, Intel Corporation.
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <asm/regs.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/domain.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <io_ports.h>
#include <xen/event.h>
#include <xen/compile.h>
#include <public/version.h>


extern struct hvm_mmio_handler hpet_mmio_handler;
extern struct hvm_mmio_handler vlapic_mmio_handler;
extern struct hvm_mmio_handler vioapic_mmio_handler;

#define HVM_MMIO_HANDLER_NR 3

static struct hvm_mmio_handler *hvm_mmio_handlers[HVM_MMIO_HANDLER_NR] =
{
    &hpet_mmio_handler,
    &vlapic_mmio_handler,
    &vioapic_mmio_handler
};

struct hvm_buffered_io_range {
    unsigned long start_addr;
    unsigned long length;
};

#define HVM_BUFFERED_IO_RANGE_NR 1

static struct hvm_buffered_io_range buffered_stdvga_range = {0xA0000, 0x20000};
static struct hvm_buffered_io_range
*hvm_buffered_io_ranges[HVM_BUFFERED_IO_RANGE_NR] =
{
    &buffered_stdvga_range
};

static inline void hvm_mmio_access(struct vcpu *v,
                                   ioreq_t *p,
                                   hvm_mmio_read_t read_handler,
                                   hvm_mmio_write_t write_handler)
{
    unsigned int tmp1, tmp2;
    unsigned long data;

    switch ( p->type ) {
    case IOREQ_TYPE_COPY:
    {
        if ( !p->data_is_ptr ) {
            if ( p->dir == IOREQ_READ )
                p->data = read_handler(v, p->addr, p->size);
            else    /* p->dir == IOREQ_WRITE */
                write_handler(v, p->addr, p->size, p->data);
        } else {    /* p->data_is_ptr */
            int i, sign = (p->df) ? -1 : 1;

            if ( p->dir == IOREQ_READ ) {
                for ( i = 0; i < p->count; i++ ) {
                    data = read_handler(v,
                        p->addr + (sign * i * p->size),
                        p->size);
                    (void)hvm_copy_to_guest_phys(
                        p->data + (sign * i * p->size),
                        &data,
                        p->size);
                }
            } else {/* p->dir == IOREQ_WRITE */
                for ( i = 0; i < p->count; i++ ) {
                    (void)hvm_copy_from_guest_phys(
                        &data,
                        p->data + (sign * i * p->size),
                        p->size);
                    write_handler(v,
                        p->addr + (sign * i * p->size),
                        p->size, data);
                }
            }
        }
        break;
    }

    case IOREQ_TYPE_AND:
        tmp1 = read_handler(v, p->addr, p->size);
        if ( p->dir == IOREQ_WRITE ) {
            tmp2 = tmp1 & (unsigned long) p->data;
            write_handler(v, p->addr, p->size, tmp2);
        }
        p->data = tmp1;
        break;

    case IOREQ_TYPE_ADD:
        tmp1 = read_handler(v, p->addr, p->size);
        if (p->dir == IOREQ_WRITE) {
            tmp2 = tmp1 + (unsigned long) p->data;
            write_handler(v, p->addr, p->size, tmp2);
        }
        p->data = tmp1;
        break;

    case IOREQ_TYPE_OR:
        tmp1 = read_handler(v, p->addr, p->size);
        if ( p->dir == IOREQ_WRITE ) {
            tmp2 = tmp1 | (unsigned long) p->data;
            write_handler(v, p->addr, p->size, tmp2);
        }
        p->data = tmp1;
        break;

    case IOREQ_TYPE_XOR:
        tmp1 = read_handler(v, p->addr, p->size);
        if ( p->dir == IOREQ_WRITE ) {
            tmp2 = tmp1 ^ (unsigned long) p->data;
            write_handler(v, p->addr, p->size, tmp2);
        }
        p->data = tmp1;
        break;

    case IOREQ_TYPE_XCHG:
        /*
         * Note that we don't need to be atomic here since VCPU is accessing
         * its own local APIC.
         */
        tmp1 = read_handler(v, p->addr, p->size);
        write_handler(v, p->addr, p->size, (unsigned long) p->data);
        p->data = tmp1;
        break;

    default:
        printk("hvm_mmio_access: error ioreq type %x\n", p->type);
        domain_crash_synchronous();
        break;
    }
}

/* save/restore support */
#define HVM_FILE_MAGIC   0x54381286
#define HVM_FILE_VERSION 0x00000001

int hvm_register_savevm(struct domain *d,
                    const char *idstr,
                    int instance_id,
                    int version_id,
                    SaveStateHandler *save_state,
                    LoadStateHandler *load_state,
                    void *opaque)
{
    HVMStateEntry *se, **pse;

    if ( (se = xmalloc(struct HVMStateEntry)) == NULL ){
        printk("allocat hvmstate entry fail.\n");
        return -1;
    }

    strncpy(se->idstr, idstr, HVM_SE_IDSTR_LEN);

    se->instance_id = instance_id;
    se->version_id = version_id;
    se->save_state = save_state;
    se->load_state = load_state;
    se->opaque = opaque;
    se->next = NULL;

    /* add at the end of list */
    pse = &d->arch.hvm_domain.first_se;
    while (*pse != NULL)
        pse = &(*pse)->next;
    *pse = se;
    return 0;
}

int hvm_save(struct vcpu *v, hvm_domain_context_t *h)
{
    uint32_t len, len_pos, cur_pos;
    uint32_t eax, ebx, ecx, edx;
    HVMStateEntry *se;
    char *chgset;

    if (!is_hvm_vcpu(v)) {
        printk("hvm_save only for hvm guest!\n");
        return -1;
    }

    memset(h, 0, sizeof(hvm_domain_context_t));
    hvm_put_32u(h, HVM_FILE_MAGIC);
    hvm_put_32u(h, HVM_FILE_VERSION);

    /* save xen changeset */
    chgset = strrchr(XEN_CHANGESET, ' ');
    if ( chgset )
        chgset++;
    else
        chgset = XEN_CHANGESET;

    len = strlen(chgset);
    hvm_put_8u(h, len);
    hvm_put_buffer(h, chgset, len);

    /* save cpuid */
    cpuid(1, &eax, &ebx, &ecx, &edx);
    hvm_put_32u(h, eax);

    for(se = v->domain->arch.hvm_domain.first_se; se != NULL; se = se->next) {
        /* ID string */
        len = strnlen(se->idstr, HVM_SE_IDSTR_LEN);
        hvm_put_8u(h, len);
        hvm_put_buffer(h, se->idstr, len);

        hvm_put_32u(h, se->instance_id);
        hvm_put_32u(h, se->version_id);

        /* record size */
        len_pos = hvm_ctxt_tell(h);
        hvm_put_32u(h, 0);

        se->save_state(h, se->opaque);

        cur_pos = hvm_ctxt_tell(h);
        len = cur_pos - len_pos - 4;
        hvm_ctxt_seek(h, len_pos);
        hvm_put_32u(h, len);
        hvm_ctxt_seek(h, cur_pos);

    }

    h->size = hvm_ctxt_tell(h);
    hvm_ctxt_seek(h, 0);

    if (h->size >= HVM_CTXT_SIZE) {
        printk("hvm_domain_context overflow when hvm_save! need %"PRId32" bytes for use.\n", h->size);
        return -1;
    }

    return 0;

}

static HVMStateEntry *find_se(struct domain *d, const char *idstr, int instance_id)
{
    HVMStateEntry *se;

    for(se = d->arch.hvm_domain.first_se; se != NULL; se = se->next) {
        if (!strncmp(se->idstr, idstr, HVM_SE_IDSTR_LEN) &&
            instance_id == se->instance_id){
            return se;
        }
    }
    return NULL;
}

int hvm_load(struct vcpu *v, hvm_domain_context_t *h)
{
    uint32_t len, rec_len, rec_pos, magic, instance_id, version_id;
    uint32_t eax, ebx, ecx, edx;
    HVMStateEntry *se;
    char idstr[HVM_SE_IDSTR_LEN];
    xen_changeset_info_t chgset;
    char *cur_chgset;
    int ret;

    if (!is_hvm_vcpu(v)) {
        printk("hvm_load only for hvm guest!\n");
        return -1;
    }

    if (h->size >= HVM_CTXT_SIZE) {
        printk("hvm_load fail! seems hvm_domain_context overflow when hvm_save! need %"PRId32" bytes.\n", h->size);
        return -1;
    }

    hvm_ctxt_seek(h, 0);

    magic = hvm_get_32u(h);
    if (magic != HVM_FILE_MAGIC) {
        printk("HVM restore magic dismatch!\n");
        return -1;
    }

    magic = hvm_get_32u(h);
    if (magic != HVM_FILE_VERSION) {
        printk("HVM restore version dismatch!\n");
        return -1;
    }

    /* check xen change set */
    cur_chgset = strrchr(XEN_CHANGESET, ' ');
    if ( cur_chgset )
        cur_chgset++;
    else
        cur_chgset = XEN_CHANGESET;

    len = hvm_get_8u(h);
    if (len > 20) { /*typical length is 18 -- "revision number:changeset id" */
        printk("wrong change set length %d when hvm restore!\n", len);
        return -1;
    }

    hvm_get_buffer(h, chgset, len);
    chgset[len] = '\0';
    if (strncmp(cur_chgset, chgset, len + 1))
        printk("warnings: try to restore hvm guest(%s) on a different changeset %s.\n",
                chgset, cur_chgset);


    if ( !strcmp(cur_chgset, "unavailable") )
        printk("warnings: try to restore hvm guest when changeset is unavailable.\n");


    /* check cpuid */
    cpuid(1, &eax, &ebx, &ecx, &edx);
    ebx = hvm_get_32u(h);
    /*TODO: need difine how big difference is acceptable */
    if (ebx != eax)
        printk("warnings: try to restore hvm guest(0x%"PRIx32") "
               "on a different type processor(0x%"PRIx32").\n",
                ebx,
                eax);

    while(1) {
        if (hvm_ctxt_end(h)) {
            break;
        }

        /* ID string */
        len = hvm_get_8u(h);
        if (len > HVM_SE_IDSTR_LEN) {
            printk("wrong HVM save entry idstr len %d!", len);
            return -1;
        }

        hvm_get_buffer(h, idstr, len);
        idstr[len] = '\0';

        instance_id = hvm_get_32u(h);
        version_id = hvm_get_32u(h);

        printk("HVM S/R Loading \"%s\" instance %#x\n", idstr, instance_id);

        rec_len = hvm_get_32u(h);
        rec_pos = hvm_ctxt_tell(h);

        se = find_se(v->domain, idstr, instance_id);
        if (se == NULL) {
            printk("warnings: hvm load can't find device %s's instance %d!\n",
                    idstr, instance_id);
        } else {
            ret = se->load_state(h, se->opaque, version_id);
            if (ret < 0)
                printk("warnings: loading state fail for device %s instance %d!\n",
                        idstr, instance_id);
        }
                    

        /* make sure to jump end of record */
        if ( hvm_ctxt_tell(h) - rec_pos != rec_len) {
            printk("wrong hvm record size, maybe some dismatch between save&restore handler!\n");
        }
        hvm_ctxt_seek(h, rec_pos + rec_len);
    }

    return 0;
}

int arch_gethvm_ctxt(
    struct vcpu *v, struct hvm_domain_context *c)
{
    if ( !is_hvm_vcpu(v) )
        return -1;

    return hvm_save(v, c);

}

int arch_sethvm_ctxt(
        struct vcpu *v, struct hvm_domain_context *c)
{
    return hvm_load(v, c);
}

#ifdef HVM_DEBUG_SUSPEND
static void shpage_info(shared_iopage_t *sh)
{

    vcpu_iodata_t *p = &sh->vcpu_iodata[0];
    ioreq_t *req = &p->vp_ioreq;
    printk("*****sharepage_info******!\n");
    printk("vp_eport=%d\n", p->vp_eport);
    printk("io packet: "
                     "state:%x, pvalid: %x, dir:%x, port: %"PRIx64", "
                     "data: %"PRIx64", count: %"PRIx64", size: %"PRIx64"\n",
                     req->state, req->data_is_ptr, req->dir, req->addr,
                     req->data, req->count, req->size);
}
#else
static void shpage_info(shared_iopage_t *sh)
{
}
#endif

static void shpage_save(hvm_domain_context_t *h, void *opaque)
{
    /* XXX:no action required for shpage save/restore, since it's in guest memory
     * keep it for debug purpose only */

#if 0
    struct shared_iopage *s = opaque;
    /* XXX:smp */
    struct ioreq *req = &s->vcpu_iodata[0].vp_ioreq;
    
    shpage_info(s);

    hvm_put_buffer(h, (char*)req, sizeof(struct ioreq));
#endif
}

static int shpage_load(hvm_domain_context_t *h, void *opaque, int version_id)
{
    struct shared_iopage *s = opaque;
#if 0
    /* XXX:smp */
    struct ioreq *req = &s->vcpu_iodata[0].vp_ioreq;

    if (version_id != 1)
        return -EINVAL;

    hvm_get_buffer(h, (char*)req, sizeof(struct ioreq));


#endif
    shpage_info(s);
    return 0;
}

void shpage_init(struct domain *d, shared_iopage_t *sp)
{
    hvm_register_savevm(d, "xen_hvm_shpage", 0x10, 1, shpage_save, shpage_load, sp);
}

int hvm_buffered_io_intercept(ioreq_t *p)
{
    struct vcpu *v = current;
    spinlock_t  *buffered_io_lock;
    buffered_iopage_t *buffered_iopage =
        (buffered_iopage_t *)(v->domain->arch.hvm_domain.buffered_io_va);
    unsigned long tmp_write_pointer = 0;
    int i;

    /* ignore READ ioreq_t! */
    if ( p->dir == IOREQ_READ )
        return 0;

    for ( i = 0; i < HVM_BUFFERED_IO_RANGE_NR; i++ ) {
        if ( p->addr >= hvm_buffered_io_ranges[i]->start_addr &&
             p->addr + p->size - 1 < hvm_buffered_io_ranges[i]->start_addr +
                                     hvm_buffered_io_ranges[i]->length )
            break;
    }

    if ( i == HVM_BUFFERED_IO_RANGE_NR )
        return 0;

    buffered_io_lock = &v->domain->arch.hvm_domain.buffered_io_lock;
    spin_lock(buffered_io_lock);

    if ( buffered_iopage->write_pointer - buffered_iopage->read_pointer ==
         (unsigned int)IOREQ_BUFFER_SLOT_NUM ) {
        /* the queue is full.
         * send the iopacket through the normal path.
         * NOTE: The arithimetic operation could handle the situation for
         * write_pointer overflow.
         */
        spin_unlock(buffered_io_lock);
        return 0;
    }

    tmp_write_pointer = buffered_iopage->write_pointer % IOREQ_BUFFER_SLOT_NUM;

    memcpy(&buffered_iopage->ioreq[tmp_write_pointer], p, sizeof(ioreq_t));

    /*make the ioreq_t visible before write_pointer*/
    wmb();
    buffered_iopage->write_pointer++;

    spin_unlock(buffered_io_lock);

    return 1;
}

int hvm_mmio_intercept(ioreq_t *p)
{
    struct vcpu *v = current;
    int i;

    for ( i = 0; i < HVM_MMIO_HANDLER_NR; i++ )
    {
        if ( hvm_mmio_handlers[i]->check_handler(v, p->addr) )
        {
            hvm_mmio_access(v, p,
                            hvm_mmio_handlers[i]->read_handler,
                            hvm_mmio_handlers[i]->write_handler);
            return 1;
        }
    }

    return 0;
}

/*
 * Check if the request is handled inside xen
 * return value: 0 --not handled; 1 --handled
 */
int hvm_io_intercept(ioreq_t *p, int type)
{
    struct vcpu *v = current;
    struct hvm_io_handler *handler =
                           &(v->domain->arch.hvm_domain.io_handler);
    int i;
    unsigned long addr, size;

    for (i = 0; i < handler->num_slot; i++) {
        if( type != handler->hdl_list[i].type)
            continue;
        addr = handler->hdl_list[i].addr;
        size = handler->hdl_list[i].size;
        if (p->addr >= addr &&
            p->addr <  addr + size)
            return handler->hdl_list[i].action(p);
    }
    return 0;
}

int register_io_handler(
    struct domain *d, unsigned long addr, unsigned long size,
    intercept_action_t action, int type)
{
    struct hvm_io_handler *handler = &d->arch.hvm_domain.io_handler;
    int num = handler->num_slot;

    BUG_ON(num >= MAX_IO_HANDLER);

    handler->hdl_list[num].addr = addr;
    handler->hdl_list[num].size = size;
    handler->hdl_list[num].action = action;
    handler->hdl_list[num].type = type;
    handler->num_slot++;

    return 1;
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
