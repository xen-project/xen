/******************************************************************************
 * arch/x86/guest/vixen.c
 *
 * Support for detecting and running under Xen HVM.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2017-2018 Amazon.com, Inc. or its affiliates.
 */

#include <asm/guest/vixen.h>
#include <public/version.h>
#include <xen/event.h>
#include <asm/apic.h>
#include <public/io/console.h>

static int in_vixen;
static uint8_t global_si_data[4 << 10] __attribute__((aligned(4096)));
static shared_info_t *global_si = (void *)global_si_data;
static bool vixen_per_cpu_notifications = true;
static uint8_t vixen_evtchn_vector;
static bool vixen_needs_apic_ack = true;
struct irqaction vixen_irqaction;
static volatile struct xencons_interface *vixen_xencons_iface;
static uint16_t vixen_xencons_port;
static spinlock_t vixen_xencons_lock;

void __init init_vixen(void)
{
    int major, minor, version;

    if ( !xen_guest )
    {
        printk("Disabling Vixen because we are not running under Xen\n");
        in_vixen = -1;
        return;
    }

    version = HYPERVISOR_xen_version(XENVER_version, NULL);
    major = version >> 16;
    minor = version & 0xffff;

    printk("Vixen running under Xen %d.%d\n", major, minor);

    spin_lock_init(&vixen_xencons_lock);

    in_vixen = 1;
}

void __init early_vixen_init(void)
{
    struct xen_add_to_physmap xatp;
    long rc;

    if ( !is_vixen() )
	return;

    /* Setup our own shared info area */
    xatp.domid = DOMID_SELF;
    xatp.idx = 0;
    xatp.space = XENMAPSPACE_shared_info;
    xatp.gpfn = virt_to_mfn(global_si);

    rc = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp);
    if ( rc < 0 )
        printk("Setting shared info page failed: %ld\n", rc);

    memset(&global_si->native.evtchn_mask[0], 0x00,
           sizeof(global_si->native.evtchn_mask));
}

bool is_vixen(void)
{
    return in_vixen > 0;
}

u64 vixen_get_cpu_freq(void)
{
    volatile vcpu_time_info_t *timep = &global_si->native.vcpu_info[0].time;
    vcpu_time_info_t time;
    uint32_t version;
    u64 imm;

    do {
	version = timep->version;
	rmb();
	time = *timep;
    } while ((version & 1) || version != time.version);

    imm = (1000000000ULL << 32) / time.tsc_to_system_mul;

    if (time.tsc_shift < 0) {
	return imm << -time.tsc_shift;
    } else {
	return imm >> time.tsc_shift;
    }
}

/*
 * Make a bitmask (i.e. unsigned long *) of a xen_ulong_t
 * array. Primarily to avoid long lines (hence the terse name).
 */
#define BM(x) (unsigned long *)(x)
/* Find the first set bit in a evtchn mask */
#define EVTCHN_FIRST_BIT(w) find_first_bit(BM(&(w)), BITS_PER_XEN_ULONG)

/*
 * Mask out the i least significant bits of w
 */
#define MASK_LSBS(w, i) (w & ((~((xen_ulong_t)0UL)) << i))

static DEFINE_PER_CPU(unsigned int, current_word_idx);
static DEFINE_PER_CPU(unsigned int, current_bit_idx);

static inline xen_ulong_t active_evtchns(unsigned int cpu,
                                         shared_info_t *sh,
                                         unsigned int idx)
{
    return sh->native.evtchn_pending[idx] &
           ~sh->native.evtchn_mask[idx];
}

static void vixen_evtchn_poll_one(size_t cpu)
{
    shared_info_t *s = global_si;
    struct vcpu_info *vcpu_info = &s->native.vcpu_info[cpu];
    xen_ulong_t pending_words;
    xen_ulong_t pending_bits;
    int start_word_idx, start_bit_idx;
    int word_idx, bit_idx, i;

    /*
     * Master flag must be cleared /before/ clearing
     * selector flag. xchg_xen_ulong must contain an
     * appropriate barrier.
     */
    pending_words = xchg(&vcpu_info->evtchn_pending_sel, 0);

    start_word_idx = this_cpu(current_word_idx);
    start_bit_idx = this_cpu(current_bit_idx);

    word_idx = start_word_idx;

    for (i = 0; pending_words != 0; i++) {
        xen_ulong_t words;

        words = MASK_LSBS(pending_words, word_idx);

        /*
         * If we masked out all events, wrap to beginning.
         */
        if (words == 0) {
            word_idx = 0;
            bit_idx = 0;
            continue;
        }
        word_idx = EVTCHN_FIRST_BIT(words);

        pending_bits = active_evtchns(cpu, s, word_idx);
        bit_idx = 0; /* usually scan entire word from start */
        /*
         * We scan the starting word in two parts.
         *
         * 1st time: start in the middle, scanning the
         * upper bits.
         *
         * 2nd time: scan the whole word (not just the
         * parts skipped in the first pass) -- if an
         * event in the previously scanned bits is
         * pending again it would just be scanned on
         * the next loop anyway.
         */
        if (word_idx == start_word_idx) {
            if (i == 0)
                bit_idx = start_bit_idx;
        }

        do {
            struct evtchn *chn;
            xen_ulong_t bits;
            int port;

            bits = MASK_LSBS(pending_bits, bit_idx);

            /* If we masked out all events, move on. */
            if (bits == 0)
                break;

            bit_idx = EVTCHN_FIRST_BIT(bits);

            /* Process port. */
            port = (word_idx * BITS_PER_XEN_ULONG) + bit_idx;

            chn = evtchn_from_port(hardware_domain, port);
            clear_bit(port, s->native.evtchn_pending);
            evtchn_port_set_pending(hardware_domain, chn->notify_vcpu_id, chn);

            bit_idx = (bit_idx + 1) % BITS_PER_XEN_ULONG;

            /* Next caller starts at last processed + 1 */
            this_cpu(current_word_idx) = bit_idx ? word_idx : (word_idx+1) % BITS_PER_XEN_ULONG;
            this_cpu(current_bit_idx) = bit_idx;
        } while (bit_idx != 0);

        /* Scan start_l1i twice; all others once. */
        if ((word_idx != start_word_idx) || (i != 0))
            pending_words &= ~(1UL << word_idx);

        word_idx = (word_idx + 1) % BITS_PER_XEN_ULONG;
    }
}

static void vixen_upcall(int cpu)
{
    shared_info_t *s = global_si;
    struct vcpu_info *vcpu_info = &s->native.vcpu_info[cpu];

    do {
        vcpu_info->evtchn_upcall_pending = 0;
        vixen_evtchn_poll_one(cpu);
    } while (vcpu_info->evtchn_upcall_pending);
}

static void vixen_evtchn_notify(struct cpu_user_regs *regs)
{
    if (vixen_needs_apic_ack)
        ack_APIC_irq();

    vixen_upcall(smp_processor_id());
}

static void vixen_interrupt(int irq, void *dev_id, struct cpu_user_regs *regs)
{
    vixen_upcall(smp_processor_id());
}

bool vixen_ring_process(uint16_t port)
{
    volatile struct xencons_interface *r = vixen_xencons_iface;
    char buffer[128];
    size_t n;

    if (r == NULL || port != vixen_xencons_port) {
        return false;
    }

    spin_lock(&vixen_xencons_lock);

    n = 0;
    while (r->out_prod != r->out_cons) {
        char ch = r->out[MASK_XENCONS_IDX(r->out_cons, r->out)];
        if (n == sizeof(buffer) - 1) {
            buffer[n] = 0;
            guest_puts(hardware_domain, buffer);
            n = 0;
        }
        buffer[n++] = ch;
        rmb();
        r->out_cons++;
    }

    if (n) {
        buffer[n] = 0;
        guest_puts(hardware_domain, buffer);
    }

    spin_unlock(&vixen_xencons_lock);

    return true;
}

static int hvm_get_parameter(int idx, uint64_t *value)
{
    struct xen_hvm_param xhv;
    int r;

    xhv.domid = DOMID_SELF;
    xhv.index = idx;
    r = HYPERVISOR_hvm_op(HVMOP_get_param, &xhv);
    if (r < 0) {
        printk("Cannot get hvm parameter %d: %d!\n",
               idx, r);
        return r;
    }
    *value = xhv.value;
    return r;
}

static int hvm_set_parameter(int idx, uint64_t value)
{
    struct xen_hvm_param xhv;
    int r;

    xhv.domid = DOMID_SELF;
    xhv.index = idx;
    xhv.value = value;
    r = HYPERVISOR_hvm_op(HVMOP_set_param, &xhv);
    if (r < 0) {
        printk("Cannot set hvm parameter %d: %d!\n",
               idx, r);
        return r;
    }
    return r;
}

void vixen_vcpu_initialize(struct vcpu *v)
{
    struct xen_hvm_evtchn_upcall_vector upcall;
    long rc;

    printk("VIXEN vcpu init VCPU%d\n", v->vcpu_id);

    vcpu_pin_override(v, v->vcpu_id);

    if (!vixen_needs_apic_ack)
        return;

    printk("VIXEN vcpu init VCPU%d -- trying evtchn_upcall_vector\n", v->vcpu_id);

    upcall.vcpu = v->vcpu_id;
    upcall.vector = vixen_evtchn_vector;
    rc = HYPERVISOR_hvm_op(HVMOP_set_evtchn_upcall_vector, &upcall);
    if ( rc )
    {
        struct xen_feature_info fi;

        printk("VIXEN vcpu init VCPU%d -- trying hvm_callback_vector\n", v->vcpu_id);

        fi.submap_idx = 0;
        rc = HYPERVISOR_xen_version(XENVER_get_features, &fi);
        if ( !rc )
        {
            rc = -EINVAL;
            if ( fi.submap & (1 << XENFEAT_hvm_callback_vector) )
            {
                rc = hvm_set_parameter(HVM_PARAM_CALLBACK_IRQ,
                                       ((uint64_t)HVM_PARAM_CALLBACK_TYPE_VECTOR << 56) | vixen_evtchn_vector);
            }
            if ( !rc )
                vixen_needs_apic_ack = false;
        }
    } else {
        /*
         * XXX Upcall vector setup succeeded. Trick xl to think the guest is
         * enlightened!
         */
        if ( hvm_set_parameter(HVM_PARAM_CALLBACK_IRQ, -1) )
            printk("Setting dummy value for callback_via didn't work\n");
    }

    if ( rc )
    {
        int slot;

        vixen_per_cpu_notifications = false;

        printk("VIXEN vcpu init VCPU%d -- trying pci_intx_callback\n", v->vcpu_id);
        for (slot = 2; slot < 32; slot++) {
            uint16_t vendor, device;

            vendor = pci_conf_read16(0, 0, slot, 0, PCI_VENDOR_ID);
            device = pci_conf_read16(0, 0, slot, 0, PCI_DEVICE_ID);

            if (vendor == 0x5853 && device == 0x0001) {
                break;
            }
        }

        if (slot != 32) {
            int pin, line;

            printk("Found Xen platform device at 0000:00:%02d.0\n", slot);
            pin = pci_conf_read8(0, 0, slot, 0, PCI_INTERRUPT_PIN);
            if (pin) {
                line = pci_conf_read8(0, 0, slot, 0, PCI_INTERRUPT_LINE);
                rc = hvm_set_parameter(HVM_PARAM_CALLBACK_IRQ,
                                       (1ULL << 56) | (slot << 11) | (pin - 1));

                if (rc) {
                    printk("Failed to setup IRQ callback\n");
                } else {
                    vixen_irqaction.handler = vixen_interrupt;
                    vixen_irqaction.name = "vixen";
                    vixen_irqaction.dev_id = 0;
                    rc = setup_irq(line, 0, &vixen_irqaction);
                    if (rc) {
                        printk("Setup IRQ failed!\n");
                    } else {
                        printk("Xen platform LNK mapped to line %d\n", line);
                        vixen_needs_apic_ack = false;
                    }
                }
            }
        } else {
            printk("Cannot find Platform device\n");
        }
    }
}

bool vixen_has_per_cpu_notifications(void)
{
    return vixen_per_cpu_notifications;
}

void __init
vixen_transform(struct domain *dom0,
                xen_pfn_t *pstore_mfn, uint32_t *pstore_evtchn,
                xen_pfn_t *pconsole_mfn, uint32_t *pconsole_evtchn)
{
    uint64_t v = 0;
    long rc;
    struct evtchn_unmask unmask;
    struct evtchn_alloc_unbound alloc;

    /* Setup Xenstore */
    hvm_get_parameter(HVM_PARAM_STORE_EVTCHN, &v);
    *pstore_evtchn = unmask.port = v;
    HYPERVISOR_event_channel_op(EVTCHNOP_unmask, &unmask);

    hvm_get_parameter(HVM_PARAM_STORE_PFN, &v);
    *pstore_mfn = v;

    printk("Vixen Xenstore evtchn is %d, pfn is 0x%" PRIx64 "\n",
           *pstore_evtchn, *pstore_mfn);

    /* Setup Xencons */
    alloc.dom = DOMID_SELF;
    alloc.remote_dom = DOMID_SELF;

    rc = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &alloc);
    if ( rc )
    {
        printk("Failed to alloc unbound event channel: %ld\n", rc);
        *pconsole_evtchn = 0;
        *pconsole_mfn = 0;
    }
    else
    {
        void *console_data;

        console_data = alloc_xenheap_page();

        *pconsole_evtchn = alloc.port;
        *pconsole_mfn = virt_to_mfn(console_data);

        memset(console_data, 0, 4096);
        vixen_xencons_iface = console_data;
        vixen_xencons_port = alloc.port;
    }

    printk("Vixen Xencons evtchn is %d, pfn is 0x%" PRIx64 "\n",
           *pconsole_evtchn, *pconsole_mfn);

    /* Setup event channel forwarding */
    alloc_direct_apic_vector(&vixen_evtchn_vector, vixen_evtchn_notify);
    printk("Vixen evtchn vector is %d\n", vixen_evtchn_vector);

    /* Initialize the first vCPU */
    vixen_vcpu_initialize(dom0->vcpu[0]);
}
