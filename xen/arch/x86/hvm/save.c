/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * hvm/save.c: Save and restore HVM guest's emulated hardware state.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2007, XenSource Inc.
 * Copyright (c) 2007, Isaku Yamahata <yamahata at valinux co jp>
 *                     VA Linux Systems Japan K.K.
 *                     split x86 specific part
 */

#include <xen/guest_access.h>
#include <xen/softirq.h>
#include <xen/version.h>

#include <public/hvm/save.h>

static void arch_hvm_save(struct domain *d, struct hvm_save_header *hdr)
{
    uint32_t eax, ebx, ecx, edx;

    /* Save some CPUID bits */
    cpuid(1, &eax, &ebx, &ecx, &edx);
    hdr->cpuid = eax;

    /* Save guest's preferred TSC. */
    hdr->gtsc_khz = d->arch.tsc_khz;

    /* Time when saving started */
    d->arch.hvm.sync_tsc = rdtsc();
}

static int arch_hvm_check(const struct domain *d,
                          const struct hvm_save_header *hdr)
{
    uint32_t eax, ebx, ecx, edx;

    if ( hdr->magic != HVM_FILE_MAGIC )
    {
        printk(XENLOG_G_ERR "HVM%d restore: bad magic number %#"PRIx32"\n",
               d->domain_id, hdr->magic);
        return -EINVAL;
    }

    if ( hdr->version != HVM_FILE_VERSION )
    {
        printk(XENLOG_G_ERR "HVM%d restore: unsupported version %u\n",
               d->domain_id, hdr->version);
        return -EINVAL;
    }

    cpuid(1, &eax, &ebx, &ecx, &edx);
    /* CPUs ought to match but with feature-masking they might not */
    if ( (hdr->cpuid & ~0x0fUL) != (eax & ~0x0fUL) )
        printk(XENLOG_G_INFO "HVM%d restore: VM saved on one CPU "
               "(%#"PRIx32") and restored on another (%#"PRIx32").\n",
               d->domain_id, hdr->cpuid, eax);

    return 0;
}

static void arch_hvm_load(struct domain *d, const struct hvm_save_header *hdr)
{
    /* Restore guest's preferred TSC frequency. */
    if ( hdr->gtsc_khz )
        d->arch.tsc_khz = hdr->gtsc_khz;
    if ( d->arch.vtsc )
        hvm_set_rdtsc_exiting(d, 1);

    /* Time when restore started  */
    d->arch.hvm.sync_tsc = rdtsc();
}

/* List of handlers for various HVM save and restore types */
static struct {
    hvm_save_handler save;
    hvm_check_handler check;
    hvm_load_handler load;
    const char *name;
    size_t size;
    int kind;
} hvm_sr_handlers[HVM_SAVE_CODE_MAX + 1];

/* Init-time function to add entries to that list */
void __init hvm_register_savevm(uint16_t typecode,
                                const char *name,
                                hvm_save_handler save_state,
                                hvm_check_handler check_state,
                                hvm_load_handler load_state,
                                size_t size, int kind)
{
    ASSERT(typecode <= HVM_SAVE_CODE_MAX);
    ASSERT(hvm_sr_handlers[typecode].save == NULL);
    ASSERT(hvm_sr_handlers[typecode].check == NULL);
    ASSERT(hvm_sr_handlers[typecode].load == NULL);
    hvm_sr_handlers[typecode].save = save_state;
    hvm_sr_handlers[typecode].check = check_state;
    hvm_sr_handlers[typecode].load = load_state;
    hvm_sr_handlers[typecode].name = name;
    hvm_sr_handlers[typecode].size = size;
    hvm_sr_handlers[typecode].kind = kind;
}

size_t hvm_save_size(struct domain *d)
{
    struct vcpu *v;
    size_t sz;
    int i;

    /* Basic overhead for header and footer */
    sz = (2 * sizeof (struct hvm_save_descriptor)) + HVM_SAVE_LENGTH(HEADER);

    /* Plus space for each thing we will be saving */
    for ( i = 0; i <= HVM_SAVE_CODE_MAX; i++ )
        if ( hvm_sr_handlers[i].kind == HVMSR_PER_VCPU )
            for_each_vcpu(d, v)
                sz += hvm_sr_handlers[i].size;
        else
            sz += hvm_sr_handlers[i].size;

    return sz;
}

/*
 * Extract a single instance of a save record, by marshalling all records of
 * that type and copying out the one we need.
 */
int hvm_save_one(struct domain *d, unsigned int typecode, unsigned int instance,
                 XEN_GUEST_HANDLE_64(uint8) handle, uint64_t *bufsz)
{
    int rv;
    hvm_domain_context_t ctxt = { };
    const struct hvm_save_descriptor *desc;
    struct vcpu *v;

    if ( d->is_dying ||
         typecode > HVM_SAVE_CODE_MAX ||
         hvm_sr_handlers[typecode].size < sizeof(*desc) ||
         !hvm_sr_handlers[typecode].save )
        return -EINVAL;

    if ( hvm_sr_handlers[typecode].kind != HVMSR_PER_VCPU )
        v = d->vcpu[0];
    else if ( instance >= d->max_vcpus || !d->vcpu[instance] )
        return -ENOENT;
    else
        v = d->vcpu[instance];
    ctxt.size = hvm_sr_handlers[typecode].size;
    ctxt.data = xmalloc_bytes(ctxt.size);
    if ( !ctxt.data )
        return -ENOMEM;

    if ( hvm_sr_handlers[typecode].kind == HVMSR_PER_VCPU )
        vcpu_pause(v);
    else
        domain_pause(d);

    if ( (rv = hvm_sr_handlers[typecode].save(v, &ctxt)) != 0 )
        printk(XENLOG_G_ERR "HVM%d save: failed to save type %"PRIu16" (%d)\n",
               d->domain_id, typecode, rv);
    else if ( (rv = hvm_sr_handlers[typecode].kind == HVMSR_PER_VCPU ?
               -ENODATA : -ENOENT), ctxt.cur >= sizeof(*desc) )
    {
        uint32_t off;

        for ( off = 0; off <= (ctxt.cur - sizeof(*desc)); off += desc->length )
        {
            desc = (void *)(ctxt.data + off);
            /* Move past header */
            off += sizeof(*desc);
            if ( ctxt.cur < desc->length ||
                 off > ctxt.cur - desc->length )
                break;
            if ( instance == desc->instance )
            {
                rv = 0;
                if ( guest_handle_is_null(handle) )
                    *bufsz = desc->length;
                else if ( *bufsz < desc->length )
                    rv = -ENOBUFS;
                else if ( copy_to_guest(handle, ctxt.data + off, desc->length) )
                    rv = -EFAULT;
                else
                    *bufsz = desc->length;
                break;
            }
        }
    }

    if ( hvm_sr_handlers[typecode].kind == HVMSR_PER_VCPU )
        vcpu_unpause(v);
    else
        domain_unpause(d);

    xfree(ctxt.data);
    return rv;
}

int hvm_save(struct domain *d, hvm_domain_context_t *h)
{
    char *c;
    struct hvm_save_header hdr;
    struct hvm_save_end end;
    unsigned int i;

    if ( d->is_dying )
        return -EINVAL;

    hdr.magic = HVM_FILE_MAGIC;
    hdr.version = HVM_FILE_VERSION;

    /* Save xen changeset */
    c = strrchr(xen_changeset(), ':');
    if ( c )
        hdr.changeset = simple_strtoll(c, NULL, 16);
    else
        hdr.changeset = -1ULL; /* Unknown */

    arch_hvm_save(d, &hdr);

    if ( hvm_save_entry(HEADER, 0, h, &hdr) != 0 )
    {
        printk(XENLOG_G_ERR "HVM%d save: failed to write header\n",
               d->domain_id);
        return -EFAULT;
    }

    /* Save all available kinds of state */
    for ( i = 0; i <= HVM_SAVE_CODE_MAX; i++ )
    {
        hvm_save_handler handler = hvm_sr_handlers[i].save;

        if ( !handler )
            continue;

        if ( hvm_sr_handlers[i].kind == HVMSR_PER_VCPU )
        {
            struct vcpu *v;

            for_each_vcpu ( d, v )
            {
                printk(XENLOG_G_INFO "HVM %pv save: %s\n",
                       v, hvm_sr_handlers[i].name);
                if ( handler(v, h) != 0 )
                {
                    printk(XENLOG_G_ERR
                           "HVM %pv save: failed to save type %"PRIu16"\n",
                           v, i);
                    return -ENODATA;
                }
                process_pending_softirqs();
            }
        }
        else
        {
            printk(XENLOG_G_INFO "HVM d%d save: %s\n",
                   d->domain_id, hvm_sr_handlers[i].name);
            if ( handler(d->vcpu[0], h) != 0 )
            {
                printk(XENLOG_G_ERR
                       "HVM d%d save: failed to save type %"PRIu16"\n",
                       d->domain_id, i);
                return -ENODATA;
            }
            process_pending_softirqs();
        }
    }

    /* Save an end-of-file marker */
    if ( hvm_save_entry(END, 0, h, &end) != 0 )
    {
        /* Run out of data */
        printk(XENLOG_G_ERR "HVM%d save: no room for end marker\n",
               d->domain_id);
        return -EFAULT;
    }

    /* Save macros should not have let us overrun */
    ASSERT(h->cur <= h->size);
    return 0;
}

/*
 * @real = false requests checking of the incoming state, while @real = true
 * requests actual loading, which will then assume that checking was already
 * done or is unnecessary.
 */
int hvm_load(struct domain *d, bool real, hvm_domain_context_t *h)
{
    const struct hvm_save_header *hdr;
    struct hvm_save_descriptor *desc;
    int rc;

    if ( d->is_dying )
        return -EINVAL;

    /* Get at the save header, which must be first */
    hdr = hvm_get_entry(HEADER, h);
    if ( !hdr )
        return -ENODATA;

    rc = arch_hvm_check(d, hdr);
    if ( real )
    {
        struct vcpu *v;

        ASSERT(!rc);

        /*
         * Down all the vcpus: we only re-enable the ones that had state
         * saved.
         */
        for_each_vcpu(d, v)
            if ( !test_and_set_bit(_VPF_down, &v->pause_flags) )
                vcpu_sleep_nosync(v);

        arch_hvm_load(d, hdr);
    }
    else if ( rc )
        return rc;

    for ( ; ; )
    {
        const char *name;
        hvm_load_handler load;

        if ( h->size - h->cur < sizeof(struct hvm_save_descriptor) )
        {
            /* Run out of data */
            printk(XENLOG_G_ERR
                   "HVM%d restore: save did not end with a null entry\n",
                   d->domain_id);
            ASSERT(!real);
            return -ENODATA;
        }

        /* Read the typecode of the next entry  and check for the end-marker */
        desc = (struct hvm_save_descriptor *)(&h->data[h->cur]);
        if ( desc->typecode == HVM_SAVE_CODE(END) )
        {
            /* Reset cursor for hvm_load(, true, ). */
            if ( !real )
                h->cur = 0;
            return 0;
        }

        /* Find the handler for this entry */
        if ( desc->typecode >= ARRAY_SIZE(hvm_sr_handlers) ||
             !(name = hvm_sr_handlers[desc->typecode].name) ||
             !(load = hvm_sr_handlers[desc->typecode].load) )
        {
            printk(XENLOG_G_ERR "HVM%d restore: unknown entry typecode %u\n",
                   d->domain_id, desc->typecode);
            ASSERT(!real);
            return -EINVAL;
        }

        if ( real )
        {
            /* Load the entry */
            printk(XENLOG_G_INFO "HVM restore %pd: %s %"PRIu16"\n", d,
                   name, desc->instance);
            rc = load(d, h);
        }
        else
        {
            /* Check the entry. */
            hvm_check_handler check = hvm_sr_handlers[desc->typecode].check;

            if ( !check )
            {
                if ( desc->length > h->size - h->cur - sizeof(*desc) )
                    return -ENODATA;
                h->cur += sizeof(*desc) + desc->length;
                rc = 0;
            }
            else
                rc = check(d, h);
        }

        if ( rc )
        {
            printk(XENLOG_G_ERR "HVM restore %pd: failed to %s %s:%u rc %d\n",
                   d, real ? "load" : "check", name, desc->instance, rc);
            return rc;
        }

        process_pending_softirqs();
    }

    /* Not reached */
}

int _hvm_init_entry(struct hvm_domain_context *h, uint16_t tc, uint16_t inst,
                    uint32_t len)
{
    struct hvm_save_descriptor *d
        = (struct hvm_save_descriptor *)&h->data[h->cur];

    if ( h->size - h->cur < len + sizeof (*d) )
    {
        printk(XENLOG_G_WARNING "HVM save: no room for"
               " %"PRIu32" + %zu bytes for typecode %"PRIu16"\n",
               len, sizeof(*d), tc);
        return -1;
    }

    d->typecode = tc;
    d->instance = inst;
    d->length = len;
    h->cur += sizeof(*d);

    return 0;
}

void _hvm_write_entry(struct hvm_domain_context *h, void *src,
                      uint32_t src_len)
{
    memcpy(&h->data[h->cur], src, src_len);
    h->cur += src_len;
}

int _hvm_check_entry(struct hvm_domain_context *h, uint16_t type, uint32_t len,
                     bool strict_length)
{
    struct hvm_save_descriptor *d
        = (struct hvm_save_descriptor *)&h->data[h->cur];

    if ( sizeof(*d) > h->size - h->cur)
    {
        printk(XENLOG_G_WARNING
               "HVM restore: not enough data left to read %zu bytes "
               "for type %u header\n", sizeof(*d), type);
        return -1;
    }

    if ( (type != d->typecode) ||
         (strict_length ? (len != d->length) : (len < d->length)) ||
         (d->length > (h->size - h->cur - sizeof(*d))) )
    {
        printk(XENLOG_G_WARNING
               "HVM restore mismatch: expected %s type %u length %u, "
               "saw type %u length %u.  %zu bytes remaining\n",
               strict_length ? "strict" : "zeroextended", type, len,
               d->typecode, d->length, h->size - h->cur - sizeof(*d));
        return -1;
    }

    h->cur += sizeof(*d);

    return 0;
}

void _hvm_read_entry(struct hvm_domain_context *h, void *dest,
                     uint32_t dest_len)
{
    struct hvm_save_descriptor *d
        = (struct hvm_save_descriptor *)&h->data[h->cur - sizeof(*d)];

    BUG_ON(d->length > dest_len);

    memcpy(dest, &h->data[h->cur], d->length);

    if ( d->length < dest_len )
        memset(dest + d->length, 0, dest_len - d->length);

    h->cur += d->length;
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
