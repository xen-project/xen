/******************************************************************************
 * platform_hypercall.c
 * 
 * Hardware platform operations. Intended for use by domain-0 kernel.
 * 
 * Copyright (c) 2002-2006, K Fraser
 */

#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
#include <xen/acpi.h>
#include <xen/efi.h>
#include <xen/cpu.h>
#include <xen/pmstat.h>
#include <xen/irq.h>
#include <xen/symbols.h>
#include <asm/current.h>
#include <public/platform.h>
#include <acpi/cpufreq/processor_perf.h>
#include <asm/edd.h>
#include <asm/mtrr.h>
#include <asm/io_apic.h>
#include <asm/setup.h>
#include "cpu/mtrr/mtrr.h"
#include <xsm/xsm.h>

/* Declarations for items shared with the compat mode handler. */
extern spinlock_t xenpf_lock;

#define RESOURCE_ACCESS_MAX_ENTRIES 3
struct resource_access {
    unsigned int nr_done;
    unsigned int nr_entries;
    xenpf_resource_entry_t *entries;
};

long cpu_frequency_change_helper(void *);
void check_resource_access(struct resource_access *);
void resource_access(void *);

#ifndef COMPAT
typedef long ret_t;
DEFINE_SPINLOCK(xenpf_lock);
# undef copy_from_compat
# define copy_from_compat copy_from_guest
# undef copy_to_compat
# define copy_to_compat copy_to_guest
# undef guest_from_compat_handle
# define guest_from_compat_handle(x,y) ((x)=(y))

long cpu_frequency_change_helper(void *data)
{
    return cpu_frequency_change((uint64_t)data);
}

static bool allow_access_msr(unsigned int msr)
{
    switch ( msr )
    {
    /* MSR for CMT, refer to chapter 17.14 of Intel SDM. */
    case MSR_IA32_CMT_EVTSEL:
    case MSR_IA32_CMT_CTR:
    case MSR_IA32_TSC:
        return true;
    }

    return false;
}

void check_resource_access(struct resource_access *ra)
{
    unsigned int i;

    for ( i = 0; i < ra->nr_entries; i++ )
    {
        int ret = 0;
        xenpf_resource_entry_t *entry = ra->entries + i;

        if ( entry->rsvd )
        {
            entry->u.ret = -EINVAL;
            break;
        }

        switch ( entry->u.cmd )
        {
        case XEN_RESOURCE_OP_MSR_READ:
        case XEN_RESOURCE_OP_MSR_WRITE:
            if ( entry->idx >> 32 )
                ret = -EINVAL;
            else if ( !allow_access_msr(entry->idx) )
                ret = -EACCES;
            break;
        default:
            ret = -EOPNOTSUPP;
            break;
        }

        if ( ret )
        {
           entry->u.ret = ret;
           break;
        }
    }

    ra->nr_done = i;
}

void resource_access(void *info)
{
    struct resource_access *ra = info;
    unsigned int i;
    u64 tsc = 0;

    for ( i = 0; i < ra->nr_done; i++ )
    {
        int ret;
        xenpf_resource_entry_t *entry = ra->entries + i;

        switch ( entry->u.cmd )
        {
        case XEN_RESOURCE_OP_MSR_READ:
            if ( unlikely(entry->idx == MSR_IA32_TSC) )
            {
                /* Return obfuscated scaled time instead of raw timestamp */
                entry->val = get_s_time_fixed(tsc)
                             + SECONDS(boot_random) - boot_random;
                ret = 0;
            }
            else
            {
                unsigned long flags = 0;
                /*
                 * If next entry is MSR_IA32_TSC read, then the actual rdtsc
                 * is performed together with current entry, with IRQ disabled.
                 */
                bool read_tsc = i < ra->nr_done - 1 &&
                                unlikely(entry[1].idx == MSR_IA32_TSC);

                if ( unlikely(read_tsc) )
                    local_irq_save(flags);

                ret = rdmsr_safe(entry->idx, entry->val);

                if ( unlikely(read_tsc) )
                {
                    tsc = rdtsc();
                    local_irq_restore(flags);
                }
            }
            break;
        case XEN_RESOURCE_OP_MSR_WRITE:
            if ( unlikely(entry->idx == MSR_IA32_TSC) )
                ret = -EPERM;
            else
                ret = wrmsr_safe(entry->idx, entry->val);
            break;
        default:
            BUG();
            break;
        }

        if ( ret )
        {
            entry->u.ret = ret;
            break;
        }
    }

    ra->nr_done = i;
}
#endif

ret_t do_platform_op(XEN_GUEST_HANDLE_PARAM(xen_platform_op_t) u_xenpf_op)
{
    ret_t ret;
    struct xen_platform_op curop, *op = &curop;

    if ( copy_from_guest(op, u_xenpf_op, 1) )
        return -EFAULT;

    if ( op->interface_version != XENPF_INTERFACE_VERSION )
        return -EACCES;

    ret = xsm_platform_op(XSM_PRIV, op->cmd);
    if ( ret )
        return ret;

    /*
     * Trylock here avoids deadlock with an existing platform critical section
     * which might (for some current or future reason) want to synchronise
     * with this vcpu.
     */
    while ( !spin_trylock(&xenpf_lock) )
        if ( hypercall_preempt_check() )
            return hypercall_create_continuation(
                __HYPERVISOR_platform_op, "h", u_xenpf_op);

    switch ( op->cmd )
    {
    case XENPF_settime32:
        do_settime(op->u.settime32.secs,
                   op->u.settime32.nsecs,
                   op->u.settime32.system_time);
        break;

    case XENPF_settime64:
        if ( likely(!op->u.settime64.mbz) )
            do_settime(op->u.settime64.secs,
                       op->u.settime64.nsecs,
                       op->u.settime64.system_time);
        else
            ret = -EINVAL;
        break;

    case XENPF_add_memtype:
    {
        ret = mtrr_add_page(
            op->u.add_memtype.mfn,
            op->u.add_memtype.nr_mfns,
            op->u.add_memtype.type,
            1);
        if ( ret >= 0 )
        {
            op->u.add_memtype.handle = 0;
            op->u.add_memtype.reg    = ret;
            ret = __copy_field_to_guest(u_xenpf_op, op, u.add_memtype) ?
                  -EFAULT : 0;
            if ( ret != 0 )
                mtrr_del_page(ret, 0, 0);
        }
    }
    break;

    case XENPF_del_memtype:
    {
        if (op->u.del_memtype.handle == 0
            /* mtrr/main.c otherwise does a lookup */
            && (int)op->u.del_memtype.reg >= 0)
        {
            ret = mtrr_del_page(op->u.del_memtype.reg, 0, 0);
            if ( ret > 0 )
                ret = 0;
        }
        else
            ret = -EINVAL;
    }
    break;

    case XENPF_read_memtype:
    {
        unsigned long mfn, nr_mfns;
        mtrr_type     type;

        ret = -EINVAL;
        if ( op->u.read_memtype.reg < num_var_ranges )
        {
            mtrr_if->get(op->u.read_memtype.reg, &mfn, &nr_mfns, &type);
            op->u.read_memtype.mfn     = mfn;
            op->u.read_memtype.nr_mfns = nr_mfns;
            op->u.read_memtype.type    = type;
            ret = __copy_field_to_guest(u_xenpf_op, op, u.read_memtype)
                  ? -EFAULT : 0;
        }
    }
    break;

    case XENPF_microcode_update:
    {
        XEN_GUEST_HANDLE(const_void) data;

        guest_from_compat_handle(data, op->u.microcode.data);

        /*
         * alloc_vcpu() will access data which is modified during
         * microcode update
         */
        while ( !spin_trylock(&vcpu_alloc_lock) )
        {
            if ( hypercall_preempt_check() )
            {
                ret = hypercall_create_continuation(
                    __HYPERVISOR_platform_op, "h", u_xenpf_op);
                goto out;
            }
        }

        ret = microcode_update(
                guest_handle_to_param(data, const_void),
                op->u.microcode.length);
        spin_unlock(&vcpu_alloc_lock);
    }
    break;

    case XENPF_platform_quirk:
    {
        int quirk_id = op->u.platform_quirk.quirk_id;

        switch ( quirk_id )
        {
        case QUIRK_NOIRQBALANCING:
            printk("Platform quirk -- Disabling IRQ balancing/affinity.\n");
            opt_noirqbalance = 1;
            setup_ioapic_dest();
            break;
        case QUIRK_IOAPIC_BAD_REGSEL:
            dprintk(XENLOG_WARNING,
                    "Domain 0 thinks that IO-APIC REGSEL is bad\n");
            break;
        case QUIRK_IOAPIC_GOOD_REGSEL:
            break;
        default:
            ret = -EINVAL;
            break;
        }
    }
    break;

    case XENPF_firmware_info:
        switch ( op->u.firmware_info.type )
        {
        case XEN_FW_DISK_INFO: {
            const struct edd_info *info;
            u16 length;

            ret = -ESRCH;
            if ( op->u.firmware_info.index >= bootsym(boot_edd_info_nr) )
                break;

            info = bootsym(boot_edd_info) + op->u.firmware_info.index;

            /* Transfer the EDD info block. */
            ret = -EFAULT;
            if ( copy_from_compat(&length, op->u.firmware_info.u.
                                  disk_info.edd_params, 1) )
                break;
            if ( length > info->edd_device_params.length )
                length = info->edd_device_params.length;
            if ( copy_to_compat(op->u.firmware_info.u.disk_info.edd_params,
                                (u8 *)&info->edd_device_params,
                                length) )
                break;
            if ( copy_to_compat(op->u.firmware_info.u.disk_info.edd_params,
                                &length, 1) )
                break;

            /* Transfer miscellaneous other information values. */
#define C(x) op->u.firmware_info.u.disk_info.x = info->x
            C(device);
            C(version);
            C(interface_support);
            C(legacy_max_cylinder);
            C(legacy_max_head);
            C(legacy_sectors_per_track);
#undef C

            ret = (__copy_field_to_guest(u_xenpf_op, op,
                                         u.firmware_info.u.disk_info)
                   ? -EFAULT : 0);
            break;
        }
        case XEN_FW_DISK_MBR_SIGNATURE: {
            const struct mbr_signature *sig;

            ret = -ESRCH;
            if ( op->u.firmware_info.index >= bootsym(boot_mbr_signature_nr) )
                break;

            sig = bootsym(boot_mbr_signature) + op->u.firmware_info.index;

            op->u.firmware_info.u.disk_mbr_signature.device = sig->device;
            op->u.firmware_info.u.disk_mbr_signature.mbr_signature =
                sig->signature;

            ret = (__copy_field_to_guest(u_xenpf_op, op,
                                         u.firmware_info.u.disk_mbr_signature)
                   ? -EFAULT : 0);
            break;
        }
        case XEN_FW_VBEDDC_INFO:
            ret = -ESRCH;
#ifdef CONFIG_VIDEO
            if ( op->u.firmware_info.index != 0 )
                break;
            if ( *(u32 *)bootsym(boot_edid_info) == 0x13131313 )
                break;

            op->u.firmware_info.u.vbeddc_info.capabilities =
                bootsym(boot_edid_caps);
            op->u.firmware_info.u.vbeddc_info.edid_transfer_time =
                bootsym(boot_edid_caps) >> 8;

            ret = 0;
            if ( __copy_field_to_guest(u_xenpf_op, op, u.firmware_info.
                                       u.vbeddc_info.capabilities) ||
                 __copy_field_to_guest(u_xenpf_op, op, u.firmware_info.
                                       u.vbeddc_info.edid_transfer_time) ||
                 copy_to_compat(op->u.firmware_info.u.vbeddc_info.edid,
                                bootsym(boot_edid_info), 128) )
                ret = -EFAULT;
#endif
            break;
        case XEN_FW_EFI_INFO:
            ret = efi_get_info(op->u.firmware_info.index,
                               &op->u.firmware_info.u.efi_info);
            if ( ret == 0 &&
                 __copy_field_to_guest(u_xenpf_op, op,
                                       u.firmware_info.u.efi_info) )
                ret = -EFAULT;
            break;
        case XEN_FW_KBD_SHIFT_FLAGS:
            ret = -ESRCH;
            if ( op->u.firmware_info.index != 0 )
                break;

            op->u.firmware_info.u.kbd_shift_flags = bootsym(kbd_shift_flags);

            ret = 0;
            if ( __copy_field_to_guest(u_xenpf_op, op,
                                       u.firmware_info.u.kbd_shift_flags) )
                ret = -EFAULT;
            break;
        default:
            ret = -EINVAL;
            break;
        }
        break;

    case XENPF_efi_runtime_call:
        ret = efi_runtime_call(&op->u.efi_runtime_call);
        if ( ret == 0 &&
             __copy_field_to_guest(u_xenpf_op, op, u.efi_runtime_call) )
            ret = -EFAULT;
        break;

    case XENPF_enter_acpi_sleep:
        ret = acpi_enter_sleep(&op->u.enter_acpi_sleep);
        break;

    case XENPF_change_freq:
        ret = -ENOSYS;
        if ( cpufreq_controller != FREQCTL_dom0_kernel )
            break;
        ret = -EINVAL;
        if ( op->u.change_freq.flags || !cpu_online(op->u.change_freq.cpu) )
            break;
        ret = continue_hypercall_on_cpu(op->u.change_freq.cpu,
                                        cpu_frequency_change_helper,
                                        (void *)op->u.change_freq.freq);
        break;

    case XENPF_getidletime:
    {
        uint32_t cpu;
        uint64_t idletime, now = NOW();
        struct xenctl_bitmap ctlmap;
        cpumask_var_t cpumap;
        XEN_GUEST_HANDLE(uint8) cpumap_bitmap;
        XEN_GUEST_HANDLE(uint64) idletimes;

        ret = -ENOSYS;
        if ( cpufreq_controller != FREQCTL_dom0_kernel )
            break;

        ctlmap.nr_bits  = op->u.getidletime.cpumap_nr_cpus;
        guest_from_compat_handle(cpumap_bitmap,
                                 op->u.getidletime.cpumap_bitmap);
        ctlmap.bitmap.p = cpumap_bitmap.p; /* handle -> handle_64 conversion */
        if ( (ret = xenctl_bitmap_to_cpumask(&cpumap, &ctlmap)) != 0 )
            goto out;
        guest_from_compat_handle(idletimes, op->u.getidletime.idletime);

        for_each_cpu ( cpu, cpumap )
        {
            idletime = get_cpu_idle_time(cpu);

            if ( !idletime )
            {
                __cpumask_clear_cpu(cpu, cpumap);
                continue;
            }

            if ( copy_to_guest_offset(idletimes, cpu, &idletime, 1) )
            {
                ret = -EFAULT;
                break;
            }
        }

        op->u.getidletime.now = now;
        if ( ret == 0 )
            ret = cpumask_to_xenctl_bitmap(&ctlmap, cpumap);
        free_cpumask_var(cpumap);

        if ( ret == 0 && __copy_field_to_guest(u_xenpf_op, op, u.getidletime) )
            ret = -EFAULT;
    }
    break;

    case XENPF_set_processor_pminfo:
        switch ( op->u.set_pminfo.type )
        {
        case XEN_PM_PX:
            if ( !(xen_processor_pmbits & XEN_PROCESSOR_PM_PX) )
            {
                ret = -ENOSYS;
                break;
            }
            ret = set_px_pminfo(op->u.set_pminfo.id, &op->u.set_pminfo.u.perf);
            break;
 
        case XEN_PM_CX:
            if ( !(xen_processor_pmbits & XEN_PROCESSOR_PM_CX) )
            {
                ret = -ENOSYS;
                break;
            }
            ret = set_cx_pminfo(op->u.set_pminfo.id, &op->u.set_pminfo.u.power);
            break;

        case XEN_PM_TX:
            if ( !(xen_processor_pmbits & XEN_PROCESSOR_PM_TX) )
            {
                ret = -ENOSYS;
                break;
            }
            ret = -EINVAL;
            break;

        case XEN_PM_PDC:
        {
            XEN_GUEST_HANDLE(uint32) pdc;

            guest_from_compat_handle(pdc, op->u.set_pminfo.u.pdc);
            ret = acpi_set_pdc_bits(
                    op->u.set_pminfo.id,
                    guest_handle_to_param(pdc, uint32));
        }
        break;

        default:
            ret = -EINVAL;
            break;
        }
        break;

    case XENPF_get_cpuinfo:
    {
        struct xenpf_pcpuinfo *g_info;

        g_info = &op->u.pcpu_info;

        if ( !get_cpu_maps() )
        {
            ret = -EBUSY;
            break;
        }

        if ( (g_info->xen_cpuid >= nr_cpu_ids) ||
             !cpu_present(g_info->xen_cpuid) )
        {
            g_info->flags = XEN_PCPU_FLAGS_INVALID;
        }
        else
        {
            g_info->apic_id = x86_cpu_to_apicid[g_info->xen_cpuid];
            g_info->acpi_id = acpi_get_processor_id(g_info->xen_cpuid);
            ASSERT(g_info->apic_id != BAD_APICID);
            g_info->flags = 0;
            if (cpu_online(g_info->xen_cpuid))
                g_info->flags |= XEN_PCPU_FLAGS_ONLINE;
        }

        g_info->max_present = cpumask_last(&cpu_present_map);

        put_cpu_maps();

        ret = __copy_field_to_guest(u_xenpf_op, op, u.pcpu_info) ? -EFAULT : 0;
    }
    break;

    case XENPF_get_cpu_version:
    {
        struct xenpf_pcpu_version *ver = &op->u.pcpu_version;

        if ( !get_cpu_maps() )
        {
            ret = -EBUSY;
            break;
        }

        if ( (ver->xen_cpuid >= nr_cpu_ids) || !cpu_online(ver->xen_cpuid) )
        {
            memset(ver->vendor_id, 0, sizeof(ver->vendor_id));
            ver->family = 0;
            ver->model = 0;
            ver->stepping = 0;
        }
        else
        {
            const struct cpuinfo_x86 *c = &cpu_data[ver->xen_cpuid];

            memcpy(ver->vendor_id, c->x86_vendor_id, sizeof(ver->vendor_id));
            ver->family = c->x86;
            ver->model = c->x86_model;
            ver->stepping = c->x86_mask;
        }

        ver->max_present = cpumask_last(&cpu_present_map);

        put_cpu_maps();

        if ( __copy_field_to_guest(u_xenpf_op, op, u.pcpu_version) )
            ret = -EFAULT;
    }
    break;

    case XENPF_cpu_online:
    {
        int cpu = op->u.cpu_ol.cpuid;

        ret = xsm_resource_plug_core(XSM_HOOK);
        if ( ret )
            break;

        if ( cpu >= nr_cpu_ids || !cpu_present(cpu) ||
             clocksource_is_tsc() )
        {
            ret = -EINVAL;
            break;
        }

        if ( cpu_online(cpu) )
        {
            ret = 0;
            break;
        }

        ret = continue_hypercall_on_cpu(
            0, cpu_up_helper, (void *)(unsigned long)cpu);
        break;
    }

    case XENPF_cpu_offline:
    {
        int cpu = op->u.cpu_ol.cpuid;

        ret = xsm_resource_unplug_core(XSM_HOOK);
        if ( ret )
            break;

        if ( cpu == 0 )
        {
            ret = -EOPNOTSUPP;
            break;
        }

        if ( cpu >= nr_cpu_ids || !cpu_present(cpu) )
        {
            ret = -EINVAL;
            break;
        }

        if ( !cpu_online(cpu) )
        {
            ret = 0;
            break;
        }

        ret = continue_hypercall_on_cpu(
            0, cpu_down_helper, (void *)(unsigned long)cpu);
        break;
    }
    break;

    case XENPF_cpu_hotadd:
        ret = xsm_resource_plug_core(XSM_HOOK);
        if ( ret )
            break;

        ret = cpu_add(op->u.cpu_add.apic_id,
                      op->u.cpu_add.acpi_id,
                      op->u.cpu_add.pxm);
    break;

    case XENPF_mem_hotadd:
        ret = xsm_resource_plug_core(XSM_HOOK);
        if ( ret )
            break;

        ret = memory_add(op->u.mem_add.spfn,
                      op->u.mem_add.epfn,
                      op->u.mem_add.pxm);
        break;

    case XENPF_core_parking:
    {
        uint32_t idle_nums;

        switch(op->u.core_parking.type)
        {
        case XEN_CORE_PARKING_SET:
            idle_nums = min_t(uint32_t,
                    op->u.core_parking.idle_nums, num_present_cpus() - 1);
            ret = continue_hypercall_on_cpu(
                    0, core_parking_helper, (void *)(unsigned long)idle_nums);
            break;

        case XEN_CORE_PARKING_GET:
            op->u.core_parking.idle_nums = get_cur_idle_nums();
            ret = __copy_field_to_guest(u_xenpf_op, op, u.core_parking) ?
                  -EFAULT : 0;
            break;

        default:
            ret = -EINVAL;
            break;
        }
    }
    break;

    case XENPF_resource_op:
    {
        struct resource_access ra;
        unsigned int cpu;
        XEN_GUEST_HANDLE(xenpf_resource_entry_t) guest_entries;

        ra.nr_entries = op->u.resource_op.nr_entries;
        if ( ra.nr_entries == 0 )
            break;
        if ( ra.nr_entries > RESOURCE_ACCESS_MAX_ENTRIES )
        {
            ret = -EINVAL;
            break;
        }

        ra.entries = xmalloc_array(xenpf_resource_entry_t, ra.nr_entries);
        if ( !ra.entries )
        {
            ret = -ENOMEM;
            break;
        }

        guest_from_compat_handle(guest_entries, op->u.resource_op.entries);

        if ( copy_from_guest(ra.entries, guest_entries, ra.nr_entries) )
        {
            xfree(ra.entries);
            ret = -EFAULT;
            break;
        }

        /* Do sanity check earlier to omit the potential IPI overhead. */
        check_resource_access(&ra);
        if ( ra.nr_done == 0 )
        {
            /* Copy the return value for entry 0 if it failed. */
            if ( __copy_to_guest(guest_entries, ra.entries, 1) )
                ret = -EFAULT;

            xfree(ra.entries);
            break;
        }

        cpu = op->u.resource_op.cpu;
        if ( (cpu >= nr_cpu_ids) || !cpu_online(cpu) )
        {
            xfree(ra.entries);
            ret = -ENODEV;
            break;
        }
        if ( cpu == smp_processor_id() )
            resource_access(&ra);
        else
            on_selected_cpus(cpumask_of(cpu), resource_access, &ra, 1);

        /* Copy all if succeeded or up to the failed entry. */
        if ( __copy_to_guest(guest_entries, ra.entries,
                             ra.nr_done < ra.nr_entries ? ra.nr_done + 1
                                                        : ra.nr_entries) )
            ret = -EFAULT;
        else
            ret = ra.nr_done;

        xfree(ra.entries);
    }
    break;

    case XENPF_get_symbol:
    {
        static char name[KSYM_NAME_LEN + 1]; /* protected by xenpf_lock */
        XEN_GUEST_HANDLE(char) nameh;
        uint32_t namelen, copylen;
        unsigned long addr;

        guest_from_compat_handle(nameh, op->u.symdata.name);

        ret = xensyms_read(&op->u.symdata.symnum, &op->u.symdata.type,
                           &addr, name);
        op->u.symdata.address = addr;
        namelen = strlen(name) + 1;

        if ( namelen > op->u.symdata.namelen )
            copylen = op->u.symdata.namelen;
        else
            copylen = namelen;

        op->u.symdata.namelen = namelen;

        if ( !ret && copy_to_guest(nameh, name, copylen) )
            ret = -EFAULT;
        if ( !ret && __copy_field_to_guest(u_xenpf_op, op, u.symdata) )
            ret = -EFAULT;
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

 out:
    spin_unlock(&xenpf_lock);

    return ret;
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
