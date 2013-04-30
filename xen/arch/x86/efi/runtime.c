#include "efi.h"
#include <xen/cache.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/irq.h>
#include <xen/time.h>
#include <asm/mc146818rtc.h>

DEFINE_XEN_GUEST_HANDLE(CHAR16);

#ifndef COMPAT

# include <public/platform.h>

const bool_t efi_enabled = 1;

unsigned int __read_mostly efi_num_ct;
EFI_CONFIGURATION_TABLE *__read_mostly efi_ct;

unsigned int __read_mostly efi_version;
unsigned int __read_mostly efi_fw_revision;
const CHAR16 *__read_mostly efi_fw_vendor;

EFI_RUNTIME_SERVICES *__read_mostly efi_rs;
static DEFINE_SPINLOCK(efi_rs_lock);

UINTN __read_mostly efi_memmap_size;
UINTN __read_mostly efi_mdesc_size;
void *__read_mostly efi_memmap;

struct efi __read_mostly efi = {
	.acpi   = EFI_INVALID_TABLE_ADDR,
	.acpi20 = EFI_INVALID_TABLE_ADDR,
	.mps    = EFI_INVALID_TABLE_ADDR,
	.smbios = EFI_INVALID_TABLE_ADDR,
};

l4_pgentry_t *__read_mostly efi_l4_pgtable;

unsigned long efi_rs_enter(void)
{
    unsigned long cr3 = read_cr3();

    spin_lock(&efi_rs_lock);

    /* prevent fixup_page_fault() from doing anything */
    irq_enter();

    if ( !is_hvm_vcpu(current) && !is_idle_vcpu(current) )
    {
        struct desc_ptr gdt_desc = {
            .limit = LAST_RESERVED_GDT_BYTE,
            .base  = (unsigned long)(per_cpu(gdt_table, smp_processor_id()) -
                                     FIRST_RESERVED_GDT_ENTRY)
        };

        asm volatile ( "lgdt %0" : : "m" (gdt_desc) );
    }

    write_cr3(virt_to_maddr(efi_l4_pgtable));

    return cr3;
}

void efi_rs_leave(unsigned long cr3)
{
    write_cr3(cr3);
    if ( !is_hvm_vcpu(current) && !is_idle_vcpu(current) )
    {
        struct desc_ptr gdt_desc = {
            .limit = LAST_RESERVED_GDT_BYTE,
            .base  = GDT_VIRT_START(current)
        };

        asm volatile ( "lgdt %0" : : "m" (gdt_desc) );
    }
    irq_exit();
    spin_unlock(&efi_rs_lock);
}

unsigned long efi_get_time(void)
{
    EFI_TIME time;
    EFI_STATUS status;
    unsigned long cr3 = efi_rs_enter(), flags;

    spin_lock_irqsave(&rtc_lock, flags);
    status = efi_rs->GetTime(&time, NULL);
    spin_unlock_irqrestore(&rtc_lock, flags);
    efi_rs_leave(cr3);

    if ( EFI_ERROR(status) )
        return 0;

    return mktime(time.Year, time.Month, time.Day,
                  time.Hour, time.Minute, time.Second);
}

void efi_halt_system(void)
{
    EFI_STATUS status;
    unsigned long cr3 = efi_rs_enter();

    status = efi_rs->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
    efi_rs_leave(cr3);

    printk(XENLOG_WARNING "EFI: could not halt system (%#lx)\n", status);
}

void efi_reset_system(bool_t warm)
{
    EFI_STATUS status;
    unsigned long cr3 = efi_rs_enter();

    status = efi_rs->ResetSystem(warm ? EfiResetWarm : EfiResetCold,
                                 EFI_SUCCESS, 0, NULL);
    efi_rs_leave(cr3);

    printk(XENLOG_WARNING "EFI: could not reset system (%#lx)\n", status);
}

#endif

int efi_get_info(uint32_t idx, union xenpf_efi_info *info)
{
    unsigned int i, n;

    switch ( idx )
    {
    case XEN_FW_EFI_VERSION:
        info->version = efi_version;
        break;
    case XEN_FW_EFI_RT_VERSION:
    {
        unsigned long cr3 = efi_rs_enter();

        info->version = efi_rs->Hdr.Revision;
        efi_rs_leave(cr3);
        break;
    }
    case XEN_FW_EFI_CONFIG_TABLE:
        info->cfg.addr = __pa(efi_ct);
        info->cfg.nent = efi_num_ct;
        break;
    case XEN_FW_EFI_VENDOR:
        info->vendor.revision = efi_fw_revision;
        n = info->vendor.bufsz / sizeof(*efi_fw_vendor);
        if ( !guest_handle_okay(guest_handle_cast(info->vendor.name,
                                                  CHAR16), n) )
            return -EFAULT;
        for ( i = 0; i < n; ++i )
        {
            if ( __copy_to_guest_offset(info->vendor.name, i,
                                        efi_fw_vendor + i, 1) )
                return -EFAULT;
            if ( !efi_fw_vendor[i] )
                break;
        }
        break;
    case XEN_FW_EFI_MEM_INFO:
        for ( i = 0; i < efi_memmap_size; i += efi_mdesc_size )
        {
            EFI_MEMORY_DESCRIPTOR *desc = efi_memmap + i;
            u64 len = desc->NumberOfPages << EFI_PAGE_SHIFT;

            if ( info->mem.addr >= desc->PhysicalStart &&
                 info->mem.addr < desc->PhysicalStart + len )
            {
                info->mem.type = desc->Type;
                info->mem.attr = desc->Attribute;
                if ( info->mem.addr + info->mem.size < info->mem.addr ||
                     info->mem.addr + info->mem.size >
                     desc->PhysicalStart + len )
                    info->mem.size = desc->PhysicalStart + len -
                                     info->mem.addr;
                return 0;
            }
        }
        return -ESRCH;
    default:
        return -EINVAL;
    }

    return 0;
}

static long gwstrlen(XEN_GUEST_HANDLE(CHAR16) str)
{
    unsigned long len;

    for ( len = 0; ; ++len )
    {
        CHAR16 c;

        if ( copy_from_guest_offset(&c, str, len, 1) )
            return -EFAULT;
        if ( !c )
            break;
    }

    return len;
}

static inline EFI_TIME *cast_time(struct xenpf_efi_time *time)
{
#define chk_fld(F, f) \
    BUILD_BUG_ON(sizeof(cast_time(NULL)->F) != sizeof(time->f) || \
                 offsetof(EFI_TIME, F) != offsetof(struct xenpf_efi_time, f))
    chk_fld(Year, year);
    chk_fld(Month, month);
    chk_fld(Day, day);
    chk_fld(Hour, hour);
    chk_fld(Minute, min);
    chk_fld(Second, sec);
    chk_fld(Nanosecond, ns);
    chk_fld(TimeZone, tz);
    chk_fld(Daylight, daylight);
#undef chk_fld
    return (void *)time;
}

static inline EFI_GUID *cast_guid(struct xenpf_efi_guid *guid)
{
#define chk_fld(n) \
    BUILD_BUG_ON(sizeof(cast_guid(NULL)->Data##n) != sizeof(guid->data##n) || \
                 offsetof(EFI_GUID, Data##n) != \
                 offsetof(struct xenpf_efi_guid, data##n))
    chk_fld(1);
    chk_fld(2);
    chk_fld(3);
    chk_fld(4);
#undef chk_fld
    return (void *)guid;
}

int efi_runtime_call(struct xenpf_efi_runtime_call *op)
{
    unsigned long cr3, flags;
    EFI_STATUS status = EFI_NOT_STARTED;
    int rc = 0;

    switch ( op->function )
    {
    case XEN_EFI_get_time:
    {
        EFI_TIME_CAPABILITIES caps;

        if ( op->misc )
            return -EINVAL;

        cr3 = efi_rs_enter();
        spin_lock_irqsave(&rtc_lock, flags);
        status = efi_rs->GetTime(cast_time(&op->u.get_time.time), &caps);
        spin_unlock_irqrestore(&rtc_lock, flags);
        efi_rs_leave(cr3);

        if ( !EFI_ERROR(status) )
        {
            op->u.get_time.resolution = caps.Resolution;
            op->u.get_time.accuracy = caps.Accuracy;
            if ( caps.SetsToZero )
                op->misc = XEN_EFI_GET_TIME_SET_CLEARS_NS;
        }
    }
    break;

    case XEN_EFI_set_time:
        if ( op->misc )
            return -EINVAL;

        cr3 = efi_rs_enter();
        spin_lock_irqsave(&rtc_lock, flags);
        status = efi_rs->SetTime(cast_time(&op->u.set_time));
        spin_unlock_irqrestore(&rtc_lock, flags);
        efi_rs_leave(cr3);
        break;

    case XEN_EFI_get_wakeup_time:
    {
        BOOLEAN enabled, pending;

        if ( op->misc )
            return -EINVAL;

        cr3 = efi_rs_enter();
        spin_lock_irqsave(&rtc_lock, flags);
        status = efi_rs->GetWakeupTime(&enabled, &pending,
                                       cast_time(&op->u.get_wakeup_time));
        spin_unlock_irqrestore(&rtc_lock, flags);
        efi_rs_leave(cr3);

        if ( !EFI_ERROR(status) )
        {
            if ( enabled )
                op->misc |= XEN_EFI_GET_WAKEUP_TIME_ENABLED;
            if ( pending )
                op->misc |= XEN_EFI_GET_WAKEUP_TIME_PENDING;
        }
    }
    break;

    case XEN_EFI_set_wakeup_time:
        if ( op->misc & ~(XEN_EFI_SET_WAKEUP_TIME_ENABLE |
                          XEN_EFI_SET_WAKEUP_TIME_ENABLE_ONLY) )
            return -EINVAL;

        cr3 = efi_rs_enter();
        spin_lock_irqsave(&rtc_lock, flags);
        status = efi_rs->SetWakeupTime(!!(op->misc &
                                          XEN_EFI_SET_WAKEUP_TIME_ENABLE),
                                       (op->misc &
                                        XEN_EFI_SET_WAKEUP_TIME_ENABLE_ONLY) ?
                                       NULL :
                                       cast_time(&op->u.set_wakeup_time));
        spin_unlock_irqrestore(&rtc_lock, flags);
        efi_rs_leave(cr3);

        op->misc = 0;
        break;

    case XEN_EFI_get_next_high_monotonic_count:
        if ( op->misc )
            return -EINVAL;

        cr3 = efi_rs_enter();
        status = efi_rs->GetNextHighMonotonicCount(&op->misc);
        efi_rs_leave(cr3);
        break;

    case XEN_EFI_get_variable:
    {
        CHAR16 *name;
        long len;
        unsigned char *data;
        UINTN size;

        if ( op->misc )
            return -EINVAL;

        len = gwstrlen(guest_handle_cast(op->u.get_variable.name, CHAR16));
        if ( len < 0 )
            return len;
        name = xmalloc_array(CHAR16, ++len);
        if ( !name )
           return -ENOMEM;
        __copy_from_guest(name, op->u.get_variable.name, len);

        size = op->u.get_variable.size;
        if ( size )
        {
            data = xmalloc_bytes(size);
            if ( !data )
            {
                xfree(name);
                return -ENOMEM;
            }
        }
        else
            data = NULL;

        cr3 = efi_rs_enter();
        status = efi_rs->GetVariable(
            name, cast_guid(&op->u.get_variable.vendor_guid),
            &op->misc, &size, data);
        efi_rs_leave(cr3);

        if ( !EFI_ERROR(status) &&
             copy_to_guest(op->u.get_variable.data, data, size) )
            rc = -EFAULT;
        op->u.get_variable.size = size;

        xfree(data);
        xfree(name);
    }
    break;

    case XEN_EFI_set_variable:
    {
        CHAR16 *name;
        long len;
        unsigned char *data;

        len = gwstrlen(guest_handle_cast(op->u.set_variable.name, CHAR16));
        if ( len < 0 )
            return len;
        name = xmalloc_array(CHAR16, ++len);
        if ( !name )
           return -ENOMEM;
        __copy_from_guest(name, op->u.set_variable.name, len);

        data = xmalloc_bytes(op->u.set_variable.size);
        if ( !data )
            rc = -ENOMEM;
        else if ( copy_from_guest(data, op->u.set_variable.data,
                                  op->u.set_variable.size) )
            rc = -EFAULT;
        else
        {
            cr3 = efi_rs_enter();
            status = efi_rs->SetVariable(
                name, cast_guid(&op->u.set_variable.vendor_guid),
                op->misc, op->u.set_variable.size, data);
            efi_rs_leave(cr3);
        }

        xfree(data);
        xfree(name);
    }
    break;

    case XEN_EFI_get_next_variable_name:
    {
        union {
            CHAR16 *str;
            unsigned char *raw;
        } name;
        UINTN size;

        if ( op->misc )
            return -EINVAL;

        size = op->u.get_next_variable_name.size;
        name.raw = xmalloc_bytes(size);
        if ( !name.raw )
            return -ENOMEM;
        if ( copy_from_guest(name.raw, op->u.get_next_variable_name.name,
                             size) )
        {
            xfree(name.raw);
            return -EFAULT;
        }

        cr3 = efi_rs_enter();
        status = efi_rs->GetNextVariableName(
            &size, name.str,
            cast_guid(&op->u.get_next_variable_name.vendor_guid));
        efi_rs_leave(cr3);

        if ( !EFI_ERROR(status) &&
             copy_to_guest(op->u.get_next_variable_name.name, name.raw, size) )
            rc = -EFAULT;
        op->u.get_next_variable_name.size = size;

        xfree(name.raw);
    }
    break;

    case XEN_EFI_query_variable_info:
        cr3 = efi_rs_enter();
        if ( (efi_rs->Hdr.Revision >> 16) < 2 )
        {
            efi_rs_leave(cr3);
            return -EOPNOTSUPP;
        }
        status = efi_rs->QueryVariableInfo(
            op->u.query_variable_info.attr,
            &op->u.query_variable_info.max_store_size,
            &op->u.query_variable_info.remain_store_size,
            &op->u.query_variable_info.max_size);
        efi_rs_leave(cr3);
        break;

    case XEN_EFI_query_capsule_capabilities:
    case XEN_EFI_update_capsule:
        cr3 = efi_rs_enter();
        if ( (efi_rs->Hdr.Revision >> 16) < 2 )
        {
            efi_rs_leave(cr3);
            return -EOPNOTSUPP;
        }
        efi_rs_leave(cr3);
        /* XXX fall through for now */
    default:
        return -ENOSYS;
    }

#ifndef COMPAT
    op->status = status;
#else
    op->status = (status & 0x3fffffff) | ((status >> 32) & 0xc0000000);
#endif

    return rc;
}
