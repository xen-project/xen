#include "efi.h"
#include "runtime.h"
#include <xen/cache.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/irq.h>
#include <xen/time.h>

DEFINE_XEN_GUEST_HANDLE(CHAR16);

struct efi_rs_state {
#ifdef CONFIG_X86
 /*
  * The way stacks get set up leads to them always being on an 8-byte
  * boundary not evenly divisible by 16 (see asm-x86/current.h). The EFI ABI,
  * just like the CPU one, however requires stacks to be 16-byte aligned
  * before every function call. Since the compiler assumes this (unless
  * passing it -mpreferred-stack-boundary=3), it wouldn't generate code to
  * align the stack to 16 bytes even if putting a 16-byte aligned object
  * there. Hence we need to force larger than 16-byte alignment, even if we
  * don't strictly need that.
  */
 unsigned long __aligned(32) cr3;
#endif
};

struct efi_rs_state efi_rs_enter(void);
void efi_rs_leave(struct efi_rs_state *);

#ifndef COMPAT

#ifndef CONFIG_ARM
# include <asm/i387.h>
# include <asm/xstate.h>
# include <public/platform.h>
#endif

unsigned int __read_mostly efi_num_ct;
const EFI_CONFIGURATION_TABLE *__read_mostly efi_ct;

unsigned int __read_mostly efi_version;
unsigned int __read_mostly efi_fw_revision;
const CHAR16 *__read_mostly efi_fw_vendor;

const EFI_RUNTIME_SERVICES *__read_mostly efi_rs;
#ifndef CONFIG_ARM /* TODO - disabled until implemented on ARM */
static DEFINE_SPINLOCK(efi_rs_lock);
static unsigned int efi_rs_on_cpu = NR_CPUS;
#endif

UINTN __read_mostly efi_memmap_size;
UINTN __read_mostly efi_mdesc_size;
void *__read_mostly efi_memmap;

UINT64 __read_mostly efi_boot_max_var_store_size;
UINT64 __read_mostly efi_boot_remain_var_store_size;
UINT64 __read_mostly efi_boot_max_var_size;

UINT64 __read_mostly efi_apple_properties_addr;
UINTN __read_mostly efi_apple_properties_len;

/* Bit field representing available EFI features/properties. */
unsigned int efi_flags;

struct efi __read_mostly efi = {
	.acpi   = EFI_INVALID_TABLE_ADDR,
	.acpi20 = EFI_INVALID_TABLE_ADDR,
	.mps    = EFI_INVALID_TABLE_ADDR,
	.smbios = EFI_INVALID_TABLE_ADDR,
	.smbios3 = EFI_INVALID_TABLE_ADDR,
};

const struct efi_pci_rom *__read_mostly efi_pci_roms;

bool efi_enabled(unsigned int feature)
{
    return test_bit(feature, &efi_flags);
}

#ifndef CONFIG_ARM /* TODO - disabled until implemented on ARM */

struct efi_rs_state efi_rs_enter(void)
{
    static const u16 fcw = FCW_DEFAULT;
    static const u32 mxcsr = MXCSR_DEFAULT;
    struct efi_rs_state state = { .cr3 = 0 };

    if ( !efi_l4_pgtable )
        return state;

    state.cr3 = read_cr3();
    save_fpu_enable();
    asm volatile ( "fnclex; fldcw %0" :: "m" (fcw) );
    asm volatile ( "ldmxcsr %0" :: "m" (mxcsr) );

    spin_lock(&efi_rs_lock);

    efi_rs_on_cpu = smp_processor_id();

    /* prevent fixup_page_fault() from doing anything */
    irq_enter();

    if ( is_pv_vcpu(current) && !is_idle_vcpu(current) )
    {
        struct desc_ptr gdt_desc = {
            .limit = LAST_RESERVED_GDT_BYTE,
            .base  = (unsigned long)(per_cpu(gdt_table, smp_processor_id()) -
                                     FIRST_RESERVED_GDT_ENTRY)
        };

        lgdt(&gdt_desc);
    }

    write_cr3(virt_to_maddr(efi_l4_pgtable));

    return state;
}

void efi_rs_leave(struct efi_rs_state *state)
{
    if ( !state->cr3 )
        return;
    write_cr3(state->cr3);
    if ( is_pv_vcpu(current) && !is_idle_vcpu(current) )
    {
        struct desc_ptr gdt_desc = {
            .limit = LAST_RESERVED_GDT_BYTE,
            .base  = GDT_VIRT_START(current)
        };

        lgdt(&gdt_desc);
    }
    irq_exit();
    efi_rs_on_cpu = NR_CPUS;
    spin_unlock(&efi_rs_lock);
    stts();
}

bool efi_rs_using_pgtables(void)
{
    return efi_l4_pgtable &&
           (smp_processor_id() == efi_rs_on_cpu) &&
           (read_cr3() == virt_to_maddr(efi_l4_pgtable));
}

unsigned long efi_get_time(void)
{
    EFI_TIME time;
    EFI_STATUS status;
    struct efi_rs_state state = efi_rs_enter();
    unsigned long flags;

    if ( !state.cr3 )
        return 0;
    spin_lock_irqsave(&rtc_lock, flags);
    status = efi_rs->GetTime(&time, NULL);
    spin_unlock_irqrestore(&rtc_lock, flags);
    efi_rs_leave(&state);

    if ( EFI_ERROR(status) )
        return 0;

    return mktime(time.Year, time.Month, time.Day,
                  time.Hour, time.Minute, time.Second);
}

void efi_halt_system(void)
{
    EFI_STATUS status;
    struct efi_rs_state state = efi_rs_enter();

    if ( !state.cr3 )
        return;
    status = efi_rs->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
    efi_rs_leave(&state);

    printk(XENLOG_WARNING "EFI: could not halt system (%#lx)\n", status);
}

void efi_reset_system(bool warm)
{
    EFI_STATUS status;
    struct efi_rs_state state = efi_rs_enter();

    if ( !state.cr3 )
        return;
    status = efi_rs->ResetSystem(warm ? EfiResetWarm : EfiResetCold,
                                 EFI_SUCCESS, 0, NULL);
    efi_rs_leave(&state);

    printk(XENLOG_WARNING "EFI: could not reset system (%#lx)\n", status);
}

#endif /* CONFIG_ARM */
#endif

#ifndef CONFIG_ARM /* TODO - disabled until implemented on ARM */
int efi_get_info(uint32_t idx, union xenpf_efi_info *info)
{
    unsigned int i, n;

    if ( !efi_enabled(EFI_BOOT) )
        return -ENOSYS;

    switch ( idx )
    {
    case XEN_FW_EFI_VERSION:
        info->version = efi_version;
        break;
    case XEN_FW_EFI_RT_VERSION:
    {
        struct efi_rs_state state = efi_rs_enter();

        if ( !state.cr3 )
            return -EOPNOTSUPP;
        info->version = efi_rs->Hdr.Revision;
        efi_rs_leave(&state);
        break;
    }
    case XEN_FW_EFI_CONFIG_TABLE:
        info->cfg.addr = __pa(efi_ct);
        info->cfg.nent = efi_num_ct;
        break;
    case XEN_FW_EFI_VENDOR:
        if ( !efi_fw_vendor )
            return -EOPNOTSUPP;
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
    case XEN_FW_EFI_PCI_ROM: {
        const struct efi_pci_rom *ent;

        for ( ent = efi_pci_roms; ent; ent = ent->next )
            if ( info->pci_rom.segment == ent->segment &&
                 info->pci_rom.bus == ent->bus &&
                 info->pci_rom.devfn == ent->devfn &&
                 info->pci_rom.vendor == ent->vendor &&
                 info->pci_rom.devid == ent->devid )
            {
                info->pci_rom.address = __pa(ent->data);
                info->pci_rom.size = ent->size;
                return 0;
            }
        return -ESRCH;
    }

    case XEN_FW_EFI_APPLE_PROPERTIES:
        if ( !efi_apple_properties_len )
            return -ENODATA;
        info->apple_properties.address = efi_apple_properties_addr;
        info->apple_properties.size = efi_apple_properties_len;
        break;

    default:
        return -EINVAL;
    }

    return 0;
}

static long gwstrlen(XEN_GUEST_HANDLE_PARAM(CHAR16) str)
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
    struct efi_rs_state state;
    unsigned long flags;
    EFI_STATUS status = EFI_NOT_STARTED;
    int rc = 0;

    if ( !efi_enabled(EFI_BOOT) )
        return -ENOSYS;

    if ( !efi_enabled(EFI_RS) )
        return -EOPNOTSUPP;

    switch ( op->function )
    {
    case XEN_EFI_get_time:
    {
        EFI_TIME_CAPABILITIES caps;

        if ( op->misc )
            return -EINVAL;

        state = efi_rs_enter();
        if ( !state.cr3 )
            return -EOPNOTSUPP;
        spin_lock_irqsave(&rtc_lock, flags);
        status = efi_rs->GetTime(cast_time(&op->u.get_time.time), &caps);
        spin_unlock_irqrestore(&rtc_lock, flags);
        efi_rs_leave(&state);

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

        state = efi_rs_enter();
        if ( !state.cr3 )
            return -EOPNOTSUPP;
        spin_lock_irqsave(&rtc_lock, flags);
        status = efi_rs->SetTime(cast_time(&op->u.set_time));
        spin_unlock_irqrestore(&rtc_lock, flags);
        efi_rs_leave(&state);
        break;

    case XEN_EFI_get_wakeup_time:
    {
        BOOLEAN enabled, pending;

        if ( op->misc )
            return -EINVAL;

        state = efi_rs_enter();
        if ( !state.cr3 )
            return -EOPNOTSUPP;
        spin_lock_irqsave(&rtc_lock, flags);
        status = efi_rs->GetWakeupTime(&enabled, &pending,
                                       cast_time(&op->u.get_wakeup_time));
        spin_unlock_irqrestore(&rtc_lock, flags);
        efi_rs_leave(&state);

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

        state = efi_rs_enter();
        if ( !state.cr3 )
            return -EOPNOTSUPP;
        spin_lock_irqsave(&rtc_lock, flags);
        status = efi_rs->SetWakeupTime(!!(op->misc &
                                          XEN_EFI_SET_WAKEUP_TIME_ENABLE),
                                       (op->misc &
                                        XEN_EFI_SET_WAKEUP_TIME_ENABLE_ONLY) ?
                                       NULL :
                                       cast_time(&op->u.set_wakeup_time));
        spin_unlock_irqrestore(&rtc_lock, flags);
        efi_rs_leave(&state);

        op->misc = 0;
        break;

    case XEN_EFI_get_next_high_monotonic_count:
        if ( op->misc )
            return -EINVAL;

        state = efi_rs_enter();
        if ( state.cr3 )
            status = efi_rs->GetNextHighMonotonicCount(&op->misc);
        else
            rc = -EOPNOTSUPP;
        efi_rs_leave(&state);
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

        state = efi_rs_enter();
        if ( state.cr3 )
        {
            status = efi_rs->GetVariable(
                name, cast_guid(&op->u.get_variable.vendor_guid),
                &op->misc, &size, data);
            efi_rs_leave(&state);

            if ( !EFI_ERROR(status) &&
                 copy_to_guest(op->u.get_variable.data, data, size) )
                rc = -EFAULT;
            op->u.get_variable.size = size;
        }
        else
            rc = -EOPNOTSUPP;

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
            state = efi_rs_enter();
            if ( state.cr3 )
                status = efi_rs->SetVariable(
                    name, cast_guid(&op->u.set_variable.vendor_guid),
                    op->misc, op->u.set_variable.size, data);
            else
                rc = -EOPNOTSUPP;
            efi_rs_leave(&state);
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

        state = efi_rs_enter();
        if ( state.cr3 )
        {
            status = efi_rs->GetNextVariableName(
                &size, name.str,
                cast_guid(&op->u.get_next_variable_name.vendor_guid));
            efi_rs_leave(&state);

            /*
             * Copy the variable name if necessary. The caller provided size
             * is used because some firmwares update size when they shouldn't.
             * */
            if ( !EFI_ERROR(status) &&
                 __copy_to_guest(op->u.get_next_variable_name.name,
                                 name.raw, op->u.get_next_variable_name.size) )
                rc = -EFAULT;
            op->u.get_next_variable_name.size = size;
        }
        else
            rc = -EOPNOTSUPP;

        xfree(name.raw);
    }
    break;

    case XEN_EFI_query_variable_info:
        if ( op->misc & ~XEN_EFI_VARINFO_BOOT_SNAPSHOT )
            return -EINVAL;

        if ( op->misc & XEN_EFI_VARINFO_BOOT_SNAPSHOT )
        {
            if ( (op->u.query_variable_info.attr
                  & ~EFI_VARIABLE_APPEND_WRITE) !=
                 (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS) )
                return -EINVAL;

            op->u.query_variable_info.max_store_size =
                efi_boot_max_var_store_size;
            op->u.query_variable_info.remain_store_size =
                efi_boot_remain_var_store_size;
            if ( efi_boot_max_var_store_size )
            {
                op->u.query_variable_info.max_size = efi_boot_max_var_size;
                status = EFI_SUCCESS;
            }
            else
            {
                op->u.query_variable_info.max_size = 0;
                status = efi_boot_max_var_size;
            }
            break;
        }

        state = efi_rs_enter();
        if ( !state.cr3 || (efi_rs->Hdr.Revision >> 16) < 2 )
        {
            efi_rs_leave(&state);
            return -EOPNOTSUPP;
        }
        status = efi_rs->QueryVariableInfo(
            op->u.query_variable_info.attr,
            &op->u.query_variable_info.max_store_size,
            &op->u.query_variable_info.remain_store_size,
            &op->u.query_variable_info.max_size);
        efi_rs_leave(&state);
        break;

    case XEN_EFI_query_capsule_capabilities:
    case XEN_EFI_update_capsule:
        if ( op->misc )
            return -EINVAL;

        state = efi_rs_enter();
        if ( !state.cr3 || (efi_rs->Hdr.Revision >> 16) < 2 )
        {
            efi_rs_leave(&state);
            return -EOPNOTSUPP;
        }
        efi_rs_leave(&state);
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
#endif
