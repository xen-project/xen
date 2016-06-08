/******************************************************************************
 * kexec.c - Achitecture independent kexec code for Xen
 *
 * Xen port written by:
 * - Simon 'Horms' Horman <horms@verge.net.au>
 * - Magnus Damm <magnus@valinux.co.jp>
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/acpi.h>
#include <xen/ctype.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/watchdog.h>
#include <xen/sched.h>
#include <xen/types.h>
#include <xen/hypercall.h>
#include <xen/kexec.h>
#include <xen/keyhandler.h>
#include <public/kexec.h>
#include <xen/cpumask.h>
#include <asm/atomic.h>
#include <xen/spinlock.h>
#include <xen/version.h>
#include <xen/console.h>
#include <xen/kexec.h>
#include <xen/kimage.h>
#include <public/elfnote.h>
#include <xsm/xsm.h>
#include <xen/cpu.h>
#ifdef CONFIG_COMPAT
#include <compat/kexec.h>
#endif

bool_t kexecing = FALSE;

/* Memory regions to store the per cpu register state etc. on a crash. */
typedef struct { Elf_Note * start; size_t size; } crash_note_range_t;
static crash_note_range_t * crash_notes;

/* Lock to prevent race conditions when allocating the crash note buffers.
 * It also serves to protect calls to alloc_from_crash_heap when allocating
 * crash note buffers in lower memory. */
static DEFINE_SPINLOCK(crash_notes_lock);

static Elf_Note *xen_crash_note;

static cpumask_t crash_saved_cpus;

static struct kexec_image *kexec_image[KEXEC_IMAGE_NR];

#define KEXEC_FLAG_DEFAULT_POS   (KEXEC_IMAGE_NR + 0)
#define KEXEC_FLAG_CRASH_POS     (KEXEC_IMAGE_NR + 1)
#define KEXEC_FLAG_IN_PROGRESS   (KEXEC_IMAGE_NR + 2)

static unsigned long kexec_flags = 0; /* the lowest bits are for KEXEC_IMAGE... */

static unsigned char vmcoreinfo_data[VMCOREINFO_BYTES];
static size_t vmcoreinfo_size = 0;

xen_kexec_reserve_t kexec_crash_area;
paddr_t __initdata kexec_crash_area_limit = ~(paddr_t)0;
static struct {
    u64 start, end;
    unsigned long size;
} ranges[16] __initdata;

/* Low crashinfo mode.  Start as INVALID so serveral codepaths can set up
 * defaults without needing to know the state of the others. */
enum low_crashinfo low_crashinfo_mode = LOW_CRASHINFO_INVALID;

/* This value is only considered if low_crash_mode is set to MIN or ALL, so
 * setting a default here is safe. Default to 4GB.  This is because the current
 * KEXEC_CMD_get_range compat hypercall trucates 64bit pointers to 32 bits. The
 * typical usecase for crashinfo_maxaddr will be for 64bit Xen with 32bit dom0
 * and 32bit crash kernel. */
static paddr_t __initdata crashinfo_maxaddr = 4ULL << 30;

/* = log base 2 of crashinfo_maxaddr after checking for sanity. Default to
 * larger than the entire physical address space. */
unsigned int __initdata crashinfo_maxaddr_bits = 64;

/* Pointers to keep track of the crash heap region. */
static void *crash_heap_current = NULL, *crash_heap_end = NULL;

/*
 * Parse command lines in the format
 *
 *   crashkernel=<ramsize-range>:<size>[,...][{@,<}<address>]
 *
 * with <ramsize-range> being of form
 *
 *   <start>-[<end>]
 *
 * as well as the legacy ones in the format
 *
 *   crashkernel=<size>[{@,<}<address>]
 */
static void __init parse_crashkernel(const char *str)
{
    const char *cur;

    if ( strchr(str, ':' ) )
    {
        unsigned int idx = 0;

        do {
            if ( idx >= ARRAY_SIZE(ranges) )
            {
                printk(XENLOG_WARNING "crashkernel: too many ranges\n");
                cur = NULL;
                str = strpbrk(str, "@<");
                break;
            }

            ranges[idx].start = parse_size_and_unit(cur = str + !!idx, &str);
            if ( cur == str )
                break;

            if ( *str != '-' )
            {
                printk(XENLOG_WARNING "crashkernel: '-' expected\n");
                break;
            }

            if ( *++str != ':' )
            {
                ranges[idx].end = parse_size_and_unit(cur = str, &str);
                if ( cur == str )
                    break;
                if ( ranges[idx].end <= ranges[idx].start )
                {
                    printk(XENLOG_WARNING "crashkernel: end <= start\n");
                    break;
                }
            }
            else
                ranges[idx].end = -1;

            if ( *str != ':' )
            {
                printk(XENLOG_WARNING "crashkernel: ':' expected\n");
                break;
            }

            ranges[idx].size = parse_size_and_unit(cur = str + 1, &str);
            if ( cur == str )
                break;

            ++idx;
        } while ( *str == ',' );
        if ( idx < ARRAY_SIZE(ranges) )
            ranges[idx].size = 0;
    }
    else
        kexec_crash_area.size = parse_size_and_unit(cur = str, &str);
    if ( cur != str )
    {
        if ( *str == '@' )
            kexec_crash_area.start = parse_size_and_unit(cur = str + 1, &str);
        else if ( *str == '<' )
            kexec_crash_area_limit = parse_size_and_unit(cur = str + 1, &str);
        else
            printk(XENLOG_WARNING "crashkernel: '%s' ignored\n", str);
    }
    if ( cur && cur == str )
        printk(XENLOG_WARNING "crashkernel: memory value expected\n");
}
custom_param("crashkernel", parse_crashkernel);

/* Parse command lines in the format:
 *
 *   low_crashinfo=[none,min,all]
 *
 * - none disables the low allocation of crash info.
 * - min will allocate enough low information for the crash kernel to be able
 *       to extract the hypervisor and dom0 message ring buffers.
 * - all will allocate additional structures such as domain and vcpu structs
 *       low so the crash kernel can perform an extended analysis of state.
 */
static void __init parse_low_crashinfo(const char * str)
{

    if ( !strlen(str) )
        /* default to min if user just specifies "low_crashinfo" */
        low_crashinfo_mode = LOW_CRASHINFO_MIN;
    else if ( !strcmp(str, "none" ) )
        low_crashinfo_mode = LOW_CRASHINFO_NONE;
    else if ( !strcmp(str, "min" ) )
        low_crashinfo_mode = LOW_CRASHINFO_MIN;
    else if ( !strcmp(str, "all" ) )
        low_crashinfo_mode = LOW_CRASHINFO_ALL;
    else
    {
        printk("Unknown low_crashinfo parameter '%s'.  Defaulting to min.\n", str);
        low_crashinfo_mode = LOW_CRASHINFO_MIN;
    }
}
custom_param("low_crashinfo", parse_low_crashinfo);

/* Parse command lines in the format:
 *
 *   crashinfo_maxaddr=<addr>
 *
 * <addr> will be rounded down to the nearest power of two.  Defaults to 64G
 */
static void __init parse_crashinfo_maxaddr(const char * str)
{
    u64 addr;

    /* if low_crashinfo_mode is unset, default to min. */
    if ( low_crashinfo_mode == LOW_CRASHINFO_INVALID )
        low_crashinfo_mode = LOW_CRASHINFO_MIN;

    if ( (addr = parse_size_and_unit(str, NULL)) )
        crashinfo_maxaddr = addr;
    else
        printk("Unable to parse crashinfo_maxaddr. Defaulting to %"PRIpaddr"\n",
               crashinfo_maxaddr);
}
custom_param("crashinfo_maxaddr", parse_crashinfo_maxaddr);

void __init set_kexec_crash_area_size(u64 system_ram)
{
    unsigned int idx;

    for ( idx = 0; idx < ARRAY_SIZE(ranges) && !kexec_crash_area.size; ++idx )
    {
        if ( !ranges[idx].size )
            break;

        if ( ranges[idx].size >= system_ram )
        {
            printk(XENLOG_WARNING "crashkernel: invalid size\n");
            continue;
        }

        if ( ranges[idx].start <= system_ram && ranges[idx].end > system_ram )
            kexec_crash_area.size = ranges[idx].size;
    }
}

/*
 * Only allow one cpu to continue on the crash path, forcing others to spin.
 * Racing on the crash path from here will end in misery.  If we reenter,
 * something has very gone wrong and retrying will (almost certainly) be
 * futile.  Return up to our nested panic() to try and reboot.
 *
 * This is noinline to make it obvious in stack traces which cpus have lost
 * the race (as opposed to being somewhere in kexec_common_shutdown())
 */
static int noinline one_cpu_only(void)
{
    static unsigned int crashing_cpu = -1;
    unsigned int cpu = smp_processor_id();

    if ( cmpxchg(&crashing_cpu, -1, cpu) != -1 )
    {
        /* Not the first entry into one_cpu_only(). */
        if ( crashing_cpu == cpu )
        {
            printk("Reentered the crash path.  Something is very broken\n");
            return -EBUSY;
        }

        /*
         * Another cpu has beaten us to this point.  Wait here patiently for
         * it to kill us.
         */
        for ( ; ; )
            halt();
    }

    set_bit(KEXEC_FLAG_IN_PROGRESS, &kexec_flags);
    printk("Executing kexec image on cpu%u\n", cpu);

    return 0;
}

/* Save the registers in the per-cpu crash note buffer. */
void kexec_crash_save_cpu(void)
{
    int cpu = smp_processor_id();
    Elf_Note *note;
    ELF_Prstatus *prstatus;
    crash_xen_core_t *xencore;

    BUG_ON ( ! crash_notes );

    if ( cpumask_test_and_set_cpu(cpu, &crash_saved_cpus) )
        return;

    note = crash_notes[cpu].start;

    prstatus = (ELF_Prstatus *)ELFNOTE_DESC(note);

    note = ELFNOTE_NEXT(note);
    xencore = (crash_xen_core_t *)ELFNOTE_DESC(note);

    elf_core_save_regs(&prstatus->pr_reg, xencore);
}

/* Set up the single Xen-specific-info crash note. */
crash_xen_info_t *kexec_crash_save_info(void)
{
    int cpu = smp_processor_id();
    crash_xen_info_t info;
    crash_xen_info_t *out = (crash_xen_info_t *)ELFNOTE_DESC(xen_crash_note);

    BUG_ON(!cpumask_test_and_set_cpu(cpu, &crash_saved_cpus));

    memset(&info, 0, sizeof(info));
    info.xen_major_version = xen_major_version();
    info.xen_minor_version = xen_minor_version();
    info.xen_extra_version = __pa(xen_extra_version());
    info.xen_changeset = __pa(xen_changeset());
    info.xen_compiler = __pa(xen_compiler());
    info.xen_compile_date = __pa(xen_compile_date());
    info.xen_compile_time = __pa(xen_compile_time());
    info.tainted = tainted;

    /* Copy from guaranteed-aligned local copy to possibly-unaligned dest. */
    memcpy(out, &info, sizeof(info));

    return out;
}

static int kexec_common_shutdown(void)
{
    int ret;

    ret = one_cpu_only();
    if ( ret )
        return ret;

    watchdog_disable();
    console_start_sync();
    spin_debug_disable();
    acpi_dmar_reinstate();

    return 0;
}

void kexec_crash(void)
{
    int pos;

    pos = (test_bit(KEXEC_FLAG_CRASH_POS, &kexec_flags) != 0);
    if ( !test_bit(KEXEC_IMAGE_CRASH_BASE + pos, &kexec_flags) )
        return;

    kexecing = TRUE;

    if ( kexec_common_shutdown() != 0 )
        return;

    kexec_crash_save_cpu();
    machine_crash_shutdown();
    machine_kexec(kexec_image[KEXEC_IMAGE_CRASH_BASE + pos]);

    BUG();
}

static long kexec_reboot(void *_image)
{
    struct kexec_image *image = _image;

    kexecing = TRUE;

    kexec_common_shutdown();
    machine_reboot_kexec(image);

    BUG();
    return 0;
}

static void do_crashdump_trigger(unsigned char key)
{
    printk("'%c' pressed -> triggering crashdump\n", key);
    kexec_crash();
    printk(" * no crash kernel loaded!\n");
}

static void setup_note(Elf_Note *n, const char *name, int type, int descsz)
{
    int l = strlen(name) + 1;
    strlcpy(ELFNOTE_NAME(n), name, l);
    n->namesz = l;
    n->descsz = descsz;
    n->type = type;
}

static size_t sizeof_note(const char *name, int descsz)
{
    return (sizeof(Elf_Note) +
            ELFNOTE_ALIGN(strlen(name)+1) +
            ELFNOTE_ALIGN(descsz));
}

static size_t sizeof_cpu_notes(const unsigned long cpu)
{
    /* All CPUs present a PRSTATUS and crash_xen_core note. */
    size_t bytes =
        + sizeof_note("CORE", sizeof(ELF_Prstatus)) +
        + sizeof_note("Xen", sizeof(crash_xen_core_t));

    /* CPU0 also presents the crash_xen_info note. */
    if ( ! cpu )
        bytes = bytes +
            sizeof_note("Xen", sizeof(crash_xen_info_t));

    return bytes;
}

/* Allocate size_t bytes of space from the previously allocated
 * crash heap if the user has requested that crash notes be allocated
 * in lower memory.  There is currently no case where the crash notes
 * should be free()'d. */
static void * alloc_from_crash_heap(const size_t bytes)
{
    void * ret;
    if ( crash_heap_current + bytes > crash_heap_end )
        return NULL;
    ret = (void*)crash_heap_current;
    crash_heap_current += bytes;
    return ret;
}

/* Allocate a crash note buffer for a newly onlined cpu. */
static int kexec_init_cpu_notes(const unsigned long cpu)
{
    Elf_Note * note = NULL;
    int ret = 0;
    int nr_bytes = 0;

    BUG_ON( cpu >= nr_cpu_ids || ! crash_notes );

    /* If already allocated, nothing to do. */
    if ( crash_notes[cpu].start )
        return ret;

    nr_bytes = sizeof_cpu_notes(cpu);

    /* If we dont care about the position of allocation, malloc. */
    if ( low_crashinfo_mode == LOW_CRASHINFO_NONE )
        note = xzalloc_bytes(nr_bytes);

    /* Protect the write into crash_notes[] with a spinlock, as this function
     * is on a hotplug path and a hypercall path. */
    spin_lock(&crash_notes_lock);

    /* If we are racing with another CPU and it has beaten us, give up
     * gracefully. */
    if ( crash_notes[cpu].start )
    {
        spin_unlock(&crash_notes_lock);
        /* Always return ok, because whether we successfully allocated or not,
         * another CPU has successfully allocated. */
        xfree(note);
    }
    else
    {
        /* If we care about memory possition, alloc from the crash heap,
         * also protected by the crash_notes_lock. */
        if ( low_crashinfo_mode > LOW_CRASHINFO_NONE )
            note = alloc_from_crash_heap(nr_bytes);

        crash_notes[cpu].start = note;
        crash_notes[cpu].size = nr_bytes;
        spin_unlock(&crash_notes_lock);

        /* If the allocation failed, and another CPU did not beat us, give
         * up with ENOMEM. */
        if ( ! note )
            ret = -ENOMEM;
        /* else all is good so lets set up the notes. */
        else
        {
            /* Set up CORE note. */
            setup_note(note, "CORE", NT_PRSTATUS, sizeof(ELF_Prstatus));
            note = ELFNOTE_NEXT(note);

            /* Set up Xen CORE note. */
            setup_note(note, "Xen", XEN_ELFNOTE_CRASH_REGS,
                       sizeof(crash_xen_core_t));

            if ( ! cpu )
            {
                /* Set up Xen Crash Info note. */
                xen_crash_note = note = ELFNOTE_NEXT(note);
                setup_note(note, "Xen", XEN_ELFNOTE_CRASH_INFO,
                           sizeof(crash_xen_info_t));
            }
        }
    }

    return ret;
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned long cpu = (unsigned long)hcpu;

    /* Only hook on CPU_UP_PREPARE because once a crash_note has been reported
     * to dom0, it must keep it around in case of a crash, as the crash kernel
     * will be hard coded to the original physical address reported. */
    switch ( action )
    {
    case CPU_UP_PREPARE:
        /* Ignore return value.  If this boot time, -ENOMEM will cause all
         * manner of problems elsewhere very soon, and if it is during runtime,
         * then failing to allocate crash notes is not a good enough reason to
         * fail the CPU_UP_PREPARE */
        kexec_init_cpu_notes(cpu);
        break;
    default:
        break;
    }
    return NOTIFY_DONE;
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback
};

void __init kexec_early_calculations(void)
{
    /* If low_crashinfo_mode is still INVALID, neither "low_crashinfo" nor
     * "crashinfo_maxaddr" have been specified on the command line, so
     * explicitly set to NONE. */
    if ( low_crashinfo_mode == LOW_CRASHINFO_INVALID )
        low_crashinfo_mode = LOW_CRASHINFO_NONE;

    if ( low_crashinfo_mode > LOW_CRASHINFO_NONE )
        crashinfo_maxaddr_bits = fls64(crashinfo_maxaddr) - 1;
}

static int __init kexec_init(void)
{
    void *cpu = (void *)(unsigned long)smp_processor_id();

    /* If no crash area, no need to allocate space for notes. */
    if ( !kexec_crash_area.size )
        return 0;

    if ( low_crashinfo_mode > LOW_CRASHINFO_NONE )
    {
        size_t crash_heap_size;

        /* This calculation is safe even if the machine is booted in
         * uniprocessor mode. */
        crash_heap_size = sizeof_cpu_notes(0) +
            sizeof_cpu_notes(1) * (nr_cpu_ids - 1);
        crash_heap_size = PAGE_ALIGN(crash_heap_size);

        crash_heap_current = alloc_xenheap_pages(
            get_order_from_bytes(crash_heap_size),
            MEMF_bits(crashinfo_maxaddr_bits) );

        if ( ! crash_heap_current )
            return -ENOMEM;

        memset(crash_heap_current, 0, crash_heap_size);

        crash_heap_end = crash_heap_current + crash_heap_size;
    }

    /* crash_notes may be allocated anywhere Xen can reach in memory.
       Only the individual CPU crash notes themselves must be allocated
       in lower memory if requested. */
    crash_notes = xzalloc_array(crash_note_range_t, nr_cpu_ids);
    if ( ! crash_notes )
        return -ENOMEM;

    register_keyhandler('C', do_crashdump_trigger, "trigger a crashdump", 0);

    cpu_callback(&cpu_nfb, CPU_UP_PREPARE, cpu);
    register_cpu_notifier(&cpu_nfb);
    return 0;
}
/* The reason for this to be a presmp_initcall as opposed to a regular
 * __initcall is to allow the setup of the cpu hotplug handler before APs are
 * brought up. */
presmp_initcall(kexec_init);

static int kexec_get_reserve(xen_kexec_range_t *range)
{
    if ( kexec_crash_area.size > 0 && kexec_crash_area.start > 0) {
        range->start = kexec_crash_area.start;
        range->size = kexec_crash_area.size;
    }
    else
        range->start = range->size = 0;
    return 0;
}

static int kexec_get_cpu(xen_kexec_range_t *range)
{
    int nr = range->nr;

    if ( nr < 0 || nr >= nr_cpu_ids )
        return -ERANGE;

    if ( ! crash_notes )
        return -EINVAL;

    /* Try once again to allocate room for the crash notes.  It is just possible
     * that more space has become available since we last tried.  If space has
     * already been allocated, kexec_init_cpu_notes() will return early with 0.
     */
    kexec_init_cpu_notes(nr);

    /* In the case of still not having enough memory to allocate buffer room,
     * returning a range of 0,0 is still valid. */
    if ( crash_notes[nr].start )
    {
        range->start = __pa(crash_notes[nr].start);
        range->size = crash_notes[nr].size;
    }
    else
        range->start = range->size = 0;

    return 0;
}

static int kexec_get_vmcoreinfo(xen_kexec_range_t *range)
{
    range->start = __pa((unsigned long)vmcoreinfo_data);
    range->size = VMCOREINFO_BYTES;
    return 0;
}

static int kexec_get_range_internal(xen_kexec_range_t *range)
{
    int ret = -EINVAL;

    switch ( range->range )
    {
    case KEXEC_RANGE_MA_CRASH:
        ret = kexec_get_reserve(range);
        break;
    case KEXEC_RANGE_MA_CPU:
        ret = kexec_get_cpu(range);
        break;
    case KEXEC_RANGE_MA_VMCOREINFO:
        ret = kexec_get_vmcoreinfo(range);
        break;
    default:
        ret = machine_kexec_get(range);
        break;
    }

    return ret;
}

static int kexec_get_range(XEN_GUEST_HANDLE_PARAM(void) uarg)
{
    xen_kexec_range_t range;
    int ret = -EINVAL;

    if ( unlikely(copy_from_guest(&range, uarg, 1)) )
        return -EFAULT;

    ret = kexec_get_range_internal(&range);

    if ( ret == 0 && unlikely(__copy_to_guest(uarg, &range, 1)) )
        ret = -EFAULT;

    return ret;
}

static int kexec_get_range_compat(XEN_GUEST_HANDLE_PARAM(void) uarg)
{
#ifdef CONFIG_COMPAT
    xen_kexec_range_t range;
    compat_kexec_range_t compat_range;
    int ret = -EINVAL;

    if ( unlikely(copy_from_guest(&compat_range, uarg, 1)) )
        return -EFAULT;

    XLAT_kexec_range(&range, &compat_range);

    ret = kexec_get_range_internal(&range);

    /* Dont silently truncate physical addresses or sizes. */
    if ( (range.start | range.size) & ~(unsigned long)(~0u) )
        return -ERANGE;

    if ( ret == 0 )
    {
        XLAT_kexec_range(&compat_range, &range);
        if ( unlikely(__copy_to_guest(uarg, &compat_range, 1)) )
             ret = -EFAULT;
    }

    return ret;
#else /* CONFIG_COMPAT */
    return 0;
#endif /* CONFIG_COMPAT */
}

static int kexec_load_get_bits(int type, int *base, int *bit)
{
    switch ( type )
    {
    case KEXEC_TYPE_DEFAULT:
        *base = KEXEC_IMAGE_DEFAULT_BASE;
        *bit = KEXEC_FLAG_DEFAULT_POS;
        break;
    case KEXEC_TYPE_CRASH:
        *base = KEXEC_IMAGE_CRASH_BASE;
        *bit = KEXEC_FLAG_CRASH_POS;
        break;
    default:
        return -1;
    }
    return 0;
}

void vmcoreinfo_append_str(const char *fmt, ...)
{
    va_list args;
    char buf[0x50];
    int r;
    size_t note_size = sizeof(Elf_Note) + ELFNOTE_ALIGN(strlen(VMCOREINFO_NOTE_NAME) + 1);

    if (vmcoreinfo_size + note_size + sizeof(buf) > VMCOREINFO_BYTES)
        return;

    va_start(args, fmt);
    r = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    memcpy(&vmcoreinfo_data[note_size + vmcoreinfo_size], buf, r);

    vmcoreinfo_size += r;
}

static void crash_save_vmcoreinfo(void)
{
    size_t data_size;

    if (vmcoreinfo_size > 0)    /* already saved */
        return;

    data_size = VMCOREINFO_BYTES - (sizeof(Elf_Note) + ELFNOTE_ALIGN(strlen(VMCOREINFO_NOTE_NAME) + 1));
    setup_note((Elf_Note *)vmcoreinfo_data, VMCOREINFO_NOTE_NAME, 0, data_size);

    VMCOREINFO_PAGESIZE(PAGE_SIZE);

    VMCOREINFO_SYMBOL(domain_list);
#ifndef frame_table
    VMCOREINFO_SYMBOL(frame_table);
#else
    {
        static const void *const _frame_table = frame_table;
        VMCOREINFO_SYMBOL_ALIAS(frame_table, _frame_table);
    }
#endif
    VMCOREINFO_SYMBOL(max_page);

    VMCOREINFO_STRUCT_SIZE(page_info);
    VMCOREINFO_STRUCT_SIZE(domain);

    VMCOREINFO_OFFSET(page_info, count_info);
    VMCOREINFO_OFFSET_SUB(page_info, v.inuse, _domain);
    VMCOREINFO_OFFSET(domain, domain_id);
    VMCOREINFO_OFFSET(domain, next_in_list);

#ifdef ARCH_CRASH_SAVE_VMCOREINFO
    arch_crash_save_vmcoreinfo();
#endif
}

static void kexec_unload_image(struct kexec_image *image)
{
    if ( !image )
        return;

    machine_kexec_unload(image);
    kimage_free(image);
}

static int kexec_exec(XEN_GUEST_HANDLE_PARAM(void) uarg)
{
    xen_kexec_exec_t exec;
    struct kexec_image *image;
    int base, bit, pos, ret = -EINVAL;

    if ( unlikely(copy_from_guest(&exec, uarg, 1)) )
        return -EFAULT;

    if ( kexec_load_get_bits(exec.type, &base, &bit) )
        return -EINVAL;

    pos = (test_bit(bit, &kexec_flags) != 0);

    /* Only allow kexec/kdump into loaded images */
    if ( !test_bit(base + pos, &kexec_flags) )
        return -ENOENT;

    switch (exec.type)
    {
    case KEXEC_TYPE_DEFAULT:
        image = kexec_image[base + pos];
        ret = continue_hypercall_on_cpu(0, kexec_reboot, image);
        break;
    case KEXEC_TYPE_CRASH:
        kexec_crash(); /* Does not return */
        break;
    }

    return -EINVAL; /* never reached */
}

static int kexec_swap_images(int type, struct kexec_image *new,
                             struct kexec_image **old)
{
    static DEFINE_SPINLOCK(kexec_lock);
    int base, bit, pos;
    int new_slot, old_slot;

    *old = NULL;

    if ( test_bit(KEXEC_FLAG_IN_PROGRESS, &kexec_flags) )
        return -EBUSY;

    if ( kexec_load_get_bits(type, &base, &bit) )
        return -EINVAL;

    spin_lock(&kexec_lock);

    pos = (test_bit(bit, &kexec_flags) != 0);
    old_slot = base + pos;
    new_slot = base + !pos;

    if ( new )
    {
        kexec_image[new_slot] = new;
        set_bit(new_slot, &kexec_flags);
    }
    change_bit(bit, &kexec_flags);

    clear_bit(old_slot, &kexec_flags);
    *old = kexec_image[old_slot];

    spin_unlock(&kexec_lock);

    return 0;
}

static int kexec_load_slot(struct kexec_image *kimage)
{
    struct kexec_image *old_kimage;
    int ret = -ENOMEM;

    ret = machine_kexec_load(kimage);
    if ( ret < 0 )
        return ret;

    crash_save_vmcoreinfo();

    ret = kexec_swap_images(kimage->type, kimage, &old_kimage);
    if ( ret < 0 )
        return ret;

    kexec_unload_image(old_kimage);

    return 0;
}

static uint16_t kexec_load_v1_arch(void)
{
#ifdef CONFIG_X86
    return is_pv_32bit_domain(hardware_domain) ? EM_386 : EM_X86_64;
#else
    return EM_NONE;
#endif
}

static int kexec_segments_add_segment(
    unsigned int *nr_segments, xen_kexec_segment_t *segments,
    unsigned long mfn)
{
    paddr_t maddr = (paddr_t)mfn << PAGE_SHIFT;
    unsigned int n = *nr_segments;

    /* Need a new segment? */
    if ( n == 0
         || segments[n-1].dest_maddr + segments[n-1].dest_size != maddr )
    {
        n++;
        if ( n > KEXEC_SEGMENT_MAX )
            return -EINVAL;
        *nr_segments = n;

        set_xen_guest_handle(segments[n-1].buf.h, NULL);
        segments[n-1].buf_size = 0;
        segments[n-1].dest_maddr = maddr;
        segments[n-1].dest_size = 0;
    }

    return 0;
}

static int kexec_segments_from_ind_page(unsigned long mfn,
                                        unsigned int *nr_segments,
                                        xen_kexec_segment_t *segments,
                                        bool_t compat)
{
    void *page;
    kimage_entry_t *entry;
    int ret = 0;

    page = map_domain_page(_mfn(mfn));

    /*
     * Walk the indirection page list, adding destination pages to the
     * segments.
     */
    for ( entry = page; ; )
    {
        unsigned long ind;

        ind = kimage_entry_ind(entry, compat);
        mfn = kimage_entry_mfn(entry, compat);

        switch ( ind )
        {
        case IND_DESTINATION:
            ret = kexec_segments_add_segment(nr_segments, segments, mfn);
            if ( ret < 0 )
                goto done;
            break;
        case IND_INDIRECTION:
            unmap_domain_page(page);
            entry = page = map_domain_page(_mfn(mfn));
            continue;
        case IND_DONE:
            goto done;
        case IND_SOURCE:
            if ( *nr_segments == 0 )
            {
                ret = -EINVAL;
                goto done;
            }
            segments[*nr_segments-1].dest_size += PAGE_SIZE;
            break;
        default:
            ret = -EINVAL;
            goto done;
        }
        entry = kimage_entry_next(entry, compat);
    }
done:
    unmap_domain_page(page);
    return ret;
}

static int kexec_do_load_v1(xen_kexec_load_v1_t *load, int compat)
{
    struct kexec_image *kimage = NULL;
    xen_kexec_segment_t *segments;
    uint16_t arch;
    unsigned int nr_segments = 0;
    unsigned long ind_mfn = load->image.indirection_page >> PAGE_SHIFT;
    int ret;

    arch = kexec_load_v1_arch();
    if ( arch == EM_NONE )
        return -ENOSYS;

    segments = xmalloc_array(xen_kexec_segment_t, KEXEC_SEGMENT_MAX);
    if ( segments == NULL )
        return -ENOMEM;

    /*
     * Work out the image segments (destination only) from the
     * indirection pages.
     *
     * This is needed so we don't allocate pages that will overlap
     * with the destination when building the new set of indirection
     * pages below.
     */
    ret = kexec_segments_from_ind_page(ind_mfn, &nr_segments, segments, compat);
    if ( ret < 0 )
        goto error;

    ret = kimage_alloc(&kimage, load->type, arch, load->image.start_address,
                       nr_segments, segments);
    if ( ret < 0 )
        goto error;

    /*
     * Build a new set of indirection pages in the native format.
     *
     * This walks the guest provided indirection pages a second time.
     * The guest could have altered then, invalidating the segment
     * information constructed above.  This will only result in the
     * resulting image being potentially unrelocatable.
     */
    ret = kimage_build_ind(kimage, ind_mfn, compat);
    if ( ret < 0 )
        goto error;

    if ( arch == EM_386 || arch == EM_X86_64 )
    {
        /*
         * Ensure 0 - 1 MiB is mapped and accessible by the image.
         *
         * This allows access to VGA memory and the region purgatory copies
         * in the crash case.
         */
        unsigned long addr;

        for ( addr = 0; addr < MB(1); addr += PAGE_SIZE )
        {
            ret = machine_kexec_add_page(kimage, addr, addr);
            if ( ret < 0 )
                goto error;
        }
    }

    ret = kexec_load_slot(kimage);
    if ( ret < 0 )
        goto error;

    return 0;

error:
    if ( !kimage )
        xfree(segments);
    kimage_free(kimage);
    return ret;
}

static int kexec_load_v1(XEN_GUEST_HANDLE_PARAM(void) uarg)
{
    xen_kexec_load_v1_t load;

    if ( unlikely(copy_from_guest(&load, uarg, 1)) )
        return -EFAULT;

    return kexec_do_load_v1(&load, 0);
}

static int kexec_load_v1_compat(XEN_GUEST_HANDLE_PARAM(void) uarg)
{
#ifdef CONFIG_COMPAT
    compat_kexec_load_v1_t compat_load;
    xen_kexec_load_v1_t load;

    if ( unlikely(copy_from_guest(&compat_load, uarg, 1)) )
        return -EFAULT;

    /* This is a bit dodgy, load.image is inside load,
     * but XLAT_kexec_load (which is automatically generated)
     * doesn't translate load.image (correctly)
     * Just copy load->type, the only other member, manually instead.
     *
     * XLAT_kexec_load(&load, &compat_load);
     */
    load.type = compat_load.type;
    XLAT_kexec_image(&load.image, &compat_load.image);

    return kexec_do_load_v1(&load, 1);
#else
    return 0;
#endif
}

static int kexec_load(XEN_GUEST_HANDLE_PARAM(void) uarg)
{
    xen_kexec_load_t load;
    xen_kexec_segment_t *segments;
    struct kexec_image *kimage = NULL;
    int ret;

    if ( copy_from_guest(&load, uarg, 1) )
        return -EFAULT;

    if ( load.nr_segments >= KEXEC_SEGMENT_MAX )
        return -EINVAL;

    segments = xmalloc_array(xen_kexec_segment_t, load.nr_segments);
    if ( segments == NULL )
        return -ENOMEM;

    if ( copy_from_guest(segments, load.segments.h, load.nr_segments) )
    {
        ret = -EFAULT;
        goto error;
    }

    ret = kimage_alloc(&kimage, load.type, load.arch, load.entry_maddr,
                       load.nr_segments, segments);
    if ( ret < 0 )
        goto error;

    ret = kimage_load_segments(kimage);
    if ( ret < 0 )
        goto error;

    ret = kexec_load_slot(kimage);
    if ( ret < 0 )
        goto error;

    return 0;

error:
    if ( ! kimage )
        xfree(segments);
    kimage_free(kimage);
    return ret;
}

static int kexec_do_unload(xen_kexec_unload_t *unload)
{
    struct kexec_image *old_kimage;
    int ret;

    ret = kexec_swap_images(unload->type, NULL, &old_kimage);
    if ( ret < 0 )
        return ret;

    kexec_unload_image(old_kimage);

    return 0;
}

static int kexec_unload_v1(XEN_GUEST_HANDLE_PARAM(void) uarg)
{
    xen_kexec_load_v1_t load;
    xen_kexec_unload_t unload;

    if ( copy_from_guest(&load, uarg, 1) )
        return -EFAULT;

    unload.type = load.type;
    return kexec_do_unload(&unload);
}

static int kexec_unload_v1_compat(XEN_GUEST_HANDLE_PARAM(void) uarg)
{
#ifdef CONFIG_COMPAT
    compat_kexec_load_v1_t compat_load;
    xen_kexec_unload_t unload;

    if ( copy_from_guest(&compat_load, uarg, 1) )
        return -EFAULT;

    unload.type = compat_load.type;
    return kexec_do_unload(&unload);
#else
    return 0;
#endif
}

static int kexec_unload(XEN_GUEST_HANDLE_PARAM(void) uarg)
{
    xen_kexec_unload_t unload;

    if ( unlikely(copy_from_guest(&unload, uarg, 1)) )
        return -EFAULT;

    return kexec_do_unload(&unload);
}

static int do_kexec_op_internal(unsigned long op,
                                XEN_GUEST_HANDLE_PARAM(void) uarg,
                                bool_t compat)
{
    int ret = -EINVAL;

    ret = xsm_kexec(XSM_PRIV);
    if ( ret )
        return ret;

    switch ( op )
    {
    case KEXEC_CMD_kexec_get_range:
        if (compat)
                ret = kexec_get_range_compat(uarg);
        else
                ret = kexec_get_range(uarg);
        break;
    case KEXEC_CMD_kexec_load_v1:
        if ( compat )
            ret = kexec_load_v1_compat(uarg);
        else
            ret = kexec_load_v1(uarg);
        break;
    case KEXEC_CMD_kexec_unload_v1:
        if ( compat )
            ret = kexec_unload_v1_compat(uarg);
        else
            ret = kexec_unload_v1(uarg);
        break;
    case KEXEC_CMD_kexec:
        ret = kexec_exec(uarg);
        break;
    case KEXEC_CMD_kexec_load:
        ret = kexec_load(uarg);
        break;
    case KEXEC_CMD_kexec_unload:
        ret = kexec_unload(uarg);
        break;
    }

    return ret;
}

long do_kexec_op(unsigned long op, XEN_GUEST_HANDLE_PARAM(void) uarg)
{
    return do_kexec_op_internal(op, uarg, 0);
}

#ifdef CONFIG_COMPAT
int compat_kexec_op(unsigned long op, XEN_GUEST_HANDLE_PARAM(void) uarg)
{
    return do_kexec_op_internal(op, uarg, 1);
}
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
