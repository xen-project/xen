/******************************************************************************
 * kexec.c - Achitecture independent kexec code for Xen
 *
 * Xen port written by:
 * - Simon 'Horms' Horman <horms@verge.net.au>
 * - Magnus Damm <magnus@valinux.co.jp>
 */

#include <asm/kexec.h>
#include <xen/lib.h>
#include <xen/ctype.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/sched.h>
#include <xen/types.h>
#include <xen/kexec.h>
#include <xen/keyhandler.h>
#include <public/kexec.h>
#include <xen/cpumask.h>
#include <asm/atomic.h>
#include <xen/spinlock.h>
#include <xen/version.h>
#include <public/elfnote.h>

#ifndef COMPAT

typedef long ret_t;

static DEFINE_PER_CPU(void *, crash_notes);

static Elf_Note *xen_crash_note;

static cpumask_t crash_saved_cpus;

static xen_kexec_image_t kexec_image[KEXEC_IMAGE_NR];

#define KEXEC_FLAG_DEFAULT_POS   (KEXEC_IMAGE_NR + 0)
#define KEXEC_FLAG_CRASH_POS     (KEXEC_IMAGE_NR + 1)
#define KEXEC_FLAG_IN_PROGRESS   (KEXEC_IMAGE_NR + 2)

static unsigned long kexec_flags = 0; /* the lowest bits are for KEXEC_IMAGE... */

static spinlock_t kexec_lock = SPIN_LOCK_UNLOCKED;

xen_kexec_reserve_t kexec_crash_area;

static void __init parse_crashkernel(const char *str)
{
    kexec_crash_area.size = parse_size_and_unit(str, &str);
    if ( *str == '@' )
        kexec_crash_area.start = parse_size_and_unit(str+1, NULL);
}
custom_param("crashkernel", parse_crashkernel);

static void one_cpu_only(void)
{
    /* Only allow the first cpu to continue - force other cpus to spin */
    if ( test_and_set_bit(KEXEC_FLAG_IN_PROGRESS, &kexec_flags) )
        for ( ; ; ) ;
}

/* Save the registers in the per-cpu crash note buffer. */
void kexec_crash_save_cpu(void)
{
    int cpu = smp_processor_id();
    Elf_Note *note = per_cpu(crash_notes, cpu);
    ELF_Prstatus *prstatus;
    crash_xen_core_t *xencore;

    if ( cpu_test_and_set(cpu, crash_saved_cpus) )
        return;

    prstatus = (ELF_Prstatus *)ELFNOTE_DESC(note);

    note = ELFNOTE_NEXT(note);
    xencore = (crash_xen_core_t *)ELFNOTE_DESC(note);

    elf_core_save_regs(&prstatus->pr_reg, xencore);
}

/* Set up the single Xen-specific-info crash note. */
crash_xen_info_t *kexec_crash_save_info(void)
{
    int cpu = smp_processor_id();
    crash_xen_info_t *info = (crash_xen_info_t *)ELFNOTE_DESC(xen_crash_note);

    BUG_ON(!cpu_test_and_set(cpu, crash_saved_cpus));

    info->xen_major_version = xen_major_version();
    info->xen_minor_version = xen_minor_version();
    info->xen_extra_version = __pa(xen_extra_version());
    info->xen_changeset = __pa(xen_changeset());
    info->xen_compiler = __pa(xen_compiler());
    info->xen_compile_date = __pa(xen_compile_date());
    info->xen_compile_time = __pa(xen_compile_time());
    info->tainted = tainted;

    return info;
}

void kexec_crash(void)
{
    int pos;

    pos = (test_bit(KEXEC_FLAG_CRASH_POS, &kexec_flags) != 0);
    if ( !test_bit(KEXEC_IMAGE_CRASH_BASE + pos, &kexec_flags) )
        return;

    one_cpu_only();
    kexec_crash_save_cpu();
    machine_crash_shutdown();

    machine_kexec(&kexec_image[KEXEC_IMAGE_CRASH_BASE + pos]);

    BUG();
}

static void do_crashdump_trigger(unsigned char key)
{
    printk("'%c' pressed -> triggering crashdump\n", key);
    kexec_crash();
    printk(" * no crash kernel loaded!\n");
}

static __init int register_crashdump_trigger(void)
{
    register_keyhandler('C', do_crashdump_trigger, "trigger a crashdump");
    return 0;
}
__initcall(register_crashdump_trigger);

static void setup_note(Elf_Note *n, const char *name, int type, int descsz)
{
    int l = strlen(name) + 1;
    strlcpy(ELFNOTE_NAME(n), name, l);
    n->namesz = l;
    n->descsz = descsz;
    n->type = type;
}

static int sizeof_note(const char *name, int descsz)
{
    return (sizeof(Elf_Note) +
            ELFNOTE_ALIGN(strlen(name)+1) +
            ELFNOTE_ALIGN(descsz));
}

#define kexec_get(x)      kexec_get_##x

#endif

static int kexec_get(reserve)(xen_kexec_range_t *range)
{
    if ( kexec_crash_area.size > 0 && kexec_crash_area.start > 0) {
        range->start = kexec_crash_area.start;
        range->size = kexec_crash_area.size;
    }
    else
        range->start = range->size = 0;
    return 0;
}

static int kexec_get(xen)(xen_kexec_range_t *range)
{
    range->start = virt_to_maddr(_start);
    range->size = (unsigned long)xenheap_phys_end - (unsigned long)range->start;
    return 0;
}

static int kexec_get(cpu)(xen_kexec_range_t *range)
{
    int nr = range->nr;
    int nr_bytes = 0;

    if ( nr < 0 || nr >= num_present_cpus() )
        return -EINVAL;

    nr_bytes += sizeof_note("CORE", sizeof(ELF_Prstatus));
    nr_bytes += sizeof_note("Xen", sizeof(crash_xen_core_t));

    /* The Xen info note is included in CPU0's range. */
    if ( nr == 0 )
        nr_bytes += sizeof_note("Xen", sizeof(crash_xen_info_t));

    if ( per_cpu(crash_notes, nr) == NULL )
    {
        Elf_Note *note;

        note = per_cpu(crash_notes, nr) = xmalloc_bytes(nr_bytes);

        if ( note == NULL )
            return -ENOMEM;

        /* Setup CORE note. */
        setup_note(note, "CORE", NT_PRSTATUS, sizeof(ELF_Prstatus));

        /* Setup Xen CORE note. */
        note = ELFNOTE_NEXT(note);
        setup_note(note, "Xen", XEN_ELFNOTE_CRASH_REGS, sizeof(crash_xen_core_t));

        if (nr == 0)
        {
            /* Setup system wide Xen info note. */
            xen_crash_note = note = ELFNOTE_NEXT(note);
            setup_note(note, "Xen", XEN_ELFNOTE_CRASH_INFO, sizeof(crash_xen_info_t));
        }
    }

    range->start = __pa((unsigned long)per_cpu(crash_notes, nr));
    range->size = nr_bytes;
    return 0;
}

static int kexec_get(range)(XEN_GUEST_HANDLE(void) uarg)
{
    xen_kexec_range_t range;
    int ret = -EINVAL;

    if ( unlikely(copy_from_guest(&range, uarg, 1)) )
        return -EFAULT;

    switch ( range.range )
    {
    case KEXEC_RANGE_MA_CRASH:
        ret = kexec_get(reserve)(&range);
        break;
    case KEXEC_RANGE_MA_XEN:
        ret = kexec_get(xen)(&range);
        break;
    case KEXEC_RANGE_MA_CPU:
        ret = kexec_get(cpu)(&range);
        break;
    }

    if ( ret == 0 && unlikely(copy_to_guest(uarg, &range, 1)) )
        return -EFAULT;

    return ret;
}

#ifndef COMPAT

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

#endif

static int kexec_load_unload(unsigned long op, XEN_GUEST_HANDLE(void) uarg)
{
    xen_kexec_load_t load;
    xen_kexec_image_t *image;
    int base, bit, pos;
    int ret = 0;

    if ( unlikely(copy_from_guest(&load, uarg, 1)) )
        return -EFAULT;

    if ( kexec_load_get_bits(load.type, &base, &bit) )
        return -EINVAL;

    pos = (test_bit(bit, &kexec_flags) != 0);

    /* Load the user data into an unused image */
    if ( op == KEXEC_CMD_kexec_load )
    {
        image = &kexec_image[base + !pos];

        BUG_ON(test_bit((base + !pos), &kexec_flags)); /* must be free */

#ifndef COMPAT
        memcpy(image, &load.image, sizeof(*image));
#else
        XLAT_kexec_image(image, &load.image);
#endif

        if ( !(ret = machine_kexec_load(load.type, base + !pos, image)) )
        {
            /* Set image present bit */
            set_bit((base + !pos), &kexec_flags);

            /* Make new image the active one */
            change_bit(bit, &kexec_flags);
        }
    }

    /* Unload the old image if present and load successful */
    if ( ret == 0 && !test_bit(KEXEC_FLAG_IN_PROGRESS, &kexec_flags) )
    {
        if ( test_and_clear_bit((base + pos), &kexec_flags) )
        {
            image = &kexec_image[base + pos];
            machine_kexec_unload(load.type, base + pos, image);
        }
    }

    return ret;
}

#ifndef COMPAT

static int kexec_exec(XEN_GUEST_HANDLE(void) uarg)
{
    xen_kexec_exec_t exec;
    xen_kexec_image_t *image;
    int base, bit, pos;

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
        image = &kexec_image[base + pos];
        one_cpu_only();
        machine_reboot_kexec(image); /* Does not return */
        break;
    case KEXEC_TYPE_CRASH:
        kexec_crash(); /* Does not return */
        break;
    }

    return -EINVAL; /* never reached */
}

#endif

ret_t do_kexec_op(unsigned long op, XEN_GUEST_HANDLE(void) uarg)
{
    unsigned long flags;
    int ret = -EINVAL;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    switch ( op )
    {
    case KEXEC_CMD_kexec_get_range:
        ret = kexec_get(range)(uarg);
        break;
    case KEXEC_CMD_kexec_load:
    case KEXEC_CMD_kexec_unload:
        spin_lock_irqsave(&kexec_lock, flags);
        if (!test_bit(KEXEC_FLAG_IN_PROGRESS, &kexec_flags))
        {
            ret = kexec_load_unload(op, uarg);
        }
        spin_unlock_irqrestore(&kexec_lock, flags);
        break;
    case KEXEC_CMD_kexec:
        ret = kexec_exec(uarg);
        break;
    }

    return ret;
}

#if defined(CONFIG_COMPAT) && !defined(COMPAT)
#include "compat/kexec.c"
#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
