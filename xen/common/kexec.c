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

DEFINE_PER_CPU (crash_note_t, crash_notes);
cpumask_t crash_saved_cpus;

xen_kexec_image_t kexec_image[KEXEC_IMAGE_NR];

#define KEXEC_FLAG_DEFAULT_POS   (KEXEC_IMAGE_NR + 0)
#define KEXEC_FLAG_CRASH_POS     (KEXEC_IMAGE_NR + 1)
#define KEXEC_FLAG_IN_PROGRESS   (KEXEC_IMAGE_NR + 2)

unsigned long kexec_flags = 0; /* the lowest bits are for KEXEC_IMAGE... */

spinlock_t kexec_lock = SPIN_LOCK_UNLOCKED;

xen_kexec_reserve_t kexec_crash_area;

static void __init parse_crashkernel(const char *str)
{
    unsigned long start, size;

    size = parse_size_and_unit(str, &str);
    if ( *str == '@' )
        start = parse_size_and_unit(str+1, NULL);
    else
        start = 0;

    if ( start && size )
    {
        kexec_crash_area.start = start;
        kexec_crash_area.size = size;
    }
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
    crash_note_t *cntp;

    if ( cpu_test_and_set(cpu, crash_saved_cpus) )
        return;

    cntp = &per_cpu(crash_notes, cpu);
    elf_core_save_regs(&cntp->core.desc.desc.pr_reg,
                       &cntp->xen_regs.desc.desc);

    /* Set up crash "CORE" note. */
    setup_crash_note(cntp, core, CORE_STR, CORE_STR_LEN, NT_PRSTATUS);

    /* Set up crash note "Xen", XEN_ELFNOTE_CRASH_REGS. */
    setup_crash_note(cntp, xen_regs, XEN_STR, XEN_STR_LEN,
                     XEN_ELFNOTE_CRASH_REGS);
}

/* Set up the single Xen-specific-info crash note. */
crash_xen_info_t *kexec_crash_save_info(void)
{
    int cpu = smp_processor_id();
    crash_note_t *cntp;
    crash_xen_info_t *info;

    BUG_ON(!cpu_test_and_set(cpu, crash_saved_cpus));

    cntp = &per_cpu(crash_notes, cpu);

    /* Set up crash note "Xen", XEN_ELFNOTE_CRASH_INFO. */
    setup_crash_note(cntp, xen_info, XEN_STR, XEN_STR_LEN,
                     XEN_ELFNOTE_CRASH_INFO);

    info = &cntp->xen_info.desc.desc;

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

static int kexec_get_reserve(xen_kexec_range_t *range)
{
    range->start = kexec_crash_area.start;
    range->size = kexec_crash_area.size;
    return 0;
}

static int kexec_get_xen(xen_kexec_range_t *range)
{
    range->start = virt_to_maddr(_start);
    range->size = (unsigned long)_end - (unsigned long)_start;
    return 0;
}

static int kexec_get_cpu(xen_kexec_range_t *range)
{
    if ( range->nr < 0 || range->nr >= num_present_cpus() )
        return -EINVAL;

    range->start = __pa((unsigned long)&per_cpu(crash_notes, range->nr));
    range->size = sizeof(crash_note_t);
    return 0;
}

static int kexec_get_range(XEN_GUEST_HANDLE(void) uarg)
{
    xen_kexec_range_t range;
    int ret = -EINVAL;

    if ( unlikely(copy_from_guest(&range, uarg, 1)) )
        return -EFAULT;

    switch ( range.range )
    {
    case KEXEC_RANGE_MA_CRASH:
        ret = kexec_get_reserve(&range);
        break;
    case KEXEC_RANGE_MA_XEN:
        ret = kexec_get_xen(&range);
        break;
    case KEXEC_RANGE_MA_CPU:
        ret = kexec_get_cpu(&range);
        break;
    }

    if ( ret == 0 && unlikely(copy_to_guest(uarg, &range, 1)) )
        return -EFAULT;

    return ret;
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

        memcpy(image, &load.image, sizeof(*image));

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

long do_kexec_op(unsigned long op, XEN_GUEST_HANDLE(void) uarg)
{
    unsigned long flags;
    int ret = -EINVAL;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    switch ( op )
    {
    case KEXEC_CMD_kexec_get_range:
        ret = kexec_get_range(uarg);
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
