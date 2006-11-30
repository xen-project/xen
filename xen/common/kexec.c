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

static char opt_crashkernel[32] = "";
string_param("crashkernel", opt_crashkernel);

DEFINE_PER_CPU (crash_note_t, crash_notes);
cpumask_t crash_saved_cpus;
int crashing_cpu;

xen_kexec_image_t kexec_image[KEXEC_IMAGE_NR];

#define KEXEC_FLAG_DEFAULT_POS   (KEXEC_IMAGE_NR + 0)
#define KEXEC_FLAG_CRASH_POS     (KEXEC_IMAGE_NR + 1)
#define KEXEC_FLAG_IN_PROGRESS   (KEXEC_IMAGE_NR + 2)

unsigned long kexec_flags = 0; /* the lowest bits are for KEXEC_IMAGE... */

spinlock_t kexec_lock = SPIN_LOCK_UNLOCKED;

static void one_cpu_only(void)
{
   /* Only allow the first cpu to continue - force other cpus to spin */
    if ( test_and_set_bit(KEXEC_FLAG_IN_PROGRESS, &kexec_flags) )
    {
        while (1);
    }
}

/* Save the registers in the per-cpu crash note buffer */

void machine_crash_save_cpu(void)
{
    int cpu = smp_processor_id();
    crash_note_t *cntp;

    if ( !cpu_test_and_set(cpu, crash_saved_cpus) )
    {
        cntp = &per_cpu(crash_notes, cpu);
        elf_core_save_regs(&cntp->core.desc.desc.pr_reg,
                           &cntp->xen_regs.desc.desc);

        /* setup crash "CORE" note */
        setup_crash_note(cntp, core, CORE_STR, CORE_STR_LEN, NT_PRSTATUS);

        /* setup crash note "Xen", XEN_ELFNOTE_CRASH_REGS */
        setup_crash_note(cntp, xen_regs, XEN_STR, XEN_STR_LEN,
                         XEN_ELFNOTE_CRASH_REGS);
    }
}

/* Setup the single Xen specific info crash note */

crash_xen_info_t *machine_crash_save_info(void)
{
    int cpu = smp_processor_id();
    crash_note_t *cntp;
    crash_xen_info_t *info;

    BUG_ON(!cpu_test_and_set(cpu, crash_saved_cpus));

    cntp = &per_cpu(crash_notes, cpu);

    /* setup crash note "Xen", XEN_ELFNOTE_CRASH_INFO */
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

void machine_crash_kexec(void)
{
    int pos;
    xen_kexec_image_t *image;

    one_cpu_only();

    machine_crash_save_cpu();
    crashing_cpu = smp_processor_id();

    machine_crash_shutdown();

    pos = (test_bit(KEXEC_FLAG_CRASH_POS, &kexec_flags) != 0);

    if ( test_bit(KEXEC_IMAGE_CRASH_BASE + pos, &kexec_flags) )
    {
        image = &kexec_image[KEXEC_IMAGE_CRASH_BASE + pos];
        machine_kexec(image); /* Does not return */
    }

    while (1); /* No image available - just spin */
}

static void do_crashdump_trigger(unsigned char key)
{
	printk("triggering crashdump\n");
	machine_crash_kexec();
}

static __init int register_crashdump_trigger(void)
{
	register_keyhandler('c', do_crashdump_trigger, "trigger a crashdump");
	return 0;
}
__initcall(register_crashdump_trigger);

void machine_kexec_reserved(xen_kexec_reserve_t *reservation)
{
    unsigned long val[2];
    char *str = opt_crashkernel;
    int k = 0;

    memset(reservation, 0, sizeof(*reservation));

    while (k < ARRAY_SIZE(val)) {
        if (*str == '\0') {
            break;
        }
        val[k] = simple_strtoul(str, &str, 0);
        switch (toupper(*str)) {
        case 'G': val[k] <<= 10;
        case 'M': val[k] <<= 10;
        case 'K': val[k] <<= 10;
            str++;
        }
        if (*str == '@') {
            str++;
        }
        k++;
    }

    if (k == ARRAY_SIZE(val)) {
        reservation->size = val[0];
        reservation->start = val[1];
    }
}

static int kexec_get_reserve(xen_kexec_range_t *range)
{
    xen_kexec_reserve_t reservation;

    machine_kexec_reserved(&reservation);

    range->start = reservation.start;
    range->size = reservation.size;
    return 0;
}

extern unsigned long _text, _end;

static int kexec_get_xen(xen_kexec_range_t *range, int get_ma)
{
    if ( get_ma )
        range->start = virt_to_maddr(&_text);
    else
        range->start = (unsigned long) &_text;

    range->size = &_end - &_text;
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
        ret = kexec_get_xen(&range, 1);
        break;
    case KEXEC_RANGE_VA_XEN:
        ret = kexec_get_xen(&range, 0);
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
        machine_shutdown(image); /* Does not return */
        break;
    case KEXEC_TYPE_CRASH:
        machine_crash_kexec(); /* Does not return */
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
