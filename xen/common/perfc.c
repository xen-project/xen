
#include <xen/lib.h>
#include <xen/smp.h>
#include <xen/time.h>
#include <xen/perfc.h>
#include <xen/keyhandler.h> 
#include <xen/spinlock.h>
#include <xen/mm.h>
#include <xen/guest_access.h>
#include <public/sysctl.h>
#include <asm/perfc.h>

#undef  PERFCOUNTER
#undef  PERFCOUNTER_CPU
#undef  PERFCOUNTER_ARRAY
#undef  PERFSTATUS
#undef  PERFSTATUS_CPU
#undef  PERFSTATUS_ARRAY
#define PERFCOUNTER( var, name )              { name, TYPE_SINGLE, 0 },
#define PERFCOUNTER_CPU( var, name )          { name, TYPE_CPU,    0 },
#define PERFCOUNTER_ARRAY( var, name, size )  { name, TYPE_ARRAY,  size },
#define PERFSTATUS( var, name )               { name, TYPE_S_SINGLE, 0 },
#define PERFSTATUS_CPU( var, name )           { name, TYPE_S_CPU,    0 },
#define PERFSTATUS_ARRAY( var, name, size )   { name, TYPE_S_ARRAY,  size },
static struct {
    char *name;
    enum { TYPE_SINGLE, TYPE_CPU, TYPE_ARRAY,
           TYPE_S_SINGLE, TYPE_S_CPU, TYPE_S_ARRAY
    } type;
    int nr_elements;
} perfc_info[] = {
#include <xen/perfc_defn.h>
};

#define NR_PERFCTRS (sizeof(perfc_info) / sizeof(perfc_info[0]))

struct perfcounter perfcounters;

void perfc_printall(unsigned char key)
{
    unsigned int i, j, sum;
    s_time_t now = NOW();
    atomic_t *counters = (atomic_t *)&perfcounters;

    printk("Xen performance counters SHOW  (now = 0x%08X:%08X)\n",
           (u32)(now>>32), (u32)now);

    for ( i = 0; i < NR_PERFCTRS; i++ ) 
    {
        printk("%-32s  ",  perfc_info[i].name);
        switch ( perfc_info[i].type )
        {
        case TYPE_SINGLE:
        case TYPE_S_SINGLE:
            printk("TOTAL[%10d]", atomic_read(&counters[0]));
            counters += 1;
            break;
        case TYPE_CPU:
        case TYPE_S_CPU:
            sum = 0;
            for_each_online_cpu ( j )
                sum += atomic_read(&counters[j]);
            printk("TOTAL[%10u]", sum);
            if (sum)
            {
                for_each_online_cpu ( j )
                    printk("  CPU%02d[%10d]", j, atomic_read(&counters[j]));
            }
            counters += NR_CPUS;
            break;
        case TYPE_ARRAY:
        case TYPE_S_ARRAY:
            for ( j = sum = 0; j < perfc_info[i].nr_elements; j++ )
                sum += atomic_read(&counters[j]);
            printk("TOTAL[%10u]", sum);
#ifdef PERF_ARRAYS
            if (sum)
            {
                for ( j = 0; j < perfc_info[i].nr_elements; j++ )
                {
                    if ( (j % 4) == 0 )
                        printk("\n                 ");
                    printk("  ARR%02d[%10d]", j, atomic_read(&counters[j]));
                }
            }
#endif
            counters += j;
            break;
        }
        printk("\n");
    }

    arch_perfc_printall();
}

void perfc_reset(unsigned char key)
{
    unsigned int i, j;
    s_time_t now = NOW();
    atomic_t *counters = (atomic_t *)&perfcounters;

    if ( key != '\0' )
        printk("Xen performance counters RESET (now = 0x%08X:%08X)\n",
               (u32)(now>>32), (u32)now);

    /* leave STATUS counters alone -- don't reset */

    for ( i = 0; i < NR_PERFCTRS; i++ ) 
    {
        switch ( perfc_info[i].type )
        {
        case TYPE_SINGLE:
            atomic_set(&counters[0],0);
        case TYPE_S_SINGLE:
            counters += 1;
            break;
        case TYPE_CPU:
            for ( j = 0; j < NR_CPUS; j++ )
                atomic_set(&counters[j],0);
        case TYPE_S_CPU:
            counters += NR_CPUS;
            break;
        case TYPE_ARRAY:
            for ( j = 0; j < perfc_info[i].nr_elements; j++ )
                atomic_set(&counters[j],0);
        case TYPE_S_ARRAY:
            counters += perfc_info[i].nr_elements;
            break;
        }
    }

    arch_perfc_reset ();
}

static xen_sysctl_perfc_desc_t perfc_d[NR_PERFCTRS];
static xen_sysctl_perfc_val_t *perfc_vals;
static int               perfc_nbr_vals;
static int               perfc_init = 0;
static int perfc_copy_info(XEN_GUEST_HANDLE_64(xen_sysctl_perfc_desc_t) desc,
                           XEN_GUEST_HANDLE_64(xen_sysctl_perfc_val_t) val)
{
    unsigned int i, j;
    unsigned int v = 0;
    atomic_t *counters = (atomic_t *)&perfcounters;

    /* We only copy the name and array-size information once. */
    if ( !perfc_init ) 
    {
        for ( i = 0; i < NR_PERFCTRS; i++ )
        {
            safe_strcpy(perfc_d[i].name, perfc_info[i].name);

            switch ( perfc_info[i].type )
            {
            case TYPE_SINGLE:
            case TYPE_S_SINGLE:
                perfc_d[i].nr_vals = 1;
                break;
            case TYPE_CPU:
            case TYPE_S_CPU:
                perfc_d[i].nr_vals = num_online_cpus();
                break;
            case TYPE_ARRAY:
            case TYPE_S_ARRAY:
                perfc_d[i].nr_vals = perfc_info[i].nr_elements;
                break;
            }
            perfc_nbr_vals += perfc_d[i].nr_vals;
        }
        perfc_vals = xmalloc_array(xen_sysctl_perfc_val_t, perfc_nbr_vals);
        perfc_init = 1;
    }

    if ( guest_handle_is_null(desc) )
        return 0;

    if ( perfc_vals == NULL )
        return -ENOMEM;

    /* Architecture may fill counters from hardware.  */
    arch_perfc_gather();

    /* We gather the counts together every time. */
    for ( i = 0; i < NR_PERFCTRS; i++ )
    {
        switch ( perfc_info[i].type )
        {
        case TYPE_SINGLE:
        case TYPE_S_SINGLE:
            perfc_vals[v++] = atomic_read(&counters[0]);
            counters += 1;
            break;
        case TYPE_CPU:
        case TYPE_S_CPU:
            for ( j = 0; j < perfc_d[i].nr_vals; j++ )
                perfc_vals[v++] = atomic_read(&counters[j]);
            counters += NR_CPUS;
            break;
        case TYPE_ARRAY:
        case TYPE_S_ARRAY:
            for ( j = 0; j < perfc_d[i].nr_vals; j++ )
                perfc_vals[v++] = atomic_read(&counters[j]);
            counters += perfc_info[i].nr_elements;
            break;
        }
    }
    BUG_ON(v != perfc_nbr_vals);

    if ( copy_to_guest(desc, (xen_sysctl_perfc_desc_t *)perfc_d, NR_PERFCTRS) )
        return -EFAULT;
    if ( copy_to_guest(val, perfc_vals, perfc_nbr_vals) )
        return -EFAULT;
    return 0;
}

/* Dom0 control of perf counters */
int perfc_control(xen_sysctl_perfc_op_t *pc)
{
    static DEFINE_SPINLOCK(lock);
    int rc;

    spin_lock(&lock);

    switch ( pc->cmd )
    {
    case XEN_SYSCTL_PERFCOP_reset:
        perfc_copy_info(pc->desc, pc->val);
        perfc_reset(0);
        rc = 0;
        break;

    case XEN_SYSCTL_PERFCOP_query:
        perfc_copy_info(pc->desc, pc->val);
        rc = 0;
        break;

    default:
        rc = -EINVAL;
        break;
    }

    spin_unlock(&lock);

    pc->nr_counters = NR_PERFCTRS;
    pc->nr_vals = perfc_nbr_vals;

    return rc;
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
