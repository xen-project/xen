
#include <xen/lib.h>
#include <xen/smp.h>
#include <xen/time.h>
#include <xen/perfc.h>
#include <xen/keyhandler.h> 
#include <xen/spinlock.h>
#include <xen/mm.h>
#include <xen/guest_access.h>
#include <public/dom0_ops.h>

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
    int i, j, sum;
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
            printk("TOTAL[%10d]  ", sum);
            for_each_online_cpu ( j )
                printk("CPU%02d[%10d]  ", j, atomic_read(&counters[j]));
            counters += NR_CPUS;
            break;
        case TYPE_ARRAY:
        case TYPE_S_ARRAY:
            for ( j = sum = 0; j < perfc_info[i].nr_elements; j++ )
                sum += atomic_read(&counters[j]);
            printk("TOTAL[%10d]  ", sum);
#ifdef PERF_ARRAYS
            for ( j = 0; j < perfc_info[i].nr_elements; j++ )
            {
                if ( (j != 0) && ((j % 4) == 0) )
                    printk("\n                   ");
                printk("ARR%02d[%10d]  ", j, atomic_read(&counters[j]));
            }
#endif
            counters += j;
            break;
        }
        printk("\n");
    }

#ifdef PERF_ARRAYS
    ptwr_eip_stat_print();
#endif
}

void perfc_reset(unsigned char key)
{
    int i, j;
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

#ifdef PERF_ARRAYS
    ptwr_eip_stat_reset();
#endif
}

static dom0_perfc_desc_t perfc_d[NR_PERFCTRS];
static int               perfc_init = 0;
static int perfc_copy_info(XEN_GUEST_HANDLE(dom0_perfc_desc_t) desc)
{
    unsigned int i, j;
    atomic_t *counters = (atomic_t *)&perfcounters;

    if ( guest_handle_is_null(desc) )
        return 0;

    /* We only copy the name and array-size information once. */
    if ( !perfc_init ) 
    {
        for ( i = 0; i < NR_PERFCTRS; i++ )
        {
            strncpy(perfc_d[i].name, perfc_info[i].name,
                    sizeof(perfc_d[i].name));
            perfc_d[i].name[sizeof(perfc_d[i].name)-1] = '\0';

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

            if ( perfc_d[i].nr_vals > ARRAY_SIZE(perfc_d[i].vals) )
                perfc_d[i].nr_vals = ARRAY_SIZE(perfc_d[i].vals);
        }

        perfc_init = 1;
    }

    /* We gather the counts together every time. */
    for ( i = 0; i < NR_PERFCTRS; i++ )
    {
        switch ( perfc_info[i].type )
        {
        case TYPE_SINGLE:
        case TYPE_S_SINGLE:
            perfc_d[i].vals[0] = atomic_read(&counters[0]);
            counters += 1;
            break;
        case TYPE_CPU:
        case TYPE_S_CPU:
            for ( j = 0; j < perfc_d[i].nr_vals; j++ )
                perfc_d[i].vals[j] = atomic_read(&counters[j]);
            counters += NR_CPUS;
            break;
        case TYPE_ARRAY:
        case TYPE_S_ARRAY:
            for ( j = 0; j < perfc_d[i].nr_vals; j++ )
                perfc_d[i].vals[j] = atomic_read(&counters[j]);
            counters += perfc_info[i].nr_elements;
            break;
        }
    }

    return (copy_to_guest(desc, (dom0_perfc_desc_t *)perfc_d, NR_PERFCTRS) ?
            -EFAULT : 0);
}

/* Dom0 control of perf counters */
int perfc_control(dom0_perfccontrol_t *pc)
{
    static spinlock_t lock = SPIN_LOCK_UNLOCKED;
    u32 op = pc->op;
    int rc;

    pc->nr_counters = NR_PERFCTRS;

    spin_lock(&lock);

    switch ( op )
    {
    case DOM0_PERFCCONTROL_OP_RESET:
        perfc_copy_info(pc->desc);
        perfc_reset(0);
        rc = 0;
        break;

    case DOM0_PERFCCONTROL_OP_QUERY:
        perfc_copy_info(pc->desc);
        rc = 0;
        break;

    default:
        rc = -EINVAL;
        break;
    }

    spin_unlock(&lock);

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
