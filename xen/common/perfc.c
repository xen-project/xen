
#include <xen/lib.h>
#include <xen/smp.h>
#include <xen/time.h>
#include <xen/perfc.h>
#include <xen/keyhandler.h> 

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

struct perfcounter_t perfcounters;

void perfc_printall(u_char key, void *dev_id, struct xen_regs *regs)
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
            for ( j = sum = 0; j < smp_num_cpus; j++ )
                sum += atomic_read(&counters[j]);
            printk("TOTAL[%10d]  ", sum);
            for ( j = 0; j < smp_num_cpus; j++ )
                printk("CPU%02d[%10d]  ", j, atomic_read(&counters[j]));
            counters += NR_CPUS;
            break;
        case TYPE_ARRAY:
        case TYPE_S_ARRAY:
            for ( j = sum = 0; j < perfc_info[i].nr_elements; j++ )
                sum += atomic_read(&counters[j]);
            printk("TOTAL[%10d]  ", sum);
            for ( j = 0; j < perfc_info[i].nr_elements; j++ )
                printk("ARR%02d[%10d]  ", j, atomic_read(&counters[j]));
            counters += j;
            break;
        }
        printk("\n");
    }
}

void perfc_reset(u_char key, void *dev_id, struct xen_regs *regs)
{
    int i, j, sum;
    s_time_t now = NOW();
    atomic_t *counters = (atomic_t *)&perfcounters;

    printk("Xen performance counters RESET (now = 0x%08X:%08X)\n",
           (u32)(now>>32), (u32)now);

    // leave STATUS counters alone -- don't reset

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
            for ( j = sum = 0; j < smp_num_cpus; j++ )
	      	atomic_set(&counters[j],0);
        case TYPE_S_CPU:
            counters += NR_CPUS;
            break;
        case TYPE_ARRAY:
            for ( j = sum = 0; j < perfc_info[i].nr_elements; j++ )
	      	atomic_set(&counters[j],0);
        case TYPE_S_ARRAY:
            counters += perfc_info[i].nr_elements;
            break;
        }
    }
}

