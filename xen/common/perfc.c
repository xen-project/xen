
#include <xeno/lib.h>
#include <xeno/smp.h>
#include <xeno/time.h>
#include <xeno/perfc.h>
#include <xeno/keyhandler.h> 

#undef  PERFCOUNTER
#undef  PERFCOUNTER_CPU
#undef  PERFCOUNTER_ARRAY
#define PERFCOUNTER( var, name )              { name, TYPE_SINGLE, 0 },
#define PERFCOUNTER_CPU( var, name )          { name, TYPE_CPU,    0 },
#define PERFCOUNTER_ARRAY( var, name, size )  { name, TYPE_ARRAY,  size },
static struct {
    char *name;
    enum { TYPE_SINGLE, TYPE_CPU, TYPE_ARRAY } type;
    int nr_elements;
} perfc_info[] = {
#include <xeno/perfc_defn.h>
};

#define NR_PERFCTRS (sizeof(perfc_info) / sizeof(perfc_info[0]))

struct perfcounter_t perfcounters;

void perfc_printall(u_char key, void *dev_id, struct pt_regs *regs)
{
    int i, j;
    s_time_t now = NOW();
    atomic_t *counters = (atomic_t *)&perfcounters;

    printk("Xen performance counters SHOW  (now = 0x%08X:%08X)\n",
           (u32)(now>>32), (u32)now);

    for ( i = 0; i < NR_PERFCTRS; i++ ) 
    {
        switch ( perfc_info[i].type )
        {
        case TYPE_SINGLE:
            printk("%10d  0x%08x  %s\n", 
                   atomic_read(&counters[0]), atomic_read(&counters[0]), 
                   perfc_info[i].name);
            counters += 1;
            break;
        case TYPE_CPU:
            for ( j = 0; j < smp_num_cpus; j++ )
                printk("%10d  0x%08x  %s[CPU %02d]\n",
                       atomic_read(&counters[j]), atomic_read(&counters[j]), 
                       perfc_info[i].name, j);
            counters += NR_CPUS;
            break;
        case TYPE_ARRAY:
            for ( j = 0; j < perfc_info[i].nr_elements; j++ )
                printk("%10d  0x%08x  %s[ARR %02d]\n",
                       atomic_read(&counters[j]), atomic_read(&counters[j]), 
                       perfc_info[i].name, j);
            counters += j;
            break;
        }
    }
}

void perfc_reset(u_char key, void *dev_id, struct pt_regs *regs)
{
    s_time_t now = NOW();
    printk("Xen performance counters RESET (now = 0x%08X:%08X)\n",
           (u32)(now>>32), (u32)now);
    memset(&perfcounters, 0, sizeof(perfcounters));
}

