/*
 * xen performance counters
 */

#include <xeno/lib.h>
#include <xeno/smp.h>
#include <xeno/time.h>
#include <xeno/perfc.h>
#include <xeno/keyhandler.h> 

/* used for different purposes in perfc.h and here */
#undef PERFCOUNTER
#undef PERFCOUNTER_CPU
#undef PERFCOUNTER_ARRAY

#define PERFCOUNTER( var, name ) "[0]"name"\0",
#define PERFCOUNTER_CPU( var, name )  "C"name"\0",
#define PERFCOUNTER_ARRAY( var, name, size )  "["#size"]"name"\0",

char* perfc_name[] = {
#include <xeno/perfc_defn.h>
};

struct perfcounter_t perfcounters;

void __perfc_print (unsigned long counter[], int offset)
{
  int loop;
  int total_size = 0;
  int element_size = 0;
  int cpus = 0;
  int num = 0;

  for (loop = 0; loop < sizeof(perfc_name) / sizeof(char *); loop++) {
      if (perfc_name[loop][0] == 'C') {
          element_size = NR_CPUS;
          cpus = 1;
      } else {
          num = sscanf (perfc_name[loop], "[%d]", &element_size);
      }

      total_size += element_size == 0 ? 1 : element_size;
      if (total_size > offset) break;
  }
  if (loop == sizeof(perfc_name) / sizeof(char *)) {
      printf ("error: couldn't find variable\n"); 
      return;
  }
  if (element_size == 0) {                              /* single counter */
      printf ("%10lu  0x%08lx  %s\n", counter[0], counter[0],
              perfc_name[loop] + 2 + num);
  } else if (cpus) {                                    /* counter per CPU  */
      for (loop = 0; loop < smp_num_cpus; loop++) {
          printf ("%10lu  0x%08lx  cpu[%02d] %s\n", 
                  counter[loop], counter[loop], 
                  loop, perfc_name[loop]);
      }
      
  } else {                                             /* show entire array */
      for (loop = 0; loop < element_size; loop++) {
          printf ("%10lu  0x%08lx  %s:%d\n", 
                  counter[loop], counter[loop], 
                  perfc_name[loop] + 2 + num, loop);
      }
  }
  return;
}

void perfc_printall (u_char key, void *dev_id, struct pt_regs *regs)
{
    int loop, idx;
    int element_size;
    int cpus=0;
    int num = 0;
    s_time_t now = NOW();
    unsigned long *counters = (unsigned long *)&perfcounters;

    printf ("xen performance counters: now=0x%08X%08X\n",
            (u32)(now>>32), (u32)now);

    for (loop = 0; loop < sizeof(perfc_name) / sizeof(char *); loop++) {

        if (perfc_name[loop][0] == 'C') {
            element_size = NR_CPUS;
            cpus = 1;
        } else {
            num = sscanf (perfc_name[loop], "[%d]", &element_size);
        }
    
        for (idx = 0; idx < (element_size ? element_size : 1); idx++) {
            if (cpus) {
                if (idx < smp_num_cpus)
                    printf ("%10ld  0x%08lx  cpu[%02d] %s\n", 
                            *counters, *counters, idx, perfc_name[loop] + 1);
            } else if (element_size) {
                printf ("%10ld  0x%08lx  %s:%d\n", 
                        *counters, *counters, perfc_name[loop] + num + 2, idx);
            } else {
                printf ("%10ld  0x%08lx  %s\n", 
                        *counters, *counters, perfc_name[loop] + num + 2);
            }
            counters++;
        }
    }

    //perfc_reset( key, dev_id, regs );

    return;
}

void perfc_reset (u_char key, void *dev_id, struct pt_regs *regs)
{
    s_time_t now = NOW();
    printk ("xen performance counters reset: now=0x%08X%08X\n",
            (u32)(now>>32), (u32)now);
    memset (&perfcounters, 0, sizeof(perfcounters));
}

