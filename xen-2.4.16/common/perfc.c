/*
 * xen performance counters
 */

#include <xeno/perfc.h>
#include <xeno/keyhandler.h> 

#define PERFCOUNTER( var, name ) "[0]"name"\0",
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
  int num;

  for (loop = 0; loop < sizeof(perfc_name) / sizeof(char *); loop++)
  {
    num = sscanf (perfc_name[loop], "[%d]", &element_size);
    total_size += element_size == 0 ? 1 : element_size;
    if (total_size > offset) break;
  }
  if (loop == sizeof(perfc_name) / sizeof(char *))
  {
    printf ("error: couldn't find variable\n"); 
    return;
  }
  if (element_size == 0)                                   /* single counter */
  {
    printf ("%10ld  0x%08lx  %s\n", counter[0], counter[0],
	    perfc_name[loop] + 2 + num);
  }
  else                                                  /* show entire array */
  {
    for (loop = 0; loop < element_size; loop++)
    {
      printf ("%10ld  0x%08lx  %s:%d\n", 
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
  int num;
  unsigned long *counters = (unsigned long *)&perfcounters;

  printf ("xen performance counters\n");
  for (loop = 0; loop < sizeof(perfc_name) / sizeof(char *); loop++)
  {
    num = sscanf (perfc_name[loop], "[%d]", &element_size);
    
    for (idx = 0; idx < (element_size ? element_size : 1); idx++)
    {
      if (element_size)
      {
	printf ("%10ld  0x%08lx  %s:%d\n", 
		*counters, *counters, perfc_name[loop] + num + 2, idx);
      }
      else
      {
	printf ("%10ld  0x%08lx  %s\n", 
		*counters, *counters, perfc_name[loop] + num + 2);
      }
      counters++;
    }
  }

  return;
}
