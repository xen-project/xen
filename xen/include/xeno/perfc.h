/*
 * xen performance counters
 */

/* 
 * NOTE: new counters must be defined in xen_perf_defn.h
 * 
 * PERFCOUNTER (counter, string)              define a new performance counter
 * PERFCOUNTER_ARRY (counter, string, size)   define an array of counters
 * 
 * unsigned long perfc_value  (counter)        get value of a counter  
 * unsigned long perfc_valuea (counter, index) get value of an array counter
 * void perfc_incr   (counter)                 increment a counter          
 * void perfc_incra  (counter, index)          increment an array counter   
 * void perfc_add    (counter, value)          add a value to a counter     
 * void perfc_adda   (counter, index, value)   add a value to array counter 
 * void perfc_print  (counter)                 print out the counter
 */

#define PERFCOUNTER( var, name ) \
unsigned long var[1];
#define PERFCOUNTER_ARRAY( var, name, size ) \
unsigned long var[size];

struct perfcounter_t 
{
#include <xeno/perfc_defn.h>
};

extern struct perfcounter_t perfcounters;
extern char *perfc_name[];

#define perf_value(x)    perfcounters.x[0]
#define perf_valuea(x,y) perfcounters.x[y]
#define perf_incr(x)     perfcounters.x[0]++
#define perf_incra(x,y)  perfcounters.x[y]++
#define perf_add(x,y)    perfcounters.x[0]+=(y)
#define perf_adda(x,y,z) perfcounters.x[y]+=(z)

#define perf_print(x) \
  __perfc_print(perfcounters.x, \
	        &perfcounters.x[0] - ((unsigned long *)&perfcounters))

