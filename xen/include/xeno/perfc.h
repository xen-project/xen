/*
 * xen performance counters
 */

/* 
 * NOTE: new counters must be defined in perfc_defn.h
 * 
 * PERFCOUNTER (counter, string)              define a new performance counter
 * PERFCOUNTER_CPU (counter, string, size)    define a counter per CPU
 * PERFCOUNTER_ARRY (counter, string, size)   define an array of counters
 * 
 * unsigned long perfc_value  (counter)        get value of a counter  
 * unsigned long perfc_valuea (counter, index) get value of an array counter
 * void perfc_incr  (counter)                 increment a counter          
 * void perfc_incrc (counter, index)          increment a per CPU counter   
 * void perfc_incra (counter, index)          increment an array counter   
 * void perfc_add   (counter, value)          add a value to a counter     
 * void perfc_addc  (counter, value)          add a value to a per CPU counter 
 * void perfc_adda  (counter, index, value)   add a value to array counter 
 * void perfc_print (counter)                 print out the counter
 */

#define PERFCOUNTER( var, name ) \
unsigned long var[1];
#define PERFCOUNTER_CPU( var, name ) \
unsigned long var[NR_CPUS];
#define PERFCOUNTER_ARRAY( var, name, size ) \
unsigned long var[size];

struct perfcounter_t 
{
#include <xeno/perfc_defn.h>
};

extern struct perfcounter_t perfcounters;
extern char *perfc_name[];

#define perfc_value(x)    perfcounters.x[0]
#define perfc_valuec(x)   perfcounters.x[smp_processor_id()]
#define perfc_valuea(x,y) perfcounters.x[y]
#define perfc_incr(x)     perfcounters.x[0]++
#define perfc_incrc(x)    perfcounters.x[smp_processor_id()]++
#define perfc_incra(x,y)  perfcounters.x[y]++
#define perfc_add(x,y)    perfcounters.x[0]+=(y)
#define perfc_addc(x,y)   perfcounters.x[smp_processor_id()]+=(y)
#define perfc_adda(x,y,z) perfcounters.x[y]+=(z)

#define perf_print(x) \
  __perfc_print(perfcounters.x, \
	        &perfcounters.x[0] - ((unsigned long *)&perfcounters))

