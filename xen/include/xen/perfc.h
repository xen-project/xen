
#ifndef __XEN_PERFC_H__
#define __XEN_PERFC_H__

#include <asm/atomic.h>

/* 
 * NOTE: new counters must be defined in perfc_defn.h
 * 
 * PERFCOUNTER (counter, string)              define a new performance counter
 * PERFCOUNTER_CPU (counter, string, size)    define a counter per CPU
 * PERFCOUNTER_ARRY (counter, string, size)   define an array of counters
 * 
 * unsigned long perfc_value  (counter)        get value of a counter  
 * unsigned long perfc_valuec (counter)        get value of a per CPU counter
 * unsigned long perfc_valuea (counter, index) get value of an array counter
 * unsigned long perfc_set  (counter, val)     set value of a counter  
 * unsigned long perfc_setc (counter, val)     set value of a per CPU counter
 * unsigned long perfc_seta (counter, index, val) set value of an array counter
 * void perfc_incr  (counter)                  increment a counter          
 * void perfc_incrc (counter, index)           increment a per CPU counter   
 * void perfc_incra (counter, index)           increment an array counter   
 * void perfc_add   (counter, value)           add a value to a counter     
 * void perfc_addc  (counter, value)           add a value to a per CPU counter
 * void perfc_adda  (counter, index, value)    add a value to array counter 
 * void perfc_print (counter)                  print out the counter
 */

#define PERFCOUNTER( var, name ) \
  atomic_t var[1];
#define PERFCOUNTER_CPU( var, name ) \
  atomic_t var[NR_CPUS];
#define PERFCOUNTER_ARRAY( var, name, size ) \
  atomic_t var[size];

struct perfcounter_t 
{
#include <xen/perfc_defn.h>
};

extern struct perfcounter_t perfcounters;

#define perfc_value(x)    atomic_read(&perfcounters.x[0])
#define perfc_valuec(x)   atomic_read(&perfcounters.x[smp_processor_id()])
#define perfc_valuea(x,y) atomic_read(&perfcounters.x[y])
#define perfc_set(x,v)    atomic_set(&perfcounters.x[0], v)
#define perfc_setc(x,v)   atomic_set(&perfcounters.x[smp_processor_id()], v)
#define perfc_seta(x,y,v) atomic_set(&perfcounters.x[y], v)
#define perfc_incr(x)     atomic_inc(&perfcounters.x[0])
#define perfc_incrc(x)    atomic_inc(&perfcounters.x[smp_processor_id()])
#define perfc_incra(x,y)  atomic_inc(&perfcounters.x[y])
#define perfc_add(x,y)    atomic_add((y), &perfcounters.x[0])
#define perfc_addc(x,y)   atomic_add((y), &perfcounters.x[smp_processor_id()])
#define perfc_adda(x,y,z) atomic_add((z), &perfcounters.x[y])

#endif /* __XEN_PERFC_H__ */
