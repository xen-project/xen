
#ifndef __XEN_PERFC_H__
#define __XEN_PERFC_H__

#ifdef PERF_COUNTERS

#include <xen/lib.h>
#include <asm/atomic.h>

/* 
 * NOTE: new counters must be defined in perfc_defn.h
 * 
 * PERFCOUNTER (counter, string)              define a new performance counter
 * PERFCOUNTER_CPU (counter, string, size)    define a counter per CPU
 * PERFCOUNTER_ARRY (counter, string, size)   define an array of counters
 * 
 * unlike "COUNTERS", "STATUS" variables DO NOT RESET
 * PERFSTATUS (counter, string)               define a new performance stauts
 * PERFSTATUS_CPU (counter, string, size)     define a status var per CPU
 * PERFSTATUS_ARRY (counter, string, size)    define an array of status vars
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
#define PERFSTATUS( var, name ) \
  atomic_t var[1];
#define PERFSTATUS_CPU( var, name ) \
  atomic_t var[NR_CPUS];
#define PERFSTATUS_ARRAY( var, name, size ) \
  atomic_t var[size];

struct perfcounter {
#include <xen/perfc_defn.h>
};

extern struct perfcounter perfcounters;

#define perfc_value(x)    atomic_read(&perfcounters.x[0])
#define perfc_valuec(x)   atomic_read(&perfcounters.x[smp_processor_id()])
#define perfc_valuea(x,y)                                               \
    ( (y) < (sizeof(perfcounters.x) / sizeof(*perfcounters.x)) ?	\
	atomic_read(&perfcounters.x[y]) : 0 )
#define perfc_set(x,v)    atomic_set(&perfcounters.x[0], v)
#define perfc_setc(x,v)   atomic_set(&perfcounters.x[smp_processor_id()], v)
#define perfc_seta(x,y,v)                                               \
    do {                                                                \
        if ( (y) < (sizeof(perfcounters.x) / sizeof(*perfcounters.x)) ) \
            atomic_set(&perfcounters.x[y], v);                          \
    } while ( 0 )
#define perfc_incr(x)     atomic_inc(&perfcounters.x[0])
#define perfc_decr(x)     atomic_dec(&perfcounters.x[0])
#define perfc_incrc(x)    atomic_inc(&perfcounters.x[smp_processor_id()])
#define perfc_decrc(x)    atomic_dec(&perfcounters.x[smp_processor_id()])
#define perfc_incra(x,y)                                                \
    do {                                                                \
        if ( (y) < (sizeof(perfcounters.x) / sizeof(*perfcounters.x)) ) \
            atomic_inc(&perfcounters.x[y]);                             \
    } while ( 0 )
#define perfc_add(x,y)    atomic_add((y), &perfcounters.x[0])
#define perfc_addc(x,y)   atomic_add((y), &perfcounters.x[smp_processor_id()])
#define perfc_adda(x,y,z)                                               \
    do {                                                                \
        if ( (y) < (sizeof(perfcounters.x) / sizeof(*perfcounters.x)) ) \
            atomic_add((z), &perfcounters.x[y]);                        \
    } while ( 0 )

/*
 * Histogram: special treatment for 0 and 1 count. After that equally spaced 
 * with last bucket taking the rest.
 */
#ifdef PERF_ARRAYS
#define perfc_incr_histo(_x,_v,_n)                                          \
    do {                                                                    \
        if ( (_v) == 0 )                                                    \
            perfc_incra(_x, 0);                                             \
        else if ( (_v) == 1 )                                               \
            perfc_incra(_x, 1);                                             \
        else if ( (((_v)-2) / PERFC_ ## _n ## _BUCKET_SIZE) <               \
                  (PERFC_MAX_ ## _n - 3) )                                  \
            perfc_incra(_x, (((_v)-2) / PERFC_ ## _n ## _BUCKET_SIZE) + 2); \
        else                                                                \
            perfc_incra(_x, PERFC_MAX_ ## _n - 1);                          \
    } while ( 0 )
#else
#define perfc_incr_histo(_x,_v,_n) ((void)0)
#endif

struct xen_sysctl_perfc_op;
int perfc_control(struct xen_sysctl_perfc_op *);
    
#else /* PERF_COUNTERS */

#define perfc_value(x)    (0)
#define perfc_valuec(x)   (0)
#define perfc_valuea(x,y) (0)
#define perfc_set(x,v)    ((void)0)
#define perfc_setc(x,v)   ((void)0)
#define perfc_seta(x,y,v) ((void)0)
#define perfc_incr(x)     ((void)0)
#define perfc_decr(x)     ((void)0)
#define perfc_incrc(x)    ((void)0)
#define perfc_decrc(x)    ((void)0)
#define perfc_incra(x,y)  ((void)0)
#define perfc_decra(x,y)  ((void)0)
#define perfc_add(x,y)    ((void)0)
#define perfc_addc(x,y)   ((void)0)
#define perfc_adda(x,y,z) ((void)0)
#define perfc_incr_histo(x,y,z) ((void)0)

#endif /* PERF_COUNTERS */

#endif /* __XEN_PERFC_H__ */
