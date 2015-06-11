#ifndef __ANALYZE_H
# define __ANALYZE_H

#include <stdint.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define TRC_GEN_MAIN     0
#define TRC_SCHED_MAIN   1
#define TRC_DOM0OP_MAIN  2
#define TRC_HVM_MAIN     3
#define TRC_MEM_MAIN     4
#define TRC_PV_MAIN      5
#define TRC_SHADOW_MAIN  6
#define TRC_HW_MAIN      7

#define TRC_LOST_RECORDS_END    (TRC_GEN + 50)

#define NR_CPUS 128
#if __x86_64__
# define BITS_PER_LONG 64
#else
# define BITS_PER_LONG 32
#endif

#define BITS_TO_LONGS(bits) \
    (((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#define DECLARE_BITMAP(name,bits) \
    unsigned long name[BITS_TO_LONGS(bits)]
typedef struct cpumask{ DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;

enum {
    TRCE_SFLAG_SET_AD,
    TRCE_SFLAG_SET_A,
    TRCE_SFLAG_SHADOW_L1_GET_REF,
    TRCE_SFLAG_SHADOW_L1_PUT_REF,
    TRCE_SFLAG_L2_PROPAGATE,
    TRCE_SFLAG_SET_CHANGED,
    TRCE_SFLAG_SET_FLUSH,
    TRCE_SFLAG_SET_ERROR,
    TRCE_SFLAG_DEMOTE,
    TRCE_SFLAG_PROMOTE,
    TRCE_SFLAG_WRMAP,
    TRCE_SFLAG_WRMAP_GUESS_FOUND,
    TRCE_SFLAG_WRMAP_BRUTE_FORCE,
    TRCE_SFLAG_EARLY_UNSHADOW,
    TRCE_SFLAG_EMULATION_2ND_PT_WRITTEN,
    TRCE_SFLAG_EMULATION_LAST_FAILED,
    TRCE_SFLAG_EMULATE_FULL_PT,
    TRCE_SFLAG_PREALLOC_UNPIN,
    TRCE_SFLAG_PREALLOC_UNHOOK
};

#define TRC_HVM_OP_DESTROY_PROC (TRC_HVM_HANDLER + 0x100)

typedef unsigned long long tsc_t;

/* -- on-disk trace buffer definitions -- */
struct trace_record {
    union {
        struct {
            unsigned event:28,
                extra_words:3,
                cycle_flag:1;
            union {
                struct {
                    uint32_t tsc_lo, tsc_hi;
                    uint32_t data[7];
                } tsc;
                struct {
                    uint32_t data[7];
                } notsc;
            } u;
        };
        uint32_t raw[8];
    };
};

/* -- General info about a current record -- */
struct time_struct {
    unsigned long long time;
    unsigned int s, ns;
};

#define DUMP_HEADER_MAX 256

struct record_info {
    int cpu;
    tsc_t tsc;
    union {
        unsigned event;
        struct {
            unsigned minor:12,
                sub:4,
                main:12,
                unused:4;
        } evt;
    };
    int extra_words;
    int size;
    uint32_t *d;
    char dump_header[DUMP_HEADER_MAX];
    struct time_struct t;
    struct trace_record rec;
};

#endif
