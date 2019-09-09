/* Common data structures and functions consumed by hypervisor and toolstack */
#ifndef XEN_LIB_X86_CPUID_H
#define XEN_LIB_X86_CPUID_H

#include <xen/lib/x86/cpuid-autogen.h>

#define FEATURESET_1d     0 /* 0x00000001.edx      */
#define FEATURESET_1c     1 /* 0x00000001.ecx      */
#define FEATURESET_e1d    2 /* 0x80000001.edx      */
#define FEATURESET_e1c    3 /* 0x80000001.ecx      */
#define FEATURESET_Da1    4 /* 0x0000000d:1.eax    */
#define FEATURESET_7b0    5 /* 0x00000007:0.ebx    */
#define FEATURESET_7c0    6 /* 0x00000007:0.ecx    */
#define FEATURESET_e7d    7 /* 0x80000007.edx      */
#define FEATURESET_e8b    8 /* 0x80000008.ebx      */
#define FEATURESET_7d0    9 /* 0x00000007:0.edx    */
#define FEATURESET_7a1   10 /* 0x00000007:1.eax    */

struct cpuid_leaf
{
    uint32_t a, b, c, d;
};

/*
 * Versions of GCC before 5 unconditionally reserve %rBX as the PIC hard
 * register, and are unable to cope with spilling it.  This results in a
 * rather cryptic error:
 *    error: inconsistent operand constraints in an ‘asm’
 *
 * In affected situations, work around the issue by using a separate register
 * to hold the the %rBX output, and xchg twice to leave %rBX preserved around
 * the asm() statement.
 */
#if defined(__PIC__) && __GNUC__ < 5 && !defined(__clang__) && defined(__i386__)
# define XCHG_BX "xchg %%ebx, %[bx];"
# define BX_CON [bx] "=&r"
#elif defined(__PIC__) && __GNUC__ < 5 && !defined(__clang__) && \
    defined(__x86_64__) && (defined(__code_model_medium__) || \
                            defined(__code_model_large__))
# define XCHG_BX "xchg %%rbx, %q[bx];"
# define BX_CON [bx] "=&r"
#else
# define XCHG_BX ""
# define BX_CON "=&b"
#endif

static inline void cpuid_leaf(uint32_t leaf, struct cpuid_leaf *l)
{
    asm ( XCHG_BX
          "cpuid;"
          XCHG_BX
          : "=a" (l->a), BX_CON (l->b), "=&c" (l->c), "=&d" (l->d)
          : "a" (leaf) );
}

static inline void cpuid_count_leaf(
    uint32_t leaf, uint32_t subleaf, struct cpuid_leaf *l)
{
    asm ( XCHG_BX
          "cpuid;"
          XCHG_BX
          : "=a" (l->a), BX_CON (l->b), "=c" (l->c), "=&d" (l->d)
          : "a" (leaf), "c" (subleaf) );
}

#undef BX_CON
#undef XCHG

/**
 * Given the vendor id from CPUID leaf 0, look up Xen's internal integer
 * vendor ID.  Returns X86_VENDOR_UNKNOWN for any unknown vendor.
 */
unsigned int x86_cpuid_lookup_vendor(uint32_t ebx, uint32_t ecx, uint32_t edx);

/**
 * Given Xen's internal vendor ID, return a string suitable for printing.
 * Returns "Unknown" for any unrecognised ID.
 */
const char *x86_cpuid_vendor_to_str(unsigned int vendor);

#define CPUID_GUEST_NR_BASIC      (0xdu + 1)
#define CPUID_GUEST_NR_CACHE      (5u + 1)
#define CPUID_GUEST_NR_FEAT       (1u + 1)
#define CPUID_GUEST_NR_TOPO       (1u + 1)
#define CPUID_GUEST_NR_XSTATE     (62u + 1)
#define CPUID_GUEST_NR_EXTD_INTEL (0x8u + 1)
#define CPUID_GUEST_NR_EXTD_AMD   (0x1cu + 1)
#define CPUID_GUEST_NR_EXTD       MAX(CPUID_GUEST_NR_EXTD_INTEL, \
                                      CPUID_GUEST_NR_EXTD_AMD)

/*
 * Maximum number of leaves a struct cpuid_policy turns into when serialised
 * for interaction with the toolstack.  (Sum of all leaves in each union, less
 * the entries in basic which sub-unions hang off of.)
 */
#define CPUID_MAX_SERIALISED_LEAVES                     \
    (CPUID_GUEST_NR_BASIC +                             \
     CPUID_GUEST_NR_FEAT   - !!CPUID_GUEST_NR_FEAT +    \
     CPUID_GUEST_NR_CACHE  - !!CPUID_GUEST_NR_CACHE +   \
     CPUID_GUEST_NR_TOPO   - !!CPUID_GUEST_NR_TOPO +    \
     CPUID_GUEST_NR_XSTATE - !!CPUID_GUEST_NR_XSTATE +  \
     CPUID_GUEST_NR_EXTD + 2 /* hv_limit and hv2_limit */ )

struct cpuid_policy
{
#define DECL_BITFIELD(word) _DECL_BITFIELD(FEATURESET_ ## word)
#define _DECL_BITFIELD(x)   __DECL_BITFIELD(x)
#define __DECL_BITFIELD(x)  CPUID_BITFIELD_ ## x

    /* Basic leaves: 0x000000xx */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_BASIC];
        struct {
            /* Leaf 0x0 - Max and vendor. */
            uint32_t max_leaf, vendor_ebx, vendor_ecx, vendor_edx;

            /* Leaf 0x1 - Family/model/stepping and features. */
            uint32_t raw_fms;
            uint8_t :8,       /* Brand ID. */
                clflush_size, /* Number of 8-byte blocks per cache line. */
                lppp,         /* Logical processors per package. */
                apic_id;      /* Initial APIC ID. */
            union {
                uint32_t _1c;
                struct { DECL_BITFIELD(1c); };
            };
            union {
                uint32_t _1d;
                struct { DECL_BITFIELD(1d); };
            };

            /* Leaf 0x2 - TLB/Cache/Prefetch. */
            uint8_t l2_nr_queries; /* Documented as fixed to 1. */
            uint8_t l2_desc[15];

            uint64_t :64, :64; /* Leaf 0x3 - PSN. */
            uint64_t :64, :64; /* Leaf 0x4 - Structured Cache. */
            uint64_t :64, :64; /* Leaf 0x5 - MONITOR. */
            uint64_t :64, :64; /* Leaf 0x6 - Therm/Perf. */
            uint64_t :64, :64; /* Leaf 0x7 - Structured Features. */
            uint64_t :64, :64; /* Leaf 0x8 - rsvd */
            uint64_t :64, :64; /* Leaf 0x9 - DCA */

            /* Leaf 0xa - Intel PMU. */
            uint8_t pmu_version, _pmu[15];

            uint64_t :64, :64; /* Leaf 0xb - Topology. */
            uint64_t :64, :64; /* Leaf 0xc - rsvd */
            uint64_t :64, :64; /* Leaf 0xd - XSTATE. */
        };
    } basic;

    /* Structured cache leaf: 0x00000004[xx] */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_CACHE];
        struct cpuid_cache_leaf {
            uint32_t /* a */ type:5, level:3;
            bool self_init:1, fully_assoc:1;
            uint32_t :4, threads_per_cache:12, cores_per_package:6;
            uint32_t /* b */ line_size:12, partitions:10, ways:10;
            uint32_t /* c */ sets;
            bool /* d */ wbinvd:1, inclusive:1, complex:1;
        } subleaf[CPUID_GUEST_NR_CACHE];
    } cache;

    /* Structured feature leaf: 0x00000007[xx] */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_FEAT];
        struct {
            /* Subleaf 0. */
            uint32_t max_subleaf;
            union {
                uint32_t _7b0;
                struct { DECL_BITFIELD(7b0); };
            };
            union {
                uint32_t _7c0;
                struct { DECL_BITFIELD(7c0); };
            };
            union {
                uint32_t _7d0;
                struct { DECL_BITFIELD(7d0); };
            };
        };
        struct {
            /* Subleaf 1. */
            union {
                uint32_t _7a1;
                struct { DECL_BITFIELD(7a1); };
            };
        };
    } feat;

    /* Extended topology enumeration: 0x0000000B[xx] */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_TOPO];
        struct cpuid_topo_leaf {
            uint32_t id_shift:5, :27;
            uint16_t nr_logical, :16;
            uint8_t level, type, :8, :8;
            uint32_t x2apic_id;
        } subleaf[CPUID_GUEST_NR_TOPO];
    } topo;

    /* Xstate feature leaf: 0x0000000D[xx] */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_XSTATE];

        struct {
            /* Subleaf 0. */
            uint32_t xcr0_low, /* b */:32, max_size, xcr0_high;

            /* Subleaf 1. */
            union {
                uint32_t Da1;
                struct { DECL_BITFIELD(Da1); };
            };
            uint32_t /* b */:32, xss_low, xss_high;
        };

        /* Per-component common state.  Valid for i >= 2. */
        struct {
            uint32_t size, offset;
            bool xss:1, align:1;
            uint32_t _res_d;
        } comp[CPUID_GUEST_NR_XSTATE];
    } xstate;

    /* Extended leaves: 0x800000xx */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_EXTD];
        struct {
            /* Leaf 0x80000000 - Max and vendor. */
            uint32_t max_leaf, vendor_ebx, vendor_ecx, vendor_edx;

            /* Leaf 0x80000001 - Family/model/stepping and features. */
            uint32_t raw_fms, /* b */:32;
            union {
                uint32_t e1c;
                struct { DECL_BITFIELD(e1c); };
            };
            union {
                uint32_t e1d;
                struct { DECL_BITFIELD(e1d); };
            };

            uint64_t :64, :64; /* Brand string. */
            uint64_t :64, :64; /* Brand string. */
            uint64_t :64, :64; /* Brand string. */
            uint64_t :64, :64; /* L1 cache/TLB. */
            uint64_t :64, :64; /* L2/3 cache/TLB. */

            /* Leaf 0x80000007 - Advanced Power Management. */
            uint32_t /* a */:32, /* b */:32, /* c */:32;
            union {
                uint32_t e7d;
                struct { DECL_BITFIELD(e7d); };
            };

            /* Leaf 0x80000008 - Misc addr/feature info. */
            uint8_t maxphysaddr, maxlinaddr, :8, :8;
            union {
                uint32_t e8b;
                struct { DECL_BITFIELD(e8b); };
            };
            uint32_t nc:8, :4, apic_id_size:4, :16;
            uint32_t /* d */:32;
        };
    } extd;

#undef __DECL_BITFIELD
#undef _DECL_BITFIELD
#undef DECL_BITFIELD

    /* Toolstack selected Hypervisor max_leaf (if non-zero). */
    uint8_t hv_limit, hv2_limit;

    /* Value calculated from raw data above. */
    uint8_t x86_vendor;
};

/* Fill in a featureset bitmap from a CPUID policy. */
static inline void cpuid_policy_to_featureset(
    const struct cpuid_policy *p, uint32_t fs[FEATURESET_NR_ENTRIES])
{
    fs[FEATURESET_1d]  = p->basic._1d;
    fs[FEATURESET_1c]  = p->basic._1c;
    fs[FEATURESET_e1d] = p->extd.e1d;
    fs[FEATURESET_e1c] = p->extd.e1c;
    fs[FEATURESET_Da1] = p->xstate.Da1;
    fs[FEATURESET_7b0] = p->feat._7b0;
    fs[FEATURESET_7c0] = p->feat._7c0;
    fs[FEATURESET_e7d] = p->extd.e7d;
    fs[FEATURESET_e8b] = p->extd.e8b;
    fs[FEATURESET_7d0] = p->feat._7d0;
    fs[FEATURESET_7a1] = p->feat._7a1;
}

/* Fill in a CPUID policy from a featureset bitmap. */
static inline void cpuid_featureset_to_policy(
    const uint32_t fs[FEATURESET_NR_ENTRIES], struct cpuid_policy *p)
{
    p->basic._1d  = fs[FEATURESET_1d];
    p->basic._1c  = fs[FEATURESET_1c];
    p->extd.e1d   = fs[FEATURESET_e1d];
    p->extd.e1c   = fs[FEATURESET_e1c];
    p->xstate.Da1 = fs[FEATURESET_Da1];
    p->feat._7b0  = fs[FEATURESET_7b0];
    p->feat._7c0  = fs[FEATURESET_7c0];
    p->extd.e7d   = fs[FEATURESET_e7d];
    p->extd.e8b   = fs[FEATURESET_e8b];
    p->feat._7d0  = fs[FEATURESET_7d0];
    p->feat._7a1  = fs[FEATURESET_7a1];
}

static inline uint64_t cpuid_policy_xcr0_max(const struct cpuid_policy *p)
{
    return ((uint64_t)p->xstate.xcr0_high << 32) | p->xstate.xcr0_low;
}

static inline uint64_t cpuid_policy_xstates(const struct cpuid_policy *p)
{
    uint64_t val = p->xstate.xcr0_high | p->xstate.xss_high;

    return (val << 32) | p->xstate.xcr0_low | p->xstate.xss_low;
}

const uint32_t *x86_cpuid_lookup_deep_deps(uint32_t feature);

/**
 * Recalculate the content in a CPUID policy which is derived from raw data.
 */
void x86_cpuid_policy_recalc_synth(struct cpuid_policy *p);

/**
 * Fill a CPUID policy using the native CPUID instruction.
 *
 * No sanitisation is performed, but synthesised values are calculated.
 * Values may be influenced by a hypervisor or from masking/faulting
 * configuration.
 */
void x86_cpuid_policy_fill_native(struct cpuid_policy *p);

/**
 * Clear leaf data beyond the policies max leaf/subleaf settings.
 *
 * Policy serialisation purposefully omits out-of-range leaves, because there
 * are a large number of them due to vendor differences.  However, when
 * constructing new policies (e.g. levelling down), it is possible to end up
 * with out-of-range leaves with stale content in them.  This helper clears
 * them.
 */
void x86_cpuid_policy_clear_out_of_range_leaves(struct cpuid_policy *p);

#ifdef __XEN__
#include <public/arch-x86/xen.h>
typedef XEN_GUEST_HANDLE_64(xen_cpuid_leaf_t) cpuid_leaf_buffer_t;
#else
#include <xen/arch-x86/xen.h>
typedef xen_cpuid_leaf_t cpuid_leaf_buffer_t[];
#endif

/**
 * Serialise a cpuid_policy object into an array of cpuid leaves.
 *
 * @param policy     The cpuid_policy to serialise.
 * @param leaves     The array of leaves to serialise into.
 * @param nr_entries The number of entries in 'leaves'.
 * @returns -errno
 *
 * Writes at most CPUID_MAX_SERIALISED_LEAVES.  May fail with -ENOBUFS if the
 * leaves array is too short.  On success, nr_entries is updated with the
 * actual number of leaves written.
 */
int x86_cpuid_copy_to_buffer(const struct cpuid_policy *policy,
                             cpuid_leaf_buffer_t leaves, uint32_t *nr_entries);

/**
 * Unserialise a cpuid_policy object from an array of cpuid leaves.
 *
 * @param policy      The cpuid_policy to unserialise into.
 * @param leaves      The array of leaves to unserialise from.
 * @param nr_entries  The number of entries in 'leaves'.
 * @param err_leaf    Optional hint for error diagnostics.
 * @param err_subleaf Optional hint for error diagnostics.
 * @returns -errno
 *
 * Reads at most CPUID_MAX_SERIALISED_LEAVES.  May return -ERANGE if an
 * incoming leaf is out of range of cpuid_policy, in which case the optional
 * err_* pointers will identify the out-of-range indicies.
 *
 * No content validation of in-range leaves is performed.  Synthesised data is
 * recalculated.
 */
int x86_cpuid_copy_from_buffer(struct cpuid_policy *policy,
                               const cpuid_leaf_buffer_t leaves,
                               uint32_t nr_entries, uint32_t *err_leaf,
                               uint32_t *err_subleaf);

#endif /* !XEN_LIB_X86_CPUID_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
