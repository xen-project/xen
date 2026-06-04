/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef XEN_SEQCOUNT_H
#define XEN_SEQCOUNT_H

#include <xen/lib.h>
#include <xen/nospec.h>

#include <asm/atomic.h>
#include <asm/system.h>

/*
 * Sequence counters (seqcount_t)
 *
 * This is the raw counting mechanism, without any writer protection.
 *
 * Write side critical sections must be serialized (and non-preemptible).
 *
 * If readers can be invoked from interrupt contexts, interrupts must also
 * be respectively disabled before entering the write section.
 *
 * This mechanism can't be used if the protected data contains pointers,
 * as the writer can invalidate a pointer that a reader is following.
 */
struct seqcount {
    unsigned int sequence;
};

/*
 * SEQCNT_ZERO() - initializer for seqcount_t
 * @name: Name of the struct seqcount instance
 */
#define SEQCNT_ZERO() { .sequence = 0 }

static inline unsigned int seqprop_sequence(const struct seqcount *s)
{
    return ACCESS_ONCE(s->sequence);
}

/*
 * read_seqcount_begin() - begin a seqcount read critical section
 * @s: Pointer to struct seqcount
 *
 * Return: count to be passed to read_seqcount_retry()
 */
static inline unsigned int _read_seqcount_begin(const struct seqcount *s)
{
    unsigned int seq;

    while ((seq = seqprop_sequence(s)) & 1)
        cpu_relax();

    smp_rmb();

    return seq;
}

static always_inline unsigned int read_seqcount_begin(const struct seqcount *s)
{
    unsigned int seq = _read_seqcount_begin(s);

    block_lock_speculation();

    return seq;
}

/*
 * read_seqcount_retry() - end a seqcount read critical section
 * @s: Pointer to struct seqcount
 * @start: count, from read_seqcount_begin()
 *
 * read_seqcount_retry closes the read critical section of given struct
 * seqcount.  If the critical section was invalid, it must be ignored
 * (and typically retried).
 *
 * Return: true if a read section retry is required, else false
 */
static inline bool _read_seqcount_retry(const struct seqcount *s,
                                        unsigned int start)
{
    smp_rmb();
    return unlikely(seqprop_sequence(s) != start);
}

static always_inline bool read_seqcount_retry(const struct seqcount *s,
                                              unsigned int start)
{
    return lock_evaluate_nospec(_read_seqcount_retry(s, start));
}

/* Loops until a consistent count has been observed across the loop body. */
#define until_seq_read(seq)                                    \
    for ( unsigned int retry_ = 1, count_;                     \
          retry_ && (count_ = read_seqcount_begin(seq), true); \
          retry_ = read_seqcount_retry(seq, count_) )

/*
 * write_seqcount_begin() - start a struct seqcount write side critical section
 * @s: Pointer to struct seqcount
 *
 * Context: sequence counter write side sections must be serialized.
 * If readers can be invoked from interrupt context, interrupts must be
 * respectively disabled.
 */
static inline void write_seqcount_begin(struct seqcount *s)
{
    add_sized(&s->sequence, 1);
    smp_wmb();
}

/*
 * write_seqcount_end() - end a struct seqcount write side critical section
 * @s: Pointer to seqcount
 */
static inline void write_seqcount_end(struct seqcount *s)
{
    smp_wmb();
    add_sized(&s->sequence, 1);
}

/*
 * Not really a loop, but we need write_seqcount_{begin,end}() in the correct
 * position.
 */
#define with_seq_write(seq)                           \
    for ( bool once_ = true;                          \
          once_ && (write_seqcount_begin(seq), true); \
          (write_seqcount_end(seq), once_ = false) )

#endif /* XEN_SEQCOUNT_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
