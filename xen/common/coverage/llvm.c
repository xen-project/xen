/*
 * Copyright (C) 2017 Citrix Systems R&D
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/types.h>

#include "coverage.h"

#ifndef __clang__
#error "LLVM coverage selected without clang compiler"
#endif

#if BITS_PER_LONG == 64
#define LLVM_PROFILE_MAGIC (((uint64_t)255 << 56) | ((uint64_t)'l' << 48) | \
    ((uint64_t)'p' << 40) | ((uint64_t)'r' << 32) | ((uint64_t)'o' << 24) | \
    ((uint64_t)'f' << 16) | ((uint64_t)'r' << 8)  | ((uint64_t)129))
#else
#define LLVM_PROFILE_MAGIC (((uint64_t)255 << 56) | ((uint64_t)'l' << 48) | \
    ((uint64_t)'p' << 40) | ((uint64_t)'r' << 32) | ((uint64_t)'o' << 24) | \
    ((uint64_t)'f' << 16) | ((uint64_t)'R' << 8)  | ((uint64_t)129)
#endif

#if __clang_major__ >= 19 && __clang_major__ <= 20
#define LLVM_PROFILE_VERSION    10
#define LLVM_PROFILE_NUM_KINDS  3
#elif __clang_major__ == 18
#define LLVM_PROFILE_VERSION    9
#define LLVM_PROFILE_NUM_KINDS  2
#elif __clang_major__ >= 14
#define LLVM_PROFILE_VERSION    8
#define LLVM_PROFILE_NUM_KINDS  2
#elif __clang_major__ == 13
#define LLVM_PROFILE_VERSION    7
#define LLVM_PROFILE_NUM_KINDS  2
#elif __clang_major__ >= 11
#define LLVM_PROFILE_VERSION    5
#define LLVM_PROFILE_NUM_KINDS  2
#else
#error "LLVM coverage selected but an unsupported clang version is used"
#endif

struct llvm_profile_data {
    uint64_t name_ref;
    uint64_t function_hash;
    void *relative_counter;
#if LLVM_PROFILE_VERSION >= 9
    void *relative_bitmap;
#endif
    void *function;
    void *values;
    uint32_t nr_counters;
    uint16_t nr_value_sites[LLVM_PROFILE_NUM_KINDS];
#if LLVM_PROFILE_VERSION >= 9
    uint32_t numbitmap_bytes;
#endif
};

struct llvm_profile_header {
    uint64_t magic;
    uint64_t version;
#if LLVM_PROFILE_VERSION >= 7
    uint64_t binary_ids_size;
#endif
    uint64_t num_data;
    uint64_t padding_bytes_before_counters;
    uint64_t num_counters;
    uint64_t padding_bytes_after_counters;
#if LLVM_PROFILE_VERSION >= 9
    uint64_t num_bitmap_bytes;
    uint64_t padding_bytes_after_bitmap_bytes;
#endif
    uint64_t names_size;
    uint64_t counters_delta;
#if LLVM_PROFILE_VERSION >= 9
    uint64_t bitmap_delta;
#endif
    uint64_t names_delta;
#if LLVM_PROFILE_VERSION == 10
    uint64_t num_vtables;
    uint64_t vnames_size;
#endif
    uint64_t value_kind_last;
};

/*
 * Since Xen uses the llvm code coverage support without the run time library
 * __llvm_profile_runtime must be defined according to the docs at:
 *
 * https://clang.llvm.org/docs/SourceBasedCodeCoverage.html 
 */
int __llvm_profile_runtime;

extern const struct llvm_profile_data __start___llvm_prf_data[];
extern const struct llvm_profile_data __stop___llvm_prf_data[];
extern const char __start___llvm_prf_names[];
extern const char __stop___llvm_prf_names[];
extern uint64_t __start___llvm_prf_cnts[];
extern uint64_t __stop___llvm_prf_cnts[];
extern const char __start___llvm_prf_bits[];
extern const char __stop___llvm_prf_bits[];

#define START_DATA      ((const void *)__start___llvm_prf_data)
#define END_DATA        ((const void *)__stop___llvm_prf_data)
#define START_NAMES     ((const void *)__start___llvm_prf_names)
#define END_NAMES       ((const void *)__stop___llvm_prf_names)
#define START_COUNTERS  ((void *)__start___llvm_prf_cnts)
#define END_COUNTERS    ((void *)__stop___llvm_prf_cnts)
#define START_BITMAP    ((void *)__start___llvm_prf_bits)
#define END_BITMAP      ((void *)__stop___llvm_prf_bits)

static void cf_check reset_counters(void)
{
    memset(START_COUNTERS, 0, END_COUNTERS - START_COUNTERS);
    if ( IS_ENABLED(CONFIG_CONDITION_COVERAGE) )
        memset(START_BITMAP, 0, END_BITMAP - START_BITMAP);
}

static uint32_t cf_check get_size(void)
{
    uint32_t size = ROUNDUP(sizeof(struct llvm_profile_header) + END_DATA - START_DATA +
                   END_COUNTERS - START_COUNTERS + END_NAMES - START_NAMES, 8);
    if ( IS_ENABLED(CONFIG_CONDITION_COVERAGE) )
        size += ROUNDUP(END_BITMAP - START_BITMAP, 8);
    return size;
}

static int cf_check dump(
    XEN_GUEST_HANDLE_PARAM(char) buffer, uint32_t *buf_size)
{
    struct llvm_profile_header header = {
        .magic = LLVM_PROFILE_MAGIC,
        .version = LLVM_PROFILE_VERSION,
        .num_data = DIV_ROUND_UP(END_DATA - START_DATA, sizeof(struct llvm_profile_data)),
        .num_counters = DIV_ROUND_UP(END_COUNTERS - START_COUNTERS, sizeof(uint64_t)),
        .names_size = END_NAMES - START_NAMES,
#if LLVM_PROFILE_VERSION >= 8
        .counters_delta = START_COUNTERS - START_DATA,
#else
        .counters_delta = (uintptr_t)START_COUNTERS,
#endif
        .names_delta = (uintptr_t)START_NAMES,
        .value_kind_last = LLVM_PROFILE_NUM_KINDS - 1,
#if defined(CONFIG_CONDITION_COVERAGE) && LLVM_PROFILE_VERSION >= 9
        .num_bitmap_bytes = END_BITMAP - START_BITMAP,
        .bitmap_delta = START_BITMAP - START_DATA,
#endif
    };
    unsigned int off = 0;

#define APPEND_TO_BUFFER(src, size)                             \
({                                                              \
    if ( off + (size) > *buf_size )                             \
        return -ENOMEM;                                         \
    copy_to_guest_offset(buffer, off, (const char *)src, size); \
    off += (size);                                              \
})
    APPEND_TO_BUFFER(&header, sizeof(header));
    APPEND_TO_BUFFER(START_DATA, END_DATA - START_DATA);
    APPEND_TO_BUFFER(START_COUNTERS, END_COUNTERS - START_COUNTERS);
#if defined(CONFIG_CONDITION_COVERAGE)
    APPEND_TO_BUFFER(START_BITMAP, END_BITMAP - START_BITMAP);
#endif
    APPEND_TO_BUFFER(START_NAMES, END_NAMES - START_NAMES);
#undef APPEND_TO_BUFFER

    clear_guest_offset(buffer, off, *buf_size - off);

    return 0;
}

const struct cov_sysctl_ops cov_ops = {
    .get_size = get_size,
    .reset_counters = reset_counters,
    .dump = dump,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
