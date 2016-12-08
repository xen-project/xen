#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <xen/xen.h>

#include "x86_emulate.h"

static unsigned char data[4096];
static unsigned int data_index;
static unsigned int data_max;

static int data_read(const char *why, void *dst, unsigned int bytes)
{
    unsigned int i;

    if ( data_index + bytes > data_max )
        return X86EMUL_EXCEPTION;

    memcpy(dst,  data + data_index, bytes);
    data_index += bytes;

    printf("%s: ", why);
    for ( i = 0; i < bytes; i++ )
        printf(" %02x", *(unsigned char *)(dst + i));
    printf("\n");

    return X86EMUL_OKAY;
}

static int fuzz_read(
    unsigned int seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    return data_read("read", p_data, bytes);
}

static int fuzz_fetch(
    unsigned int seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    return data_read("fetch", p_data, bytes);
}

static int fuzz_write(
    unsigned int seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int fuzz_cmpxchg(
    unsigned int seg,
    unsigned long offset,
    void *old,
    void *new,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static struct x86_emulate_ops fuzz_emulops = {
    .read       = fuzz_read,
    .insn_fetch = fuzz_fetch,
    .write      = fuzz_write,
    .cmpxchg    = fuzz_cmpxchg,
    .cpuid      = emul_test_cpuid,
    .read_cr    = emul_test_read_cr,
    .get_fpu    = emul_test_get_fpu,
};

#define CANONICALIZE(x)                                   \
    do {                                                  \
        uint64_t _y = (x);                                \
        if ( _y & (1ULL << 47) )                          \
            _y |= (~0ULL) << 48;                          \
        else                                              \
            _y &= (1ULL << 48)-1;                         \
        printf("Canonicalized %" PRIx64 " to %" PRIx64 "\n", x, _y);    \
        (x) = _y;                                       \
    } while( 0 )

#define ADDR_SIZE_SHIFT 60
#define ADDR_SIZE_64 (2ULL << ADDR_SIZE_SHIFT)
#define ADDR_SIZE_32 (1ULL << ADDR_SIZE_SHIFT)
#define ADDR_SIZE_16 (0)

int LLVMFuzzerTestOneInput(const uint8_t *data_p, size_t size)
{
    bool stack_exec;
    struct cpu_user_regs regs = {};
    struct x86_emulate_ctxt ctxt = {
        .regs = &regs,
        .addr_size = 8 * sizeof(void *),
        .sp_size = 8 * sizeof(void *),
    };
    unsigned int nr = 0;
    int rc;
    unsigned int x;
    const uint8_t *p = data_p;

    stack_exec = emul_test_make_stack_executable();
    if ( !stack_exec )
    {
        printf("Warning: Stack could not be made executable (%d).\n", errno);
        return 1;
    }

    /* Reset all global state variables */
    memset(data, 0, sizeof(data));
    data_index = 0;
    data_max = 0;

    nr = size < sizeof(regs) ? size : sizeof(regs);

    memcpy(&regs, p, nr);
    p += sizeof(regs);

    if ( nr < size )
    {
        memcpy(data, p, size - nr);
        data_max = size - nr;
    }

    ctxt.force_writeback = false;

    /* Zero 'private' fields */
    regs.error_code = 0;
    regs.entry_vector = 0;

    /* Use the upper bits of regs.eip to determine addr_size */
    x = (regs.rip >> ADDR_SIZE_SHIFT) & 0x3;
    if ( x == 3 )
        x = 2;
    ctxt.addr_size = 16 << x;
    printf("addr_size: %d\n", ctxt.addr_size);

    /* Use the upper bit of regs.rsp to determine sp_size (if appropriate) */
    if ( ctxt.addr_size == 64 )
        ctxt.sp_size = 64;
    else
    {
        /* If addr_size isn't 64-bits, sp_size can only be 16 or 32 bits */
        x = (regs.rsp >> ADDR_SIZE_SHIFT) & 0x1;
        ctxt.sp_size = 16 << x;
    }
    printf("sp_size: %d\n", ctxt.sp_size);
    CANONICALIZE(regs.rip);
    CANONICALIZE(regs.rsp);
    CANONICALIZE(regs.rbp);

    /* Zero all segments for now */
    regs.cs = regs.ss = regs.es = regs.ds = regs.fs = regs.gs = 0;

    do {
        rc = x86_emulate(&ctxt, &fuzz_emulops);
        printf("Emulation result: %d\n", rc);
    } while ( rc == X86EMUL_OKAY );

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
