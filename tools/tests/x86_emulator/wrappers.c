#include <stdarg.h>
#include <stdio.h>

#define WRAP(x) typeof(x) emul_##x
#include "x86-emulate.h"

size_t emul_fwrite(const void *src, size_t sz, size_t n, FILE *f)
{
    emul_save_fpu_state();
    sz = fwrite(src, sz, n, f);
    emul_restore_fpu_state();

    return sz;
}

int emul_memcmp(const void *p1, const void *p2, size_t sz)
{
    int rc;

    emul_save_fpu_state();
    rc = memcmp(p1, p2, sz);
    emul_restore_fpu_state();

    return rc;
}

void *emul_memcpy(void *dst, const void *src, size_t sz)
{
    emul_save_fpu_state();
    memcpy(dst, src, sz);
    emul_restore_fpu_state();

    return dst;
}

void *emul_memset(void *dst, int c, size_t sz)
{
    emul_save_fpu_state();
    memset(dst, c, sz);
    emul_restore_fpu_state();

    return dst;
}

int emul_printf(const char *fmt, ...)
{
    va_list varg;
    int rc;

    emul_save_fpu_state();
    va_start(varg, fmt);
    rc = vprintf(fmt, varg);
    va_end(varg);
    emul_restore_fpu_state();

    return rc;
}

int emul_putchar(int c)
{
    int rc;

    emul_save_fpu_state();
    rc = putchar(c);
    emul_restore_fpu_state();

    return rc;
}

int emul_puts(const char *str)
{
    int rc;

    emul_save_fpu_state();
    rc = puts(str);
    emul_restore_fpu_state();

    return rc;
}
