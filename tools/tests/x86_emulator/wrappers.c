#include <stdarg.h>

#define WRAP(x) typeof(x) __wrap_ ## x, __real_ ## x
#include "x86-emulate.h"

size_t __wrap_fwrite(const void *src, size_t sz, size_t n, FILE *f)
{
    emul_save_fpu_state();
    sz = __real_fwrite(src, sz, n, f);
    emul_restore_fpu_state();

    return sz;
}

int __wrap_memcmp(const void *p1, const void *p2, size_t sz)
{
    int rc;

    emul_save_fpu_state();
    rc = __real_memcmp(p1, p2, sz);
    emul_restore_fpu_state();

    return rc;
}

void *__wrap_memcpy(void *dst, const void *src, size_t sz)
{
    emul_save_fpu_state();
    __real_memcpy(dst, src, sz);
    emul_restore_fpu_state();

    return dst;
}

void *__wrap_memset(void *dst, int c, size_t sz)
{
    emul_save_fpu_state();
    __real_memset(dst, c, sz);
    emul_restore_fpu_state();

    return dst;
}

int __wrap_printf(const char *fmt, ...)
{
    va_list varg;
    int rc;

    emul_save_fpu_state();
    va_start(varg, fmt);
    rc = __real_vprintf(fmt, varg);
    va_end(varg);
    emul_restore_fpu_state();

    return rc;
}

int __wrap_putchar(int c)
{
    int rc;

    emul_save_fpu_state();
    rc = __real_putchar(c);
    emul_restore_fpu_state();

    return rc;
}

int __wrap_puts(const char *str)
{
    int rc;

    emul_save_fpu_state();
    rc = __real_puts(str);
    emul_restore_fpu_state();

    return rc;
}

int __wrap_snprintf(char *buf, size_t n, const char *fmt, ...)
{
    va_list varg;
    int rc;

    emul_save_fpu_state();
    va_start(varg, fmt);
    rc = __real_vsnprintf(buf, n, fmt, varg);
    va_end(varg);
    emul_restore_fpu_state();

    return rc;
}

int __wrap_vsnprintf(char *buf, size_t n, const char *fmt, va_list varg)
{
    int rc;

    emul_save_fpu_state();
    rc = __real_vsnprintf(buf, n, fmt, varg);
    emul_restore_fpu_state();

    return rc;
}

char *__wrap_strstr(const char *s1, const char *s2)
{
    char *s;

    emul_save_fpu_state();
    s = __real_strstr(s1, s2);
    emul_restore_fpu_state();

    return s;
}
