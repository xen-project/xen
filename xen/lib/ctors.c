#include <xen/init.h>
#include <xen/lib.h>

typedef void (*ctor_func_t)(void);
extern const ctor_func_t __ctors_start[], __ctors_end[];

void __init init_constructors(void)
{
    const ctor_func_t *f;
    for ( f = __ctors_start; f < __ctors_end; ++f )
        (*f)();

    /* Putting this here seems as good (or bad) as any other place. */
    BUILD_BUG_ON(sizeof(size_t) != sizeof(ssize_t));
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
