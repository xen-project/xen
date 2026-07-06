#include <xen/lib.h>
#include <xen/guest_access.h>
#include <xen/err.h>

/*
 * The function copies a string from the guest and checks there's a NUL
 * terminating the string.
 */
char *safe_copy_string_from_guest(XEN_GUEST_HANDLE(char) u_buf,
                                  size_t size, size_t max_size)
{
    char *tmp;

    if ( size > max_size )
        return ERR_PTR(-ENOBUFS);

    tmp = xmalloc_array(char, size);
    if ( !tmp )
        return ERR_PTR(-ENOMEM);

    if ( copy_from_guest(tmp, u_buf, size) )
    {
        xfree(tmp);
        return ERR_PTR(-EFAULT);
    }

    if ( !memchr(tmp, 0, size) )
    {
        xfree(tmp);
        return ERR_PTR(-EMSGSIZE);
    }

    return tmp;
}
