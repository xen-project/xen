/*
 * console.c
 *
 * read domain console output buffer ring in Xen 
 *
 */

#include <xeno/console.h>
#include <asm-i386/uaccess.h>

void init_console_ring()
{
    console_ring.len = 0;
}

long read_console_ring(char *str, unsigned int count)
{
    unsigned int len;
    
    len = (console_ring.len < count)? console_ring.len : count;
    
    if ( copy_to_user(str, console_ring.buf, len) )
        return -EFAULT;

    return len;
}
