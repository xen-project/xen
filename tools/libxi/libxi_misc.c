/******************************************************************************
 * libxi_misc.c
 * 
 * Miscellaneous control interface functions.
 */

#include "libxi_private.h"

int privcmd_fd = -1;

int xi_interface_open(void)
{
    if ( (privcmd_fd == -1) &&
         ((privcmd_fd = open("/proc/xeno/privcmd", O_RDWR)) < 0) )
    {
        privcmd_fd = -1;
        return -1;
    }
    return 0;
}

int xi_interface_close(void)
{
    if ( privcmd_fd != -1 )
    {
        close(privcmd_fd);
        privcmd_fd = -1;
    }
    return 0;
}


#define CONSOLE_RING_CLEAR	1

int xi_readconsolering(char *str, unsigned int max_chars, int clear)
{
    int ret;
    dom0_op_t op;

    op.cmd = DOM0_READCONSOLE;
    op.u.readconsole.str = (unsigned long)str;
    op.u.readconsole.count = max_chars;
    op.u.readconsole.cmd = clear ? CONSOLE_RING_CLEAR : 0;

    if ( (ret = do_dom0_op(&op)) > 0 )
        str[ret] = '\0';

    return ret;
}    

