/******************************************************************************
 * xc_misc.c
 * 
 * Miscellaneous control interface functions.
 */

#include "xc_private.h"

int xc_interface_open(void)
{
    int fd = open("/proc/xeno/privcmd", O_RDWR);
    if ( fd == -1 )
        PERROR("Could not obtain handle on privileged command interface");
    return fd;
}

int xc_interface_close(int xc_handle)
{
    return close(xc_handle);
}


#define CONSOLE_RING_CLEAR	1

int xc_readconsolering(int xc_handle,
                       char *str, 
                       unsigned int max_chars, 
                       int clear)
{
    int ret;
    dom0_op_t op;

    op.cmd = DOM0_READCONSOLE;
    op.u.readconsole.str = (unsigned long)str;
    op.u.readconsole.count = max_chars;
    op.u.readconsole.cmd = clear ? CONSOLE_RING_CLEAR : 0;

    if ( (ret = mlock(str, max_chars)) != 0 )
        return ret;

    if ( (ret = do_dom0_op(xc_handle, &op)) >= 0 )
        str[ret] = '\0';

    (void)munlock(str, max_chars);

    return ret;
}    


int xc_physinfo(int xc_handle,
		xc_physinfo_t *put_info)
{
    int ret;
    dom0_op_t op;
    dom0_physinfo_t *got_info = &op.u.physinfo;
    
    op.cmd = DOM0_PHYSINFO;
    op.interface_version = DOM0_INTERFACE_VERSION;

    if((ret = do_dom0_op(xc_handle, &op))) return ret;

    put_info->ht_per_core = got_info->ht_per_core;
    put_info->cores       = got_info->cores;
    put_info->total_pages = got_info->total_pages;
    put_info->free_pages  = got_info->free_pages;
    put_info->cpu_khz     = got_info->cpu_khz;

    return 0;
}

