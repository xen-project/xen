/* 
 * A very(!) simple program to kill a domain. (c) Boris Dragovic
 * Usage: <executable> <mem_kb> <os image> <num_vifs> 
 */

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "dom0_ops.h"
#include "dom0_defs.h"

#define PERR_STRING "Xen Domain Killer"

static int do_kill_domain(int dom_id)
{
    char cmd_path[MAX_PATH];
    dom0_op_t dop;
    int cmd_fd;

    dop.cmd = DOM0_KILLDOMAIN;
    dop.u.killdomain.domain = dom_id;

    /* open the /proc command interface */
    sprintf(cmd_path, "%s%s%s%s", "/proc/", PROC_XENO_ROOT, "/", PROC_CMD);
    cmd_fd = open(cmd_path, O_WRONLY);
    if(cmd_fd < 0){
        perror(PERR_STRING);
        return -1;
    }

    write(cmd_fd, &dop, sizeof(dom0_op_t));
    close(cmd_fd);

    return 0;
}

int main(int argc, char **argv)
{
    int ret;

    if(argc < 2){
        printf("Usage: kill_domain <domain_id>\n");
        ret = -1;
        goto out;
    }

    ret = do_kill_domain(atoi(argv[1]));

out:
    return ret;
}
