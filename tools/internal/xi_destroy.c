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

/***********************************************************************/

static char *argv0 = "internal_domain_stop";

static void ERROR (char *message)
{
  fprintf (stderr, "%s: %s\n", argv0, message);
  exit (-1);
}

static void PERROR (char *message)
{
  fprintf (stderr, "%s: %s (%s)\n", argv0, message, sys_errlist[errno]);
  exit (-1);
}

/***********************************************************************/

static int do_kill_domain(int dom_id, int force)
{
    char cmd_path[MAX_PATH];
    dom0_op_t dop;
    int cmd_fd;

    dop.cmd = DOM0_DESTROYDOMAIN;
    dop.u.killdomain.domain = dom_id;
    dop.u.killdomain.force  = force;

    /* open the /proc command interface */
    sprintf(cmd_path, "%s%s%s%s", "/proc/", PROC_XENO_ROOT, "/", PROC_CMD);
    cmd_fd = open(cmd_path, O_WRONLY);
    if(cmd_fd < 0){
        PERROR ("Count not open PROC_CMD interface");
    }

    write(cmd_fd, &dop, sizeof(dom0_op_t));
    close(cmd_fd);

    return 0;
}

int main(int argc, char **argv)
{
  int ret;

  if (argv[0] != NULL) 
    {
      argv0 = argv[0];
    }

  if ( (argc < 2) || (argc > 3) )
    {
    usage:
        fprintf(stderr, "Usage: %s [-f] <domain_id>\n", argv0);
        fprintf(stderr, " -f: Forces immediate destruction of specified domain\n");
        ret = -1;
        goto out;
    }

    if ( (argc == 3) && strcmp("-f", argv[1]) ) goto usage;

    ret = do_kill_domain(atoi(argv[argc-1]), argc == 3);

out:
    return ret;
}
