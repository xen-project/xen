#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "hypervisor_defs.h"
#include "dom0_ops.h"
#include "dom0_defs.h"
#include "mem_defs.h"

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

static int stop_domain(int id)
{
    dom0_newdomain_t * dom_data;
    char cmd_path[MAX_PATH];
    char dom_id_path[MAX_PATH];
    dom0_op_t dop;
    int cmd_fd;
    int id_fd;

    /* Set up the DOM0_STOPDOMAIN command */
    dop.cmd = DOM0_STOPDOMAIN;
    dop.u.meminfo.domain = id;

    /* open the /proc command interface */
    sprintf(cmd_path, "%s%s%s%s", "/proc/", PROC_XENO_ROOT, "/", PROC_CMD);
    cmd_fd = open(cmd_path, O_WRONLY);
    if(cmd_fd < 0){
        PERROR ("Count not open PROC_CMD interface");
    }

    /* Issue the command */
    write(cmd_fd, &dop, sizeof(dom0_op_t));
    close(cmd_fd);

    return 0;
}    

/***********************************************************************/

int main(int argc, char **argv)
{
  int rc;

  if (argv[0] != NULL) 
    {
      argv0 = argv[0];
    }

  if(argc != 2) 
    {
      fprintf (stderr, "Usage: %s <domain-id>\n", argv0);
      return -1;
    }

  rc = stop_domain(atol(argv[1]));

  return rc;
}
