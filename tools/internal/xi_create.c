/* 
 * XenoDomainBuilder, copyright (c) Boris Dragovic, bd240@cl.cam.ac.uk
 * This code is released under terms and conditions of GNU GPL :).
 * Usage: <executable> <mem_kb> <os image> <num_vifs> 
 */

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>

#include "dom0_ops.h"
#include "dom0_defs.h"
#include "mem_defs.h"
#include "asm-xeno/dom0.h"

/***********************************************************************/

static char *argv0 = "internal_domain_create";

static void ERROR (char *message)
{
  fprintf (stderr, "%s: %s\n", argv0, message);
  exit (-1);
}

static void PERROR (char *message)
{
  fprintf (stderr, "%s: %s (%s)\n", argv0, message, strerror(errno));
  exit (-1);
}

/***********************************************************************/

static int create_new_domain(long req_mem, char *name)
{
    char cmd_path[MAX_PATH];
    int cmd_fd;
    int dom_id;
    struct dom0_createdomain_args argbuf;

    /* open the /proc command interface */
    sprintf(cmd_path, "%s%s%s%s", "/proc/", PROC_XENO_ROOT, "/", PROC_CMD);
    cmd_fd = open(cmd_path, O_RDWR);
    if(cmd_fd < 0){
        PERROR ("Could not open PROC_CMD interface");
        return -1;
    }

    argbuf.kb_mem = req_mem;
    argbuf.name = name;
    dom_id = ioctl(cmd_fd, IOCTL_DOM0_CREATEDOMAIN, &argbuf);
    if (dom_id < 0) {
      PERROR("creating new domain");
    }
    close(cmd_fd);
    return dom_id;
}    

/***********************************************************************/

int main(int argc, char **argv)
{
  int dom_id;

  if (argv[0] != NULL) 
    {
      argv0 = argv[0];
    }

  if(argc != 3) 
    {
      fprintf (stderr, "Usage: %s <kbytes-mem> <domain-name>\n", argv0);
      return -1;
    }

  dom_id = create_new_domain(atol(argv[1]), argv[2]);

  if(dom_id < 0)
    {
      return -1;
    }

  fprintf (stdout, "%d\n", dom_id);
  return 0;
}
