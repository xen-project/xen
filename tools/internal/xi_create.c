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

#include "hypervisor_defs.h"
#include "dom0_ops.h"
#include "dom0_defs.h"
#include "mem_defs.h"

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

static dom0_newdomain_t * create_new_domain(long req_mem, char *name)
{
    dom0_newdomain_t * dom_data;
    char cmd_path[MAX_PATH];
    char dom_id_path[MAX_PATH];
    dom0_op_t dop;
    int cmd_fd;
    int id_fd;

    /* open the /proc command interface */
    sprintf(cmd_path, "%s%s%s%s", "/proc/", PROC_XENO_ROOT, "/", PROC_CMD);
    cmd_fd = open(cmd_path, O_WRONLY);
    if(cmd_fd < 0){
        PERROR ("Could not open PROC_CMD interface");
        return 0;
    }

    dop.cmd = DOM0_CREATEDOMAIN;
    dop.u.newdomain.memory_kb = req_mem;
    strncpy (dop.u.newdomain.name, name, MAX_DOMAIN_NAME - 1);
    dop.u.newdomain.name[MAX_DOMAIN_NAME - 1] = 0;

    write(cmd_fd, &dop, sizeof(dom0_op_t));
    close(cmd_fd);

    sprintf(dom_id_path, "%s%s%s%s", "/proc/", PROC_XENO_ROOT, "/", 
        PROC_DOM_DATA);
    while((id_fd = open(dom_id_path, O_RDONLY)) < 0) continue;
    dom_data = (dom0_newdomain_t *)malloc(sizeof(dom0_newdomain_t));
    read(id_fd, dom_data, sizeof(dom0_newdomain_t));
    close(id_fd);
    
    return dom_data;
}    

/***********************************************************************/

int main(int argc, char **argv)
{
  dom0_newdomain_t * dom_data;

  if (argv[0] != NULL) 
    {
      argv0 = argv[0];
    }

  if(argc != 3) 
    {
      fprintf (stderr, "Usage: %s <kbytes-mem> <domain-name>\n", argv0);
      return -1;
    }

  if(!(dom_data = create_new_domain(atol(argv[1]), argv[2]))) 
    {
      return -1;
    }

  fprintf (stdout, "%d\n", dom_data -> domain);
  return 0;
}
