/* xcsdump.c
 *
 * little tool to sniff control messages.
 *
 * Copyright (c) 2004, Andrew Warfield
 *
 * Modifications by Anthony Liguori <aliguori@us.ibm.com> are:
 *   Copyright (C) 2005, International Business Machines, Corp.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ctype.h>
#include <xc.h>
#include <xen/xen.h>
#include <xen/io/domain_controller.h>
#include <getopt.h>
#include "xcs_proto.h"
#include "xcs.h"

#include "dump.h"

static int xcs_ctrl_fd = -1; /* connection to the xcs server. */
static int xcs_data_fd = -1; /* connection to the xcs server. */

int sock_connect(char *path)
{
    struct sockaddr_un addr;
    int ret, len, fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        printf("error creating xcs socket!\n");
        return -1;
    }

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    len = sizeof(addr.sun_family) + strlen(addr.sun_path) + 1;

    ret = connect(fd, (struct sockaddr *)&addr, len);
    if (ret < 0) 
    {
        printf("error connecting to xcs!\n");
        return -1;
    }
    
    return fd;
}

void sock_disconnect(int *fd)
{
    close(*fd);
    *fd = -1;
}

void xcs_read(int fd, xcs_msg_t *msg)
{
    int ret;
    
    ret = read(fd, msg, sizeof(xcs_msg_t));
    if (ret != sizeof(xcs_msg_t)) {
        printf("read error\n");
        exit(-1);
    }
}

void xcs_send(int fd, xcs_msg_t *msg)
{
    int ret;
    
    ret = send(fd, msg, sizeof(xcs_msg_t), 0);
    if (ret != sizeof(xcs_msg_t) )
    {
        printf("send error\n");
        exit(-1);
    }
}
              

int main(int argc, char* argv[])
{
    int ret;
    xcs_msg_t msg;
    control_msg_t *cmsg;
    int verbose = 0;
    int ch;

    while ((ch = getopt(argc, argv, "hv:")) != -1)
    {
        switch (ch)
        {
        case 'v':
            verbose = atoi(optarg);
            break;
        case 'h':
  	    printf("Usage: %s [-v FLAGS]\n"
"Displays XCS control message traffic.\n"
"\n"
"FLAGS is a bitmask where each bit (numbering starts from LSB) represents\n"
"whether to display a particular message type.\n"
"\n"
"For example, -v 1022 will display all messages except for console messages.\n"
		   , argv[0]);
	    exit(0);
	    break;
        }
    }
    
    ret = sock_connect(XCS_SUN_PATH);
    if (ret < 0) 
    {
        printf("connect failed!\n"); 
        exit(-1);
    }
    xcs_ctrl_fd = ret;
    
    memset(&msg, 0, sizeof(msg));
    msg.type = XCS_CONNECT_CTRL;
    xcs_send(xcs_ctrl_fd, &msg);
    xcs_read(xcs_ctrl_fd, &msg);
    if (msg.result != XCS_RSLT_OK)
    {
        printf("Error connecting control channel\n");
        exit(-1);
    }
    
    ret = sock_connect(XCS_SUN_PATH);
    if (ret < 0) 
    {
        printf("connect failed!\n"); 
        exit(-1);
    }
    xcs_data_fd = ret;
    
    msg.type = XCS_CONNECT_DATA;
    /* session id is set from before... */
    xcs_send(xcs_data_fd, &msg);
    xcs_read(xcs_data_fd, &msg);
    if (msg.result != XCS_RSLT_OK)
    {
        printf("Error connecting data channel\n");
        exit(-1);
    }
    
    msg.type = XCS_MSG_BIND;
    msg.u.bind.port = PORT_WILDCARD;
    msg.u.bind.type = TYPE_WILDCARD;
    xcs_send(xcs_ctrl_fd, &msg);
    xcs_read(xcs_ctrl_fd, &msg);
    if (msg.result != XCS_RSLT_OK)
    {
        printf("Error binding.\n");
        exit(-1);
    }
    
    
    while (1)
    {
        xcs_read(xcs_data_fd, &msg);
        cmsg = &msg.u.control.msg;
        
        switch (msg.type)
        {
        case XCS_REQUEST:
  	    if (!verbose || verbose & (1 << msg.u.control.msg.type))
            {
	        printf("[REQUEST ] : (dom:%u port:%d) (type:(%d,%d) len %d)\n",
		       msg.u.control.remote_dom,
		       msg.u.control.local_port,
		       msg.u.control.msg.type, 
		       msg.u.control.msg.subtype, 
		       msg.u.control.msg.length);

		dump_msg(cmsg, verbose);
	    }
	    break; 
        case XCS_RESPONSE:
  	    if (!verbose || verbose & (1 << msg.u.control.msg.type))
            {
	        printf("[RESPONSE] : (dom:%u port:%d) (type:(%d,%d) len %d)\n",
		       msg.u.control.remote_dom,
		       msg.u.control.local_port,
		       msg.u.control.msg.type, 
		       msg.u.control.msg.subtype, 
		       msg.u.control.msg.length);

		dump_msg(cmsg, verbose);
	    }
	    break;
        case XCS_VIRQ:
            printf("[VIRQ    ] : %d\n", msg.u.control.local_port);
        default:
            printf("[UNKNOWN ]\n");
        }
    }
    
    return(0);
}
