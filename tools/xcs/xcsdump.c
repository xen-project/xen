/* xcsdump.c
 *
 * little tool to sniff control messages.
 *
 * Copyright (c) 2004, Andrew Warfield
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <xc.h>
#include <xen/xen.h>
#include <xen/io/domain_controller.h>
#include "xcs_proto.h"
#include "xcs.h"

static int xcs_ctrl_fd = -1; /* connection to the xcs server. */
static int xcs_data_fd = -1; /* connection to the xcs server. */

int tcp_connect(char *ip, short port)
{
    struct sockaddr_in addr;
    int ret, fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        printf("error creating xcs socket!\n");
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    memset(&(addr.sin_zero), '\0', 8);

    ret = connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr));
    if (ret < 0) 
    {
        printf("error connecting to xcs!\n");
        return -1;
    }
    
    return fd;
}

void tcp_disconnect(int *fd)
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
    int ret, i;
    xcs_msg_t msg;
    control_msg_t *cmsg;
    int verbose = 0;
    
    if (argc > 1) 
        if ((strlen(argv[1]) >=2) && (strncmp(argv[1], "-v", 2) == 0))
            verbose = 1;
    
    ret = tcp_connect("127.0.0.1", XCS_TCP_PORT);
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
    
    ret = tcp_connect("127.0.0.1", XCS_TCP_PORT);
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
        
        for (i=0; i<60; i++)
            if ((!isprint(cmsg->msg[i])) && (cmsg->msg[i] != '\0'))
                cmsg->msg[i] = '.';
        cmsg->msg[59] = '\0';
        
        switch (msg.type)
        {
        case XCS_REQUEST:
            printf("[REQUEST ] : (dom:%u port:%d) (type:(%d,%d) len %d) \n",
                    msg.u.control.remote_dom,
                    msg.u.control.local_port,
                    msg.u.control.msg.type, 
                    msg.u.control.msg.subtype, 
                    msg.u.control.msg.length);
            if (verbose)
                printf("           : %s\n", msg.u.control.msg.msg);
            break; 
        case XCS_RESPONSE:
            printf("[RESPONSE] : (dom:%u port:%d) (type:(%d,%d) len %d) \n",
                    msg.u.control.remote_dom,
                    msg.u.control.local_port,
                    msg.u.control.msg.type, 
                    msg.u.control.msg.subtype, 
                    msg.u.control.msg.length);
            if (verbose)
                printf("           : %s\n", msg.u.control.msg.msg);
            break;
        case XCS_VIRQ:
            printf("[VIRQ    ] : %d\n", msg.u.control.local_port);
        default:
            printf("[UNKNOWN ]\n");
        }
    }
    
    return(0);
}
