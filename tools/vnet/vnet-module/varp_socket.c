/*
 * Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by the 
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free software Foundation, Inc.,
 * 59 Temple Place, suite 330, Boston, MA 02111-1307 USA
 *
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/version.h>

#include <asm/uaccess.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/version.h>
#include <linux/smp_lock.h>
#include <net/sock.h>

#include <if_varp.h>
#include <varp.h>

/* Get macros needed to define system calls as functions in the kernel. */
#define __KERNEL_SYSCALLS__
static int errno;
#include <linux/unistd.h>

#define MODULE_NAME "VARP"
#define DEBUG 1
#undef DEBUG
#include "debug.h"

// Compensate for struct sock fields having 'sk_' added
// to them in 2.6.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

#define SK_RECEIVE_QUEUE sk_receive_queue
#define SK_SLEEP         sk_sleep

#else

#define SK_RECEIVE_QUEUE receive_queue
#define SK_SLEEP         sleep

#endif

/** @file
 * Support for the VARP udp sockets.
 */

static inline mm_segment_t change_fs(mm_segment_t fs){
    mm_segment_t oldfs = get_fs();
    set_fs(fs);
    return oldfs;
}

/* Replicate the user-space socket API.
 * The parts we need anyway.
 */

/* Define the socketcall() syscall.
 * Multiplexes all the socket-related calls.
 *
 * @param call socket call id
 * @param args arguments (upto 6)
 * @return call-dependent value
 */
static inline _syscall2(int, socketcall,
                        int, call,
                        unsigned long *, args)

int socket(int family, int type, int protocol){
    unsigned long args[6];
    
    args[0] = (unsigned long)family;
    args[1] = (unsigned long)type;
    args[2] = (unsigned long)protocol;
    return socketcall(SYS_SOCKET, args);
}

int bind(int fd, struct sockaddr *umyaddr, int addrlen){
    unsigned long args[6];
    
    args[0] = (unsigned long)fd;
    args[1] = (unsigned long)umyaddr;
    args[2] = (unsigned long)addrlen;
    return socketcall(SYS_BIND, args);
}

int connect(int fd, struct sockaddr *uservaddr, int addrlen){
    unsigned long args[6];
    
    args[0] = (unsigned long)fd;
    args[1] = (unsigned long)uservaddr;
    args[2] = (unsigned long)addrlen;
    return socketcall(SYS_CONNECT, args);
}

int sendto(int fd, void * buff, size_t len,
           unsigned flags, struct sockaddr *addr,
           int addr_len){
    unsigned long args[6];
    
    args[0] = (unsigned long)fd;
    args[1] = (unsigned long)buff;
    args[2] = (unsigned long)len;
    args[3] = (unsigned long)flags;
    args[4] = (unsigned long)addr;
    args[5] = (unsigned long)addr_len;
    return socketcall(SYS_SENDTO, args);
}

int recvfrom(int fd, void * ubuf, size_t size,
             unsigned flags, struct sockaddr *addr,
             int *addr_len){
    unsigned long args[6];
    
    args[0] = (unsigned long)fd;
    args[1] = (unsigned long)ubuf;
    args[2] = (unsigned long)size;
    args[3] = (unsigned long)flags;
    args[4] = (unsigned long)addr;
    args[5] = (unsigned long)addr_len;
    return socketcall(SYS_RECVFROM, args);
}

int setsockopt(int fd, int level, int optname, void *optval, int optlen){
    unsigned long args[6];
    
    args[0] = (unsigned long)fd;
    args[1] = (unsigned long)level;
    args[2] = (unsigned long)optname;
    args[3] = (unsigned long)optval;
    args[4] = (unsigned long)optlen;
    return socketcall(SYS_SETSOCKOPT, args);
}

int getsockopt(int fd, int level, int optname, void *optval, int *optlen){
    unsigned long args[6];
    
    args[0] = (unsigned long)fd;
    args[1] = (unsigned long)level;
    args[2] = (unsigned long)optname;
    args[3] = (unsigned long)optval;
    args[4] = (unsigned long)optlen;
    return socketcall(SYS_GETSOCKOPT, args);
}

int shutdown(int fd, int how){
    unsigned long args[6];
    
    args[0] = (unsigned long)fd;
    args[1] = (unsigned long)how;
    return socketcall(SYS_SHUTDOWN, args);
}

int getsockname(int fd, struct sockaddr *usockaddr, int *usockaddr_len){
    unsigned long args[6];
    
    args[0] = (unsigned long)fd;
    args[1] = (unsigned long)usockaddr;
    args[2] = (unsigned long)usockaddr_len;
    return socketcall(SYS_GETSOCKNAME, args);
}

/*============================================================================*/
/** Socket flags. */
enum {
    VSOCK_REUSE     =  1,
    VSOCK_BIND      =  2,
    VSOCK_CONNECT   =  4,
    VSOCK_BROADCAST =  8,
    VSOCK_MULTICAST = 16,
 };

/** Convert socket flags to a string.
 *
 * @param flags flags
 * @return static string
 */
char * socket_flags(int flags){
    static char s[6];
    int i = 0;
    s[i++] = (flags & VSOCK_CONNECT   ? 'c' : '-');
    s[i++] = (flags & VSOCK_BIND      ? 'b' : '-');
    s[i++] = (flags & VSOCK_REUSE     ? 'r' : '-');
    s[i++] = (flags & VSOCK_BROADCAST ? 'B' : '-');
    s[i++] = (flags & VSOCK_MULTICAST ? 'M' : '-');
    s[i++] = '\0';
    return s;
}

/** The varp multicast socket. */
int varp_mcast_sock = -1;

/** The varp unicast socket. */
int varp_ucast_sock = -1;

/** Control flag for whether varp should be running.
 * If this is set 0 then the varp thread will notice and
 * (eventually) exit. This is indicated by setting varp_running
 * to 0.
 */
atomic_t varp_run = ATOMIC_INIT(0);

/** State flag indicating whether the varp thread is running. */
atomic_t varp_running = ATOMIC_INIT(0);

/** Set socket option to reuse address.
 *
 * @param sock socket
 * @param reuse flag
 * @return 0 on success, error code otherwise
 */
int setsock_reuse(int sock, int reuse){
    int err = 0;
    err = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if(err < 0){
        eprintf("> setsockopt SO_REUSEADDR: %d %d\n", err, errno);
    }
    return err;
}

/** Set socket broadcast option.
 *
 * @param sock socket
 * @param bcast flag
 * @return 0 on success, error code otherwise
 */
int setsock_broadcast(int sock, int bcast){
    int err = 0;
    err = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));
    if(err < 0){
        eprintf("> setsockopt SO_BROADCAST: %d %d\n", err, errno);
    }
    return err;
}

/** Join a socket to a multicast group.
 *
 * @param sock socket
 * @param saddr multicast address
 * @return 0 on success, error code otherwise
 */
int setsock_multicast(int sock, uint32_t saddr){
    int err = 0;
    struct net_device *dev = NULL;
    u32 addr = 0;
    struct ip_mreqn mreq = {};
    int mloop = 0;

    err = vnet_get_device(DEVICE, &dev);
    if(err){
        eprintf("> error getting device: %d %d\n", err, errno);
        goto exit;
    }
    err = vnet_get_device_address(dev, &addr);
    if(err){
        eprintf("> error getting device address: %d %d\n", err, errno);
        goto exit;
    }
    // See 'man 7 ip' for these options.
    mreq.imr_multiaddr.s_addr = saddr;       // IP multicast address.
    //mreq.imr_address.s_addr   = addr;        // Interface IP address.
    mreq.imr_address.s_addr   = INADDR_ANY;  // Interface IP address.
    mreq.imr_ifindex = 0;                    // Interface index (0 means any).
    dprintf("> saddr=%u.%u.%u.%u addr=%u.%u.%u.%u ifindex=%d\n",
            NIPQUAD(saddr), NIPQUAD(addr), mreq.imr_ifindex);
    err = setsockopt(sock, SOL_IP, IP_MULTICAST_LOOP, &mloop, sizeof(mloop));
    if(err < 0){
        eprintf("> setsockopt IP_MULTICAST_LOOP: %d %d\n", err, errno);
        goto exit;
    }
    err = setsockopt(sock, SOL_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if(err < 0){
        eprintf("> setsockopt IP_ADD_MEMBERSHIP: %d %d\n", err, errno);
        goto exit;
    }
  exit:
    err = 0; //todo: remove hack
    return err;
}

/** Set a socket's multicast ttl (default is 1).
 * @param sock socket
 * @param ttl ttl
 * @return 0 on success, error code otherwise
 */
int setsock_multicast_ttl(int sock, uint8_t ttl){
    int err = 0;
    err = setsockopt(sock, SOL_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    return err;
}

/** Create a socket.
 * The flags can include VSOCK_REUSE, VSOCK_BROADCAST, VSOCK_CONNECT.
 *
 * @param socktype socket type
 * @param saddr address
 * @param port port
 * @param flags flags
 * @param val return value for the socket connection
 * @return 0 on success, error code otherwise
 */
int create_socket(int socktype, uint32_t saddr, uint32_t port, int flags, int *val){
    int err = 0;
    int sock;
    struct sockaddr_in addr_in;
    struct sockaddr *addr = (struct sockaddr *)&addr_in;
    int addr_n = sizeof(addr_in);
    int reuse, bcast;
    int sockproto = 0;

    //dprintf(">\n");
    reuse = (flags & VSOCK_REUSE);
    bcast = (flags & VSOCK_BROADCAST);
    addr_in.sin_family      = AF_INET;
    addr_in.sin_addr.s_addr = saddr;
    addr_in.sin_port        = port;
    dprintf("> flags=%s addr=%u.%u.%u.%u port=%d\n",
            socket_flags(flags),
            NIPQUAD(saddr), ntohs(port));

    switch(socktype){
    case SOCK_DGRAM:  sockproto = IPPROTO_UDP; break;
    case SOCK_STREAM: sockproto = IPPROTO_TCP; break;
    }
    sock = socket(AF_INET, socktype, sockproto);
    if(sock < 0) goto exit;
    if(reuse){
        err = setsock_reuse(sock, reuse);
        if(err < 0) goto exit;
    }
    if(bcast){
        err = setsock_broadcast(sock, bcast);
        if(err < 0) goto exit;
    }
    if(flags & VSOCK_MULTICAST){
        err = setsock_multicast(sock, saddr);
        if(err < 0) goto exit;
    }
    if(flags & VSOCK_CONNECT){
        err = connect(sock, addr, addr_n);
        if(err < 0) goto exit;
    }
    if(flags & VSOCK_BIND){
        err = bind(sock, addr, addr_n);
        if(err < 0) goto exit;
    }
  exit:
    *val = (err ? -1 : sock);
    if(err) eprintf("> err=%d errno=%d\n", err, errno);
    return err;
}

/** Open the varp multicast socket.
 *
 * @param mcaddr multicast address 
 * @param saddr address 
 * @param port port
 * @param val return parameter for the socket
 * @return 0 on success, error code otherwise
 */
int varp_mcast_open(uint32_t mcaddr, uint32_t saddr, uint16_t port, int *val){
    int err = 0;
    int flags = VSOCK_REUSE;
    int multicast = MULTICAST(mcaddr);
    int sock = 0;
    struct sockaddr_in addr_in;
    struct sockaddr *addr = (struct sockaddr *)&addr_in;
    int addr_n = sizeof(addr_in);
    
    dprintf(">\n");
    flags |= VSOCK_MULTICAST;
    flags |= VSOCK_BROADCAST;
    
    err = create_socket(SOCK_DGRAM, mcaddr, port, flags, &sock);
    if(err < 0) goto exit;
    if(multicast){
        err = setsock_multicast_ttl(sock, 1);
        if(err < 0) goto exit;
    }
    if(0){
        addr_in.sin_family      = AF_INET;
        addr_in.sin_addr.s_addr = saddr;
        addr_in.sin_port        = port;
        err = bind(sock, addr, addr_n);
        if(err < 0){
            eprintf("> bind: %d %d\n", err, errno);
            goto exit;
        }
    }
    if(0){
        struct sockaddr_in self = {};
        int self_n;
        getsockname(sock, (struct sockaddr *)&self, &self_n);
        dprintf("> sockname sock=%d addr=%u.%u.%u.%u port=%d\n",
                sock, NIPQUAD(saddr), ntohs(port));
    }
  exit:
    if(err){
        shutdown(sock, 2);
    }
    *val = (err ? -1 : sock);
    dprintf("< err=%d val=%d\n", err, *val);
    return err;
}

/** Open the varp unicast socket.
 *
 * @param addr address 
 * @param port port
 * @param val return parameter for the socket
 * @return 0 on success, error code otherwise
 */
int varp_ucast_open(uint32_t addr, u16 port, int *val){
    int err = 0;
    int flags = VSOCK_BIND | VSOCK_REUSE;
    dprintf(">\n");
    err = create_socket(SOCK_DGRAM, addr, port, flags, val);
    dprintf("< err=%d val=%d\n", err, *val);
    return err;
}

/* Here because inline in 'socket.c'. */
#ifndef sockfd_put
#define sockfd_put(sock) fput((sock)->file)
#endif

/** Get the next skb from a socket's receive queue.
 *
 * @param fd socket file descriptor
 * @return skb or NULL
 */
static struct sk_buff *get_sock_skb(int fd){
    int err = 0;
    struct sk_buff *skb = NULL;
    struct socket *sock = NULL;

    sock = sockfd_lookup(fd, &err);
    if (!sock){
        dprintf("> no sock for fd=%d\n", fd);
        goto exit;
    }
    skb = skb_dequeue(&sock->sk->SK_RECEIVE_QUEUE);
    //skb = skb_recv_datagram(sock->sk, 0, 1, &recv_err);
    sockfd_put(sock);
  exit:
    return skb;
}

/** Handle the next skb on a socket (if any).
 *
 * @param fd socket file descriptor
 * @return 1 if there was an skb, 0 otherwise
 */
static int handle_sock_skb(int fd){
    int ret = 0;
    struct sk_buff *skb = get_sock_skb(fd);
    if(skb){
        ret = 1;
        dprintf("> skb fd=%d skb=%p\n", fd, skb);
        varp_handle_message(skb);
        kfree_skb(skb);
    }
    return ret;
}

/** Add a wait queue to a socket.
 *
 * @param fd socket file descriptor
 * @param waitq queue
 * @return 0 on success, error code otherwise
 */
int sock_add_wait_queue(int fd, wait_queue_t *waitq){
    int err = 0;
    struct socket *sock = NULL;

    dprintf("> fd=%d\n", fd);
    sock = sockfd_lookup(fd, &err);
    if (!sock) goto exit;
    add_wait_queue(sock->sk->SK_SLEEP, waitq);
    sockfd_put(sock);
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

/** Remove a wait queue from a socket.
 *
 * @param fd socket file descriptor
 * @param waitq queue
 * @return 0 on success, error code otherwise
 */
int sock_remove_wait_queue(int fd, wait_queue_t *waitq){
    int err = 0;
    struct socket *sock = NULL;

    sock = sockfd_lookup(fd, &err);
    if (!sock) goto exit;
    remove_wait_queue(sock->sk->SK_SLEEP, waitq);
    sockfd_put(sock);
  exit:
    return err;
}

/** Loop handling the varp sockets.
 * We use kernel API for this (waitqueue, schedule_timeout) instead
 * of select because the select syscall was returning EFAULT. Oh well.
 *
 * @param arg arguments
 * @return exit code
 */
int varp_main(void *arg){
    int err = 0;
    long timeout = 3 * HZ;
    int count = 0;
    int n = 0;
    DECLARE_WAITQUEUE(mcast_wait, current);
    DECLARE_WAITQUEUE(ucast_wait, current);

    dprintf("> start\n");
    atomic_set(&varp_running, 1);
    err = sock_add_wait_queue(varp_mcast_sock, &mcast_wait);
    err = sock_add_wait_queue(varp_ucast_sock, &ucast_wait);
    for(n = 1; atomic_read(&varp_run) == 1; n++){
        //dprintf("> n=%d\n", n);
        count = 0;
        count += handle_sock_skb(varp_mcast_sock);
        count += handle_sock_skb(varp_ucast_sock);
        if(!count){
            // No skbs were handled, so go back to sleep.
            set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(timeout);
            current->state = TASK_RUNNING;
        }
    }
    sock_remove_wait_queue(varp_mcast_sock, &mcast_wait);
    sock_remove_wait_queue(varp_ucast_sock, &ucast_wait);
    atomic_set(&varp_running, 0);
    //MOD_DEC_USE_COUNT;
    dprintf("< stop err=%d\n", err);
    return err;
}

/** Start the varp thread.
 *
 * @return 0 on success, error code otherwise
 */
int varp_start(void){
    int err = 0;
    void *args = NULL;
    int flags = 0;
    long pid = 0;
    
    dprintf(">\n");
    //flags |= CLONE_VM;
    flags |= CLONE_FS;
    flags |= CLONE_FILES;
    flags |= CLONE_SIGHAND;
    atomic_set(&varp_run, 1);
    atomic_set(&varp_running, 0);
    pid = kernel_thread(varp_main, args, flags);
    dprintf("< pid=%ld\n", pid);
    return err;
}

/** Close the varp sockets and stop the thread handling them.
 */
void varp_close(void){
    mm_segment_t oldfs;
    long timeout = 1 * HZ;
    int tries = 10;
    dprintf(">\n");
    // Tell the varp thread to stop and wait a while for it.
    atomic_set(&varp_run, 0);
    while(atomic_read(&varp_running) && tries-- > 0){
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(timeout);
        current->state = TASK_RUNNING;
    }
    // Close the sockets.
    oldfs = change_fs(KERNEL_DS);
    if(varp_mcast_sock > 0){
        shutdown(varp_mcast_sock, 2);
        varp_mcast_sock = -1;
    }
    if(varp_ucast_sock > 0){
        shutdown(varp_ucast_sock, 2);
        varp_ucast_sock = -1;
    }
    set_fs(oldfs);
    //MOD_DEC_USE_COUNT;
    dprintf("<\n");
}    

/** Open the varp sockets and start the thread handling them.
 *
 * @param mcaddr multicast address
 * @param addr unicast address
 * @param port port
 * @return 0 on success, error code otherwise
 */
int varp_open(u32 mcaddr, u32 addr, u16 port){
    int err = 0;
    mm_segment_t oldfs;

    //MOD_INC_USE_COUNT;
    dprintf("> mcaddr=%u.%u.%u.%u addr=%u.%u.%u.%u port=%u\n",
            NIPQUAD(mcaddr), NIPQUAD(addr), ntohs(port));
    //MOD_INC_USE_COUNT;
    oldfs = change_fs(KERNEL_DS);
    err = varp_mcast_open(mcaddr, addr, port, &varp_mcast_sock);
    if(err < 0 ) goto exit;
    err = varp_ucast_open(INADDR_ANY, port, &varp_ucast_sock);
    if(err < 0 ) goto exit;
    set_fs(oldfs);
    err = varp_start();
  exit:
    set_fs(oldfs);
    if(err){
        varp_close();
    }
    dprintf("< err=%d\n", err);
    return err;
}	

