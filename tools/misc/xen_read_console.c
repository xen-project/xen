/******************************************************************************
 * Test program for reading console lines from DOM0 port 666.
 */

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    unsigned char buf[208], abuf[32];
    struct sockaddr_in addr, from;
    int fromlen = sizeof(from);
    int len, fd = socket(PF_INET, SOCK_DGRAM, 0);
    
    if ( fd < 0 )
    {
        fprintf(stderr, "could not open datagram socket\n");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = htonl(0xa9fe0100); /* 169.254.1.0 */
    addr.sin_port = htons(666);
    addr.sin_family = AF_INET;
    if ( bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 )
    {
        fprintf(stderr, "could not bind to local address and port\n");
        return -1;
    }

    while ( (len = recvfrom(fd, buf, sizeof(buf), 0, 
                            (struct sockaddr *)&from, &fromlen)) 
            >= 0 )
    {
#if 0
        printf("%d-byte message from %s:%d --\n", len,
               inet_ntop(AF_INET, &from.sin_addr, abuf, sizeof(abuf)),
               ntohs(from.sin_port));
#endif
        /* For sanity, clean up the string's tail. */
        if ( buf[len-1] != '\n' ) { buf[len] = '\n'; len++; }
        buf[len] = '\0';

        printf("[%d] %s", ntohs(from.sin_port),buf);

        fromlen = sizeof(from);
    }

    return 0;
}
