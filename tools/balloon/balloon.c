/******************************************************************************
 * balloon.c
 *
 * Xeno balloon driver userspace control tool. Used to shrink/grow domain's 
 * memory.
 *
 * Copyright (c) 2003, B Dragovic
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define INFLATE_BALLOON      "inflate"   /* return mem to hypervisor */
#define DEFLATE_BALLOON      "deflate"   /* claim mem from hypervisor */

/* THIS IS TAKEN FROM XENOLINUX BALLOON DRIVER */
#define USER_INFLATE_BALLOON  1   /* return mem to hypervisor */
#define USER_DEFLATE_BALLOON  2   /* claim mem from hypervisor */
typedef struct user_balloon_op {
    unsigned int    op;
    unsigned long   size;
} user_balloon_op_t;
/* END OF CODE TAKEN FROM XENOLINUX BALLOON DRIVER */


static int open_balloon_proc()
{
    return open("/proc/xeno/balloon", O_RDWR);
}

/* inflate balloon function signals to kernel it should relinquish memory */
static int inflate_balloon(unsigned long num_pages)
{
    user_balloon_op_t bop;
    int proc_fd;

    if((proc_fd = open_balloon_proc()) <= 0){
        printf("Error opening balloon proc file.\n");
        return 0;
    }

    bop.op   = USER_INFLATE_BALLOON;
    bop.size = num_pages;
    if ( write(proc_fd, &bop, sizeof(bop)) <= 0 )
    {
        printf("Error writing to balloon proc file.\n");
        return 0;
    }

    close(proc_fd);
    return 1;
}

/* deflate balloon function signals to kernel it should claim memory */
static int deflate_balloon(unsigned long num_pages)
{
    user_balloon_op_t bop;
    int proc_fd;

    if((proc_fd = open_balloon_proc()) <= 0){
        printf("Error opening balloon proc file.\n");
        return 0;
    }

    bop.op   = USER_DEFLATE_BALLOON;
    bop.size = num_pages;
    if(write(proc_fd, &bop, sizeof(bop)) <= 0){
        printf("Error writing to balloon proc file.\n");
        return 0;
    }

    close(proc_fd);
    return 1;
}

int main(int argc, char *argv[])
{
    unsigned long num_pages;

    if(argc < 2){
        printf("Usage: balloon <inflate|deflate> <num_pages>\n");
        return -1;
    }

    num_pages = atol(argv[2]);

    if(!strcmp(argv[1], INFLATE_BALLOON)){
        if(!inflate_balloon(num_pages)){
            perror("Inflating balloon failed");
            return -1;
        }

    } else if (!strcmp(argv[1], DEFLATE_BALLOON)){
        if(!deflate_balloon(num_pages)){
            perror("Deflating balloon failed");
            return -1;
        }

    } else {
        printf("Unrecognized command line argument.\n");
        return -1;
    }

    return 0;
}

    

