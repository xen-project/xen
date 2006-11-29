/******************************************************************************
 * miniterm.c
 * 
 * Adapted from the example program distributed with the Linux Programmer's
 * Guide (LPG). This has been robustified and tweaked to work as a debugging 
 * terminal for Xen-based machines.
 * 
 * Modifications are released under GPL and copyright (c) 2003, K A Fraser
 * The original copyright message and license is fully intact below.
 */

/*
 *  AUTHOR: Sven Goldt (goldt@math.tu-berlin.de)
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */

#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#define DEFAULT_BAUDRATE   115200
#define DEFAULT_SERDEVICE  "/dev/ttyS0"
#define ENDMINITERM        0x1d

volatile int stop = 0;

void child_handler(int s)
{
    stop = 1;
}

int cook_baud(int baud)
{
    int cooked_baud = 0;
    switch ( baud )
    {
    case     50: cooked_baud =     B50; break;
    case     75: cooked_baud =     B75; break;
    case    110: cooked_baud =    B110; break;
    case    134: cooked_baud =    B134; break;
    case    150: cooked_baud =    B150; break;
    case    200: cooked_baud =    B200; break;
    case    300: cooked_baud =    B300; break;
    case    600: cooked_baud =    B600; break;
    case   1200: cooked_baud =   B1200; break;
    case   1800: cooked_baud =   B1800; break;
    case   2400: cooked_baud =   B2400; break;
    case   4800: cooked_baud =   B4800; break;
    case   9600: cooked_baud =   B9600; break;
    case  19200: cooked_baud =  B19200; break;
    case  38400: cooked_baud =  B38400; break;
    case  57600: cooked_baud =  B57600; break;
    case 115200: cooked_baud = B115200; break;
    }
    return cooked_baud;
}

int main(int argc, char **argv)
{
    int              fd, c, cooked_baud = cook_baud(DEFAULT_BAUDRATE);
    char            *sername = DEFAULT_SERDEVICE;
    struct termios   oldsertio, newsertio, oldstdtio, newstdtio;
    struct sigaction sa;
    static char start_str[] = 
        "************ REMOTE CONSOLE: CTRL-] TO QUIT ********\r\n";
    static char end_str[] =
        "\n************ REMOTE CONSOLE EXITED *****************\n";

    while ( --argc != 0 )
    {
        char *p = argv[argc];
        if ( *p++ != '-' )
            goto usage;
        if ( *p == 'b' )
        {
            p++;
            if ( (cooked_baud = cook_baud(atoi(p))) == 0 )
            {
                fprintf(stderr, "Bad baud rate '%d'\n", atoi(p));
                goto usage;
            }
        }
        else if ( *p == 'd' )
        {
            sername = ++p;
            if ( *sername == '\0' )
                goto usage;
        }
        else
            goto usage;
    }

    /* Not a controlling tty: CTRL-C shouldn't kill us. */
    fd = open(sername, O_RDWR | O_NOCTTY);
    if ( fd < 0 )
    {
        perror(sername); 
        exit(-1);
    }
 
    tcgetattr(fd, &oldsertio); /* save current modem settings */
 
    /*
     * 8 data, no parity, 1 stop bit. Ignore modem control lines. Enable 
     * receive. Set appropriate baud rate. NO HARDWARE FLOW CONTROL!
     */
    newsertio.c_cflag = cooked_baud | CS8 | CLOCAL | CREAD;

    /* Raw input. Ignore errors and breaks. */
    newsertio.c_iflag = IGNBRK | IGNPAR;

    /* Raw output. */
    newsertio.c_oflag = OPOST;

    /* No echo and no signals. */
    newsertio.c_lflag = 0;
 
    /* blocking read until 1 char arrives */
    newsertio.c_cc[VMIN]=1;
    newsertio.c_cc[VTIME]=0;
 
    /* now clean the modem line and activate the settings for modem */
    tcflush(fd, TCIFLUSH);
    tcsetattr(fd,TCSANOW,&newsertio);
 
    /* next stop echo and buffering for stdin */
    tcgetattr(0,&oldstdtio);
    tcgetattr(0,&newstdtio); /* get working stdtio */
    newstdtio.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    newstdtio.c_oflag &= ~OPOST;
    newstdtio.c_cflag &= ~(CSIZE | PARENB);
    newstdtio.c_cflag |= CS8;
    newstdtio.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    newstdtio.c_cc[VMIN]=1;
    newstdtio.c_cc[VTIME]=0;
    tcsetattr(0,TCSANOW,&newstdtio);

    /* Terminal settings done: now enter the main I/O loops. */
    switch ( fork() )
    {
    case 0:
        close(1); /* stdout not needed */
        for ( c = (char)getchar(); c != ENDMINITERM; c = (char)getchar() )
            write(fd,&c,1);
        tcsetattr(fd,TCSANOW,&oldsertio);
        tcsetattr(0,TCSANOW,&oldstdtio);
        close(fd);
        exit(0); /* will send a SIGCHLD to the parent */
        break;
    case -1:
        perror("fork");
        tcsetattr(fd,TCSANOW,&oldsertio);
        close(fd);
        exit(-1);
    default:
        write(1, start_str, strlen(start_str));
        close(0); /* stdin not needed */
        sa.sa_handler = child_handler;
        sa.sa_flags = 0;
        sigaction(SIGCHLD,&sa,NULL); /* handle dying child */
        while ( !stop )
        {
            read(fd,&c,1); /* modem */
            c = (char)c;
            write(1,&c,1); /* stdout */
        }
        wait(NULL); /* wait for child to die or it will become a zombie */
        write(1, end_str, strlen(end_str));
        break;
    }

    return 0;

 usage:
    printf("miniterm [-b<baudrate>] [-d<devicename>]\n");
    printf("Default baud rate: %d\n", DEFAULT_BAUDRATE);
    printf("Default device: %s\n", DEFAULT_SERDEVICE);
    return 1;
}
