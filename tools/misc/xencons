#!/usr/bin/env python

##############################################
# Console client for Xen guest OSes
# Copyright (c) 2004, K A Fraser
##############################################

import errno, os, signal, socket, struct, sys

from termios import *
# Indexes into termios.tcgetattr() list.
IFLAG  = 0
OFLAG  = 1
CFLAG  = 2
LFLAG  = 3
ISPEED = 4
OSPEED = 5
CC     = 6

def __child_death(signum, frame):
    global stop
    stop = True

def __recv_from_sock(sock):
    global stop
    stop = False
    while not stop:
        try:
            data = sock.recv(1024)
        except socket.error, error:
            if error[0] != errno.EINTR:
                raise
        else:
            try:
                os.write(1, data)
            except os.error, error:
                if error[0] != errno.EINTR:
                    raise
    os.wait()

def __send_to_sock(sock):
    while 1:
        try:
            data = os.read(0,1024)
        except os.error, error:
            if error[0] != errno.EINTR:
                raise
        else:
            if ord(data[0]) == ord(']')-64:
                break
            try:
                sock.send(data)
            except socket.error, error:
                if error[0] == errno.EPIPE:
                    sys.exit(0)
                if error[0] != errno.EINTR:
                    raise
    sys.exit(0)

def connect(host,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.connect((host,port))

    oattrs = tcgetattr(0)
    nattrs = tcgetattr(0)
    nattrs[IFLAG] = nattrs[IFLAG] & ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON)
    nattrs[OFLAG] = nattrs[OFLAG] & ~(OPOST)
    nattrs[CFLAG] = nattrs[CFLAG] & ~(CSIZE | PARENB)
    nattrs[CFLAG] = nattrs[CFLAG] | CS8
    nattrs[LFLAG] = nattrs[LFLAG] & ~(ECHO | ICANON | IEXTEN | ISIG)
    nattrs[CC][VMIN] = 1
    nattrs[CC][VTIME] = 0

    if os.fork():
        signal.signal(signal.SIGCHLD, __child_death)
        print "************ REMOTE CONSOLE: CTRL-] TO QUIT ********"
        tcsetattr(0, TCSAFLUSH, nattrs)
        try:
            __recv_from_sock(sock)
        finally:
            tcsetattr(0, TCSAFLUSH, oattrs)
            print
            print "************ REMOTE CONSOLE EXITED *****************"
    else:
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        __send_to_sock(sock)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print sys.argv[0] + " <host> <port>"
        sys.exit(1)
    connect(str(sys.argv[1]),int(sys.argv[2]))
