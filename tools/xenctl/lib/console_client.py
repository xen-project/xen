
##############################################
# Console client for Xen guest OSes
# Copyright (c) 2004, K A Fraser
##############################################

import errno, os, signal, socket, struct, sys, termios

def __child_death(signum, frame):
    global stop
    stop = True

def __recv_from_sock(sock):
    global stop
    stop = False
    print "************ REMOTE CONSOLE: CTRL-] TO QUIT ********"
    while not stop:
        try:
            data = sock.recv(1)
            os.write(1, data)
        except socket.error, error:
            if error[0] != errno.EINTR:
                raise
    print
    print "************ REMOTE CONSOLE EXITED *****************"
    os.wait()

def __send_to_sock(sock):
    while 1:
        data = os.read(0,1)
        if ord(data[0]) == ord(']')-64:
            break
        sock.send(data)
    sys.exit(0)

def connect(host,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                    struct.pack('ii', 0, 0))
    sock.connect((host,port))

    oattrs = termios.tcgetattr(0)
    nattrs = termios.tcgetattr(0)
    nattrs[3] = nattrs[3] & ~(termios.ECHO | termios.ICANON)
    nattrs[6][termios.VMIN] = 1
    nattrs[6][termios.VTIME] = 0
    termios.tcsetattr(0, termios.TCSAFLUSH, nattrs)

    try:
        if os.fork():
            signal.signal(signal.SIGCHLD, __child_death)
            __recv_from_sock(sock)
        else:
            __send_to_sock(sock)
    finally:
        termios.tcsetattr(0, termios.TCSAFLUSH, oattrs)

if __name__ == '__main__':
    main(str(sys.argv[1]),int(sys.argv[2]))
