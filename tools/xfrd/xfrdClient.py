#!/bin/env python
"""
Test client for the migration daemon (xfrd).

Author: Mike Wray <mike.wray@hp.com>

"""
import getopt
import sys
import os
from socket import *
import StringIO

sys.path.append("/home/mjw/repos-bk/xeno-unstable.bk/tools/python")

import xen.xend.sxp as sxp
from xen.xend.packing import SxpPacker, SxpUnpacker

XFRD_PORT = 8002

verbose = 0

class TCPClient:
        
    def __init__(self, host, port):
        print ">TCPClient"
        self.sock = socket(AF_INET, SOCK_STREAM, 0)
        print ">TCPClient sock=", self.sock
        print ">TCPClient> connect ", host, port
        v = self.sock.connect((host, port))
        print ">TCPClient> connect=", v
        # Send plain header (no gzip).
        #self.sock.send("\0\0")
        
        self.sockin = self.sock.makefile("r")
        self.sockout = self.sock.makefile("w")
        self.packer = SxpPacker(self.sockout)
        self.unpacker = SxpUnpacker(self.sockin)
        #pass

    def request(self, req):
        print "request>", req
        self.packer.pack(req)
        self.sockout.flush()
        print "request<"

    def request_hello(self):
        self.request(['xfr.hello', XFR_PROTO_MAJOR, XFR_PROTO_MINOR])

    def request_migrate(self, vmid, vhost, vport, vmconfig='(vm)'):
        self.request(['xfr.migrate', vmid, vmconfig, vhost, vport])

    def read(self):
        while(1):
            v = self.unpacker.unpack()
            print 'read>', v
            if v[0] == 'xfr.err' and v[1]: return
            if v[0] == 'xfr.ok': return

XFR_PROTO_MAJOR = 1
XFR_PROTO_MINOR = 0

host_default = "localhost"
port_default = XFRD_PORT
vhost_default = "localhost"
vport_default = 8003
vmid_default = 1

# Short options. Options followed by ':' need a parameter.
short_opts = 'h'

# Long options. Options ending in '=' need a parameter.
long_opts = [ 'host=', 'port=', 'vhost=', 'vport=', 'vmid=', 'verbose', 'help']

def usage(err=None):
    if err:
        out = sys.stderr
    else:
        out = sys.stdout
    print >> out, 'Usage: %s [options] [command...]\n' % sys.argv[0]
    print >> out, '--host <host>\n\tHost to initiate transfer on. Default %s.' % host_default
    print >> out, '--port <port>\n\tPort to initiate transfer on. Default %d.' % port_default 
    print >> out, '--vhost <vhost>\n\tHost to transfer VM to. Default %s.' % vhost_default
    print >> out, '--vport <vport>\n\tPort to transfer VM to. Default %d.' % vport_default
    print >> out, '--vmid <vmid>\n\tVM id. Default %d.' % vmid_default
    print >> out, '--help\n\tPrint help.'

def main(argv):
    global verbose
    host = host_default
    port = port_default
    vhost = vhost_default
    vport = vport_default
    vmid = vmid_default

    try:
        opts, args = getopt.getopt(argv[1:], short_opts, long_opts)
    except getopt.GetoptError, ex:
        print >>sys.stderr, 'Error:', ex
        usage(1)
        sys.exit(1)

    for key, val in opts:
        if key == '--help':
            usage()
            sys.exit(0)
        elif key == '--host':
            host = val
        elif key == '--port':
            port = int(val)
        elif key == '--vhost':
            vhost = val
        elif key == '--vport':
            vport = int(val)
        elif key == '--vmid':
            vmid = int(val)

    print "host=%s port=%d" % (host, port)
    print "vhost=%s vport=%d vmid=%d" % (vhost, vport, vmid)
    client = TCPClient(gethostbyname(host), port)
    client.request_hello()
    client.request_migrate(vmid, gethostbyname(vhost), vport)
    client.read()

if __name__ == '__main__':
        main(sys.argv)

