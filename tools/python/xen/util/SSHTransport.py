#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2006 Anthony Liguori <aliguori@us.ibm.com>
# Copyright (C) 2006 XenSource Inc.
#============================================================================

"""
XML-RPC SSH transport.
"""

from xmlrpclib import getparser, Fault
from subprocess import Popen, PIPE
from getpass import getuser
from fcntl import ioctl
import errno
import os
import termios


def getHTTPURI(uri):
    (protocol, rest) = uri.split(':', 1)
    if not rest.startswith('//'):
        raise ValueError("Invalid ssh URL '%s'" % uri)
    rest = rest[2:]
    user = getuser()
    path = 'RPC2'
    if rest.find('@') != -1:
        (user, rest) = rest.split('@', 1)
    if rest.find('/') != -1:
        (host, rest) = rest.split('/', 1)
        if len(rest) > 0:
            path = rest
    else:
        host = rest
    transport = SSHTransport(host, user)
    uri = 'http://%s/%s' % (host, path)
    return transport, uri


class SSHTransport(object):
    def __init__(self, host, user, askpass=None):
        self.host = host
        self.user = user
        self.askpass = askpass
        self.ssh = None

    def getssh(self):
        if self.ssh == None:
            if self.askpass:
                f = open('/dev/tty', 'w')
                try:
                    os.environ['SSH_ASKPASS'] = self.askpass
                    ioctl(f.fileno(), termios.TIOCNOTTY)
                finally:
                    f.close()

            cmd = ['ssh', '%s@%s' % (self.user, self.host), 'xm serve']
            try:
                self.ssh = Popen(cmd, bufsize=0, stdin=PIPE, stdout=PIPE)
            except OSError, (err, msg):
                if err == errno.ENOENT:
                    raise Fault(0, "ssh executable not found!")
                raise
        return self.ssh

    def request(self, host, handler, request_body, verbose=0):
        p, u = getparser()
        ssh = self.getssh()
        ssh.stdin.write("""POST /%s HTTP/1.1
User-Agent: Xen
Host: %s
Content-Type: text/xml
Content-Length: %d

%s""" % (handler, host, len(request_body), request_body))
        ssh.stdin.flush()

        content_length = 0
        line = ssh.stdout.readline()
        if line.split()[1] != '200':
            raise Fault(0, 'Server returned %s' % (' '.join(line[1:])))
        
        while line not in ['', '\r\n', '\n']:
            if line.lower().startswith('content-length:'):
                content_length = int(line[15:].strip())
            line = ssh.stdout.readline()
        content = ssh.stdout.read(content_length)
        p.feed(content)
        p.close()
        return u.close()
