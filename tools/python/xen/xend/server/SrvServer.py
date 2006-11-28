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
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2006 XenSource Ltd.
#============================================================================

"""Example xend HTTP

   Can be accessed from a browser or from a program.
   Do 'python SrvServer.py' to run the server.
   Then point a web browser at http://localhost:8000/xend and follow the links.
   Most are stubs, except /domain which has a list of domains and a 'create domain'
   button.

   You can also access the server from a program.
   Do 'python XendClient.py' to run a few test operations.

   The data served differs depending on the client (as defined by User-Agent
   and Accept in the HTTP headers). If the client is a browser, data
   is returned in HTML, with interactive forms. If the client is a program,
   data is returned in SXP format, with no forms.

   The server serves to the world by default. To restrict it to the local host
   change 'interface' in main().

   Mike Wray <mike.wray@hp.com>
"""
# todo Support security settings etc. in the config file.
# todo Support command-line args.

import fcntl
import re
import time
import signal
from threading import Thread

from xen.web.httpserver import HttpServer, UnixHttpServer

from xen.xend import XendRoot
from xen.xend import Vifctl
from xen.xend.XendLogging import log
from xen.web.SrvDir import SrvDir

from SrvRoot import SrvRoot
from XMLRPCServer import XMLRPCServer

xroot = XendRoot.instance()


class XendServers:

    def __init__(self):
        self.servers = []
        self.cleaningUp = False

    def add(self, server):
        self.servers.append(server)

    def cleanup(self, signum = 0, frame = None):
        log.debug("SrvServer.cleanup()")
        self.cleaningUp = True
        for server in self.servers:
            try:
                server.shutdown()
            except:
                pass

    def start(self, status):
        # Running the network script will spawn another process, which takes
        # the status fd with it unless we set FD_CLOEXEC.  Failing to do this
        # causes the read in SrvDaemon to hang even when we have written here.
        if status:
            fcntl.fcntl(status, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        
        Vifctl.network('start')
        threads = []
        for server in self.servers:
            thread = Thread(target=server.run, name=server.__class__.__name__)
            if isinstance(server, HttpServer):
                thread.setDaemon(True)
            thread.start()
            threads.append(thread)


        # check for when all threads have initialized themselves and then
        # close the status pipe

        threads_left = True
        while threads_left:
            threads_left = False

            for server in self.servers:
                if not server.ready:
                    threads_left = True
                    break

            if threads_left:
                time.sleep(.5)

        if status:
            status.write('0')
            status.close()

        # Prepare to catch SIGTERM (received when 'xend stop' is executed)
        # and call each server's cleanup if possible
        signal.signal(signal.SIGTERM, self.cleanup)

        # Interruptible Thread.join - Python Bug #1167930
        #   Replaces: for t in threads: t.join()
        #   Reason:   The above will cause python signal handlers to be
        #             blocked so we're not able to catch SIGTERM in any
        #             way for cleanup
        runningThreads = threads
        while len(runningThreads) > 0:
            try:
                for t in threads:
                    t.join(1.0)
                runningThreads = [t for t in threads
                                  if t.isAlive() and not t.isDaemon()]
                if self.cleaningUp and len(runningThreads) > 0:
                    log.debug("Waiting for %s." %
                              [x.getName() for x in runningThreads])
            except:
                pass


def create():
    root = SrvDir()
    root.putChild('xend', SrvRoot())
    servers = XendServers()
    if xroot.get_xend_http_server():
        servers.add(HttpServer(root,
                               xroot.get_xend_address(),
                               xroot.get_xend_port()))
    if xroot.get_xend_unix_server():
        path = xroot.get_xend_unix_path()
        log.info('unix path=' + path)
        servers.add(UnixHttpServer(root, path))

    api_cfg = xroot.get_xen_api_server()
    if api_cfg:
        try:
            addrs = [(str(x[0]).split(':'),
                      len(x) > 1 and x[1] and map(re.compile, x[1].split(" "))
                      or None)
                     for x in api_cfg]
            for addrport, allowed in addrs:
                if len(addrport) == 1:
                    if addrport[0] == 'unix':
                        servers.add(XMLRPCServer(allowed = allowed))
                    else:
                        servers.add(XMLRPCServer(True, '', int(addrport[0]),
                                                 allowed = allowed))
                else:
                    addr, port = addrport
                    servers.add(XMLRPCServer(True, addr, int(port),
                                             allowed = allowed))
        except ValueError:
            log.error('Xen-API server configuration %s is invalid' % api_cfg)
        except TypeError:
            log.error('Xen-API server configuration %s is invalid' % api_cfg)

    if xroot.get_xend_tcp_xmlrpc_server():
        servers.add(XMLRPCServer(True))

    if xroot.get_xend_unix_xmlrpc_server():
        servers.add(XMLRPCServer())
    return servers
