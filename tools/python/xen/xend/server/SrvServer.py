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

from xen.xend import XendNode, XendOptions, XendAPI
from xen.xend import Vifctl
from xen.xend.XendLogging import log
from xen.xend.XendClient import XEN_API_SOCKET
from xen.xend.XendDomain import instance as xenddomain
from xen.web.SrvDir import SrvDir

from SrvRoot import SrvRoot
from XMLRPCServer import XMLRPCServer

xoptions = XendOptions.instance()


class XendServers:

    def __init__(self, root):
        self.servers = []
        self.root = root
        self.running = False
        self.cleaningUp = False
        self.reloadingConfig = False

    def add(self, server):
        self.servers.append(server)

    def cleanup(self, signum = 0, frame = None, reloading = False):
        log.debug("SrvServer.cleanup()")
        self.cleaningUp = True
        for server in self.servers:
            try:
                server.shutdown()
            except:
                pass

        # clean up domains for those that have on_xend_stop
        if not reloading:
            xenddomain().cleanup_domains()
        
        self.running = False
        

    def reloadConfig(self, signum = 0, frame = None):
        log.debug("SrvServer.reloadConfig()")
        self.reloadingConfig = True
        self.cleanup(signum, frame, reloading = True)

    def start(self, status):
        # Running the network script will spawn another process, which takes
        # the status fd with it unless we set FD_CLOEXEC.  Failing to do this
        # causes the read in SrvDaemon to hang even when we have written here.
        if status:
            fcntl.fcntl(status, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        
        Vifctl.network('start')

        # Prepare to catch SIGTERM (received when 'xend stop' is executed)
        # and call each server's cleanup if possible
        signal.signal(signal.SIGTERM, self.cleanup)
        signal.signal(signal.SIGHUP, self.reloadConfig)

        while True:
            XendNode.instance().refreshBridges()

            threads = []
            for server in self.servers:
                if server.ready:
                    continue

                thread = Thread(target=server.run,
                                name=server.__class__.__name__)
                thread.setDaemon(True)
                thread.start()
                threads.append(thread)

            # check for when all threads have initialized themselves and then
            # close the status pipe

            retryCount = 0
            threads_left = True
            while threads_left:
                threads_left = False

                for server in self.servers:
                    if not server.ready:
                        threads_left = True
                        break

                if threads_left:
                    time.sleep(.5)
                    retryCount += 1
                    if retryCount > 60:
                        for server in self.servers:
                            if not server.ready:
                                log.error("Server " +
                                          server.__class__.__name__ +
                                          " did not initialise!")
                        break

            if status:
                status.write('0')
                status.close()
                status = None

            # Reaching this point means we can auto start domains
            try:
                xenddomain().autostart_domains()
            except Exception, e:
                log.exception("Failed while autostarting domains")

            # loop to keep main thread alive until it receives a SIGTERM
            self.running = True
            while self.running:
                time.sleep(100000000)
                
            if self.reloadingConfig:
                log.info("Restarting all XML-RPC and Xen-API servers...")
                self.cleaningUp = False
                self.reloadingConfig = False
                xoptions.set_config()
                self.servers = []
                _loadConfig(self, self.root, True)
            else:
                break

def _loadConfig(servers, root, reload):
    if xoptions.get_xend_http_server():
        servers.add(HttpServer(root,
                               xoptions.get_xend_address(),
                               xoptions.get_xend_port()))
    if  xoptions.get_xend_unix_server():
        path = xoptions.get_xend_unix_path()
        log.info('unix path=' + path)
        servers.add(UnixHttpServer(root, path))

    api_cfg = xoptions.get_xen_api_server()
    if api_cfg:
        try:
            addrs = [(str(x[0]).split(':'),
                      len(x) > 1 and x[1] or XendAPI.AUTH_PAM,
                      len(x) > 2 and x[2] and map(re.compile, x[2].split(" "))
                      or None)
                     for x in api_cfg]
            for addrport, auth, allowed in addrs:
                if auth not in [XendAPI.AUTH_PAM, XendAPI.AUTH_NONE]:
                    log.error('Xen-API server configuration %s is invalid, ' +
                              'as %s is not a valid authentication type.',
                              api_cfg, auth)
                    break

                if len(addrport) == 1:
                    if addrport[0] == 'unix':
                        servers.add(XMLRPCServer(auth, True,
                                                 path = XEN_API_SOCKET,
                                                 hosts_allowed = allowed))
                    else:
                        servers.add(
                            XMLRPCServer(auth, True, True, '',
                                         int(addrport[0]),
                                         hosts_allowed = allowed))
                else:
                    addr, port = addrport
                    servers.add(XMLRPCServer(auth, True, True, addr,
                                             int(port),
                                             hosts_allowed = allowed))
        except (ValueError, TypeError), exn:
            log.exception('Xen API Server init failed')
            log.error('Xen-API server configuration %s is invalid.', api_cfg)

    if xoptions.get_xend_tcp_xmlrpc_server():
        addr = xoptions.get_xend_tcp_xmlrpc_server_address()
        port = xoptions.get_xend_tcp_xmlrpc_server_port()
        servers.add(XMLRPCServer(XendAPI.AUTH_PAM, False, use_tcp = True,
                                 host = addr, port = port))

    if xoptions.get_xend_unix_xmlrpc_server():
        servers.add(XMLRPCServer(XendAPI.AUTH_PAM, False))


def create():
    root = SrvDir()
    root.putChild('xend', SrvRoot())
    servers = XendServers(root)
    _loadConfig(servers, root, False)
    return servers
