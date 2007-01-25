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
# Copyright (C) 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2006 XenSource Ltd.
#============================================================================

import threading

import string
import socket
import types
from urllib import quote, unquote
import os
import os.path
import fcntl

from xen.xend import sxp
from xen.xend.Args import ArgError
from xen.xend.XendError import XendError

import http
import unix
from resource import Resource, ErrorPage
from SrvDir import SrvDir

class ThreadRequest:
    """A request to complete processing using a thread.
    """
    
    def __init__(self, processor, req, fn, args, kwds):
        self.processor = processor
        self.req = req
        self.fn = fn
        self.args = args
        self.kwds = kwds
        
    def run(self):
        self.processor.setInThread()
        thread = threading.Thread(target=self.main)
        thread.setDaemon(True)
        thread.start()

    def call(self):
        try:
            self.fn(*self.args, **self.kwds)
        except SystemExit:
            raise
        except Exception, ex:
            self.req.resultErr(ex)
        self.req.finish()

    def main(self):
        self.call()
        self.processor.process()
       

class RequestProcessor:
    """Processor for requests on a connection to an http server.
    Requests are executed synchonously unless they ask for a thread by returning
    a ThreadRequest.
    """

    done = False

    inThread = False

    def __init__(self, server, sock, addr):
        self.server = server
        self.sock = sock
        self.srd = sock.makefile('rb')
        self.srw = sock.makefile('wb')
        self.srvaddr = server.getServerAddr()

    def isInThread(self):
        return self.inThread

    def setInThread(self):
        self.inThread = True

    def getServer(self):
        return self.server

    def getRequest(self):
        return HttpServerRequest(self, self.srvaddr, self.srd, self.srw)

    def close(self):
        try:
            self.sock.close()
        except:
            pass

    def finish(self):
        self.done = True
        self.close()

    def process(self):
        while not self.done:
            req = self.getRequest()
            res = req.process()
            if isinstance(res, ThreadRequest):
                if self.isInThread():
                    res.call()
                else:
                    res.run()
                    break
            else:
                req.finish()
                                        
class HttpServerRequest(http.HttpRequest):
    """A single request to an http server.
    """

    def __init__(self, processor, addr, srd, srw):
        self.processor = processor
        self.prepath = ''
        http.HttpRequest.__init__(self, addr, srd, srw)

    def getServer(self):
        return self.processor.getServer()

    def process(self):
        """Process the request. If the return value is a ThreadRequest
        it is evaluated in a thread.
        """
        try:
            self.prepath = []
            self.postpath = map(unquote, string.split(self.request_path[1:], '/'))
            resource = self.getResource()
            return self.render(resource)
        except SystemExit:
            raise
        except Exception, ex:
            self.processError(ex)

    def processError(self, ex):
        import traceback; traceback.print_exc()
        self.sendError(http.INTERNAL_SERVER_ERROR, msg=str(ex))
        self.setCloseConnection('close')

    def finish(self):
        self.sendResponse()
        if self.close_connection:
            self.processor.finish()

    def prePathURL(self):
        url_host = self.getRequestHostname()
        port = self.getPort()
        if self.isSecure():
            url_proto = "https"
            default_port = 443
        else:
            url_proto = "http"
            default_port = 80
        if port != default_port:
            url_host += (':%d' % port)
        url_path = quote(string.join(self.prepath, '/'))
        return ('%s://%s/%s' % (url_proto, url_host, url_path))

    def getResource(self):
        return self.getServer().getResource(self)

    def render(self, resource):
        val = None
        if resource is None:
            self.sendError(http.NOT_FOUND)
        else:
            try:
                while True:
                    val = resource.render(self)
                    if not isinstance(val, Resource):
                        break
                val = self.result(val)
            except SystemExit:
                raise
            except Exception, ex:
                self.resultErr(ex)
        return val

    def threadRequest(self, _fn, *_args, **_kwds):
        """Create a request to finish request processing in a thread.
        Use this to create a ThreadRequest to return from rendering a
        resource if you need a thread to complete processing.
        """
        return ThreadRequest(self.processor, self, _fn, _args, _kwds)
            
    def result(self, val):
        if isinstance(val, Exception):
            return self.resultErr(val)
        else:
            return self.resultVal(val)

    def resultVal(self, val):
        """Callback to complete the request.

        @param val: the value
        """
        if val is None:
            return val
        elif isinstance(val, ThreadRequest):
            return val
        elif self.useSxp():
            self.setHeader("Content-Type", sxp.mime_type)
            sxp.show(val, out=self)
        else:
            self.write('<html><head></head><body>')
            self.printPath()
            if isinstance(val, types.ListType):
                self.write('<code><pre>')
                PrettyPrint.prettyprint(val, out=self)
                self.write('</pre></code>')
            else:
                self.write(str(val))
            self.write('</body></html>')
        return None

    def resultErr(self, err):
        """Error callback to complete a request.

        @param err: the error
        """
        if not isinstance(err, (ArgError, sxp.ParseError, XendError)):
            raise
        #log.exception("op=%s: %s", op, str(err))
        if self.useSxp():
            self.setHeader("Content-Type", sxp.mime_type)
            sxp.show(['xend.err', str(err)], out=self)
        else:
            self.setHeader("Content-Type", "text/plain")
            self.write('Error ')
            self.write(': ')
            self.write(str(err))
        return None

    def useSxp(self):
        """Determine whether to send an SXP response to a request.
        Uses SXP if there is no User-Agent, no Accept, or application/sxp is in Accept.

        returns 1 for SXP, 0 otherwise
        """
        ok = 0
        user_agent = self.getHeader('User-Agent')
        accept = self.getHeader('Accept')
        if (not user_agent) or (not accept) or (accept.find(sxp.mime_type) >= 0):
            ok = 1
        return ok

    def printPath(self):
        pathlist = [x for x in self.prepath if x != '' ]
        s = "/"
        self.write('<h1><a href="/">/</a>')
        for x in pathlist:
            s += x + "/"
            self.write(' <a href="%s">%s</a>/' % (s, x))
        self.write("</h1>")

class HttpServerClient:

    def __init__(self, server, sock, addr):
        self.server = server
        self.sock = sock
        self.addr = addr

    def process(self):
        thread = threading.Thread(target=self.doProcess)
        thread.setDaemon(True)
        thread.start()

    def doProcess(self):
        try:
            rp = RequestProcessor(self.server, self.sock, self.addr)
            rp.process()
        except SystemExit:
            raise
        except Exception, ex:
            print 'HttpServer>processRequest> exception: ', ex
            try:
                self.sock.close()
            except:
                pass

class HttpServer:

    backlog = 5

    def __init__(self, root, interface, port=8080):
        self.root = root
        self.interface = interface
        self.port = port
        # ready indicates when we are ready to begin accept connections
        # it should be set after a successful bind
        self.ready = False
        self.closed = False

    def run(self):
        self.bind()
        self.listen()
        self.ready = True

        while not self.closed:
            (sock, addr) = self.accept()
            cl = HttpServerClient(self, sock, addr)
            cl.process()

    def stop(self):
        self.close()

    def bind(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        flags = fcntl.fcntl(self.socket.fileno(), fcntl.F_GETFD)
        flags |= fcntl.FD_CLOEXEC
        fcntl.fcntl(self.socket.fileno(), fcntl.F_SETFD, flags)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.interface, self.port))

    def listen(self):
        self.socket.listen(self.backlog)

    def accept(self):
        return self.socket.accept()

    def close(self):
        self.closed = True
        self.ready = False
        # shutdown socket explicitly to allow reuse
        try:
            self.socket.shutdown(2)
        except socket.error:
            pass

        try:
            self.socket.close()
        except socket.error:
            pass

    def getServerAddr(self):
        return (socket.gethostname(), self.port)

    def getResource(self, req):
        return self.root.getRequestResource(req)

    def shutdown(self):
        self.close()


class UnixHttpServer(HttpServer):

    def __init__(self, root, path):
        HttpServer.__init__(self, root, 'localhost')
        self.path = path
        
    def bind(self):
        self.socket = unix.bind(self.path)
        flags = fcntl.fcntl(self.socket.fileno(), fcntl.F_GETFD)
        flags |= fcntl.FD_CLOEXEC
        fcntl.fcntl(self.socket.fileno(), fcntl.F_SETFD, flags)
