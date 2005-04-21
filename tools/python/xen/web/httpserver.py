import string
import socket
from urllib import quote, unquote

import http
from SrvDir import SrvDir

class HttpServerRequest(http.HttpRequest):

    def __init__(self, server, addr, srd, srw):
        #print 'HttpServerRequest>', addr
        self.server = server
        self.prepath = ''
        http.HttpRequest.__init__(self, addr, srd, srw)

    def process(self):
        #print 'HttpServerRequest>process', 'path=', self.request_path
        self.prepath = []
        self.postpath = map(unquote, string.split(self.request_path[1:], '/'))
        res = self.getResource()
        self.render(res)
        self.sendResponse()
        return self.close_connection
    
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
        return self.server.getResource(self)

    def render(self, res):
        #print 'HttpServerRequest>render', res
        if res is None:
            self.sendError(http.NOT_FOUND)
        else:
            res.render(self)

class HttpServer:

    request_queue_size = 5

    def __init__(self, interface='', port=8080, root=None):
        if root is None:
            root = SrvDir()
        self.interface = interface
        self.port = port
        self.closed = False
        self.root = root

    def getRoot(self):
        return self.root

    def getPort(self):
        return self.port

    def run(self):
        self.bind()
        self.listen()
        self.requestLoop()

    def stop(self):
        self.close()

    def bind(self):
        #print 'bind>', self.interface, self.port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.interface, self.port))

    def listen(self):
        self.socket.listen(self.request_queue_size)

    def accept(self):
        return self.socket.accept()

    def requestLoop(self):
        while not self.closed:
            self.acceptRequest()

    def close(self):
        self.closed = True
        try:
            self.socket.close()
        except:
            pass

    def acceptRequest(self):
        #print 'acceptRequest>'
        try:
            (sock, addr) = self.accept()
            #print 'acceptRequest>', sock, addr
            self.processRequest(sock, addr)
        except socket.error:
            return

    def processRequest(self, sock, addr):
        #print 'processRequest>', sock, addr
        srd = sock.makefile('rb')
        srw = sock.makefile('wb')
        srvaddr = (socket.gethostname(), self.port)
        while True:
            #print 'HttpServerRequest...'
            req = HttpServerRequest(self, srvaddr, srd, srw)
            close = req.process()
            srw.flush()
            #print 'HttpServerRequest close=', close
            if close:
                break
        try:
            #print 'close...'
            sock.close()
        except:
            pass
        #print 'processRequest<', sock, addr

    def getResource(self, req):
        return self.root.getRequestResource(req)


def main():
    root = SrvDir()
    a = root.add("a", SrvDir())
    b = root.add("b", SrvDir())
    server = HttpServer(root=root)
    server.run()

if __name__ == "__main__":
    main()
        
        
        
            

